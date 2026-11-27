package ingress

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testShapes() *ShapeSet {
	return NewShapeSet([]ShapeLimit{
		{Class: "small", MaxBytes: 16 << 10, MaxConns: 16},
		{Class: "medium", MaxBytes: 256 << 10, MaxConns: 8},
		{Class: "bulk", MaxBytes: 1 << 20, MaxConns: 4},
	})
}

// The class is decided by body size, because the measured concurrency knee
// differs by an order of magnitude between a 1 KiB request and a 1 MiB one.
func TestShapeClassifyByBodySize(t *testing.T) {
	set := testShapes()
	cases := []struct {
		body int64
		want string
	}{
		{0, "small"},
		{16 << 10, "small"},
		{(16 << 10) + 1, "medium"},
		{256 << 10, "medium"},
		{(256 << 10) + 1, "bulk"},
		{1 << 20, "bulk"},
		{2 << 20, "bulk"}, // larger than any class takes the tightest budget
		{-1, "bulk"},      // chunked: length unknown, assume the worst
	}
	for _, tc := range cases {
		if got := set.Classify(tc.body).Class; got != tc.want {
			t.Fatalf("Classify(%d) = %q, want %q", tc.body, got, tc.want)
		}
	}
}

func TestShapeBudgetRefusesWhenFullAndReleases(t *testing.T) {
	set := testShapes()
	release, class, ok := set.Acquire(1024)
	if !ok || class != "small" {
		t.Fatalf("first acquire: ok=%v class=%q", ok, class)
	}
	// Fill the remaining small slots.
	var held []func()
	for i := 1; i < 16; i++ {
		r, _, ok := set.Acquire(1024)
		if !ok {
			t.Fatalf("acquire %d refused with slots free", i)
		}
		held = append(held, r)
	}
	if _, _, ok := set.Acquire(1024); ok {
		t.Fatal("a seventeenth small request was admitted")
	}
	// A different class has its own budget.
	if _, class, ok := set.Acquire(64 << 10); !ok || class != "medium" {
		t.Fatalf("a medium request was refused by the small budget (class=%q ok=%v)", class, ok)
	}
	for _, r := range held {
		r()
	}
	release()
	if _, _, ok := set.Acquire(1024); !ok {
		t.Fatal("a released slot was not reusable")
	}
}

func TestNilShapeSetAdmitsEverything(t *testing.T) {
	var set *ShapeSet
	release, class, ok := set.Acquire(1 << 20)
	if !ok || class != "unshaped" {
		t.Fatalf("nil set: ok=%v class=%q", ok, class)
	}
	release()
	if set.Limits() != nil {
		t.Fatal("nil set reported limits")
	}
}

// A full class answers 429 with Retry-After and never touches the border: the
// refusal happens before the body is read.
func TestFullShapeIsRefusedBeforeTheBody(t *testing.T) {
	border := &headerCapture{}
	borderSrv := httptest.NewServer(border)
	defer borderSrv.Close()

	resolver := agreementFor(t, borderSrv.URL+"/cluster")
	server := &Server{
		Resolver:  resolver,
		Forwarder: &Forwarder{BorderKey: []byte(testKey), Policy: resolver.PolicyIsotope()},
		Token:     testToken,
		Observer:  NewObserver(),
		Shapes:    testShapes(),
	}
	srv := httptest.NewServer(server.Handler())
	defer srv.Close()

	// Hold every small slot.
	releases := make([]func(), 0, 16)
	for i := 0; i < 16; i++ {
		r, _, ok := server.Shapes.Acquire(1024)
		if !ok {
			t.Fatalf("slot %d unavailable", i)
		}
		releases = append(releases, r)
	}

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/forward?name=42", strings.NewReader(strings.Repeat("x", 1024)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
	if got := resp.Header.Get("Retry-After"); got == "" {
		t.Fatal("429 carried no Retry-After")
	}
	if got := border.count(); got != 0 {
		t.Fatalf("a shape-refused request reached the border %d times", got)
	}

	// Releasing one slot admits the next request of that class.
	for _, r := range releases {
		r()
	}
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/forward?name=42", strings.NewReader("x"))
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp2, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("after release: status = %d, want 200", resp2.StatusCode)
	}
}

// The shape caps are inside the grant's signature like every other grant.
func TestGrantShapesAreSigned(t *testing.T) {
	pub, priv := testGrant(t, 0)
	base := SignGrant(priv, Grant{
		Namespace: "session-42", Batch: 8, MaxConns: 64,
		Shapes:  []ShapeLimit{{Class: "small", MaxBytes: 1024, MaxConns: 4}},
		Expires: nowPlusHour().Unix(),
	})
	tampered := base
	tampered.Shapes = []ShapeLimit{{Class: "small", MaxBytes: 1024, MaxConns: 4000}}
	if err := VerifyGrant(pub, tampered, time.Now()); err == nil {
		t.Fatal("a tampered shape cap verified")
	}
	dup := SignGrant(priv, Grant{
		Namespace: "session-42", Batch: 8, MaxConns: 64,
		Shapes:  []ShapeLimit{{Class: "small", MaxBytes: 1024, MaxConns: 4}, {Class: "small", MaxBytes: 2048, MaxConns: 4}},
		Expires: nowPlusHour().Unix(),
	})
	if err := VerifyGrant(pub, dup, time.Now()); err == nil {
		t.Fatal("a duplicated shape class verified")
	}
}

func TestGrantDecodesShapes(t *testing.T) {
	pub, priv := testGrant(t, 0)
	g := SignGrant(priv, Grant{
		Namespace: "session-42", Batch: 8, MaxConns: 64,
		Shapes:  []ShapeLimit{{Class: "bulk", MaxBytes: 1 << 20, MaxConns: 4}},
		Expires: nowPlusHour().Unix(),
	})
	raw, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	var back Grant
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if err := VerifyGrant(pub, back, time.Now()); err != nil {
		t.Fatalf("round trip: %v", err)
	}
}

func nowPlusHour() time.Time { return time.Now().Add(time.Hour) }
