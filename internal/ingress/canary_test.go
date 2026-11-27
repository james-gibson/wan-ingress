package ingress

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A border that accepts the request but drops the marker is not carrying the
// declaration forward. The front says so instead of counting it as a success.
func TestCanaryLostIsRefused(t *testing.T) {
	silent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent) // no X-Lab-Canary echo
	}))
	defer silent.Close()

	resolver := agreementFor(t, silent.URL+"/cluster")
	server := &Server{
		Resolver:  resolver,
		Forwarder: &Forwarder{BorderKey: []byte(testKey), Canary: RandomCanary},
		Token:     testToken,
		Observer:  NewObserver(),
	}
	srv := httptest.NewServer(server.Handler())
	defer srv.Close()

	status, body := doRequest(t, srv.Client(), http.MethodPost, srv.URL+"/forward?name=42", authHeaders())
	if status != http.StatusBadGateway {
		t.Fatalf("status = %d (%s), want 502", status, body)
	}
	if decision := decisionFrom(t, body); decision.Reason != "canary_lost" {
		t.Fatalf("reason = %q, want canary_lost", decision.Reason)
	}
	if got := server.Observer.Forwarded(); got != 0 {
		t.Fatalf("a lost canary was counted as %d forged forwards", got)
	}
}

// The border's own count is a second witness. When it is absent the gap is
// visible rather than assumed away.
func TestWitnessGapIsVisible(t *testing.T) {
	echoOnly := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c := r.Header.Get("X-Lab-Canary"); c != "" {
			w.Header().Set("X-Lab-Canary", c)
		}
		w.WriteHeader(http.StatusNoContent) // deliberately no X-Lab-Seen
	}))
	defer echoOnly.Close()

	resolver := agreementFor(t, echoOnly.URL+"/cluster")
	server := &Server{
		Resolver:  resolver,
		Forwarder: &Forwarder{BorderKey: []byte(testKey), Canary: RandomCanary},
		Token:     testToken,
		Observer:  NewObserver(),
	}
	srv := httptest.NewServer(server.Handler())
	defer srv.Close()

	for i := 0; i < 3; i++ {
		if status, body := doRequest(t, srv.Client(), http.MethodPost, srv.URL+"/forward?name=42", authHeaders()); status != http.StatusOK {
			t.Fatalf("forward %d = %d (%s)", i, status, body)
		}
	}
	status, body := doRequest(t, srv.Client(), http.MethodGet, srv.URL+"/status", nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	var counts statusBody
	if err := json.Unmarshal(body, &counts); err != nil {
		t.Fatal(err)
	}
	if counts.Forwarded != 3 {
		t.Fatalf("forwarded = %d, want 3", counts.Forwarded)
	}
	if counts.WitnessGap != 3 {
		t.Fatalf("witness_gap = %d, want 3 (the border reported no count)", counts.WitnessGap)
	}
}

// When the border does report, the gap closes.
func TestWitnessClosesWhenTheBorderReports(t *testing.T) {
	border := &capture{}
	borderSrv := httptest.NewServer(border)
	defer borderSrv.Close()

	resolver := agreementFor(t, borderSrv.URL+"/cluster")
	server := &Server{
		Resolver:  resolver,
		Forwarder: &Forwarder{BorderKey: []byte(testKey), Canary: RandomCanary},
		Token:     testToken,
		Observer:  NewObserver(),
	}
	srv := httptest.NewServer(server.Handler())
	defer srv.Close()

	for i := 0; i < 5; i++ {
		if status, body := doRequest(t, srv.Client(), http.MethodPost, srv.URL+"/forward?name=42", authHeaders()); status != http.StatusOK {
			t.Fatalf("forward %d = %d (%s)", i, status, body)
		}
	}
	if got := server.Observer.BorderSeen(); got != 5 {
		t.Fatalf("border_seen = %d, want 5", got)
	}
	if got := server.Observer.WitnessGap(); got != 0 {
		t.Fatalf("witness_gap = %d, want 0", got)
	}
}

// The shape budgets are published, which is what removes the timing oracle:
// probing cannot discover a capacity that is already on /policy.
func TestPolicyPublishesShapes(t *testing.T) {
	server := &Server{
		Resolver: NewEmptyResolver(),
		Shapes:   testShapes(),
		Observer: NewObserver(),
		Token:    testToken,
	}
	srv := httptest.NewServer(server.Handler())
	defer srv.Close()

	status, body := doRequest(t, srv.Client(), http.MethodGet, srv.URL+"/policy", nil)
	if status != http.StatusOK {
		t.Fatalf("policy = %d", status)
	}
	var published struct {
		Isotope string       `json:"isotope"`
		Shapes  []ShapeLimit `json:"shapes"`
	}
	if err := json.Unmarshal(body, &published); err != nil {
		t.Fatal(err)
	}
	if len(published.Shapes) != 3 {
		t.Fatalf("shapes on /policy = %d, want 3 (%s)", len(published.Shapes), body)
	}
	for _, s := range published.Shapes {
		if s.Class == "" || s.MaxBytes <= 0 || s.MaxConns <= 0 {
			t.Fatalf("published shape is incomplete: %+v", s)
		}
	}
	_ = published.Isotope
}
