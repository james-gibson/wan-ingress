package ingress

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRouteStartBeginsAtNow(t *testing.T) {
	now := time.Now()
	start, err := RouteStart("", now, DefaultRouteSpan)
	if err != nil {
		t.Fatal(err)
	}
	if start != now.UnixMilli() {
		t.Fatalf("start = %d, want %d", start, now.UnixMilli())
	}
}

func TestRouteStartIsCarriedNotReset(t *testing.T) {
	now := time.Now()
	began := now.Add(-2 * time.Second).UnixMilli()
	start, err := RouteStart(fmt.Sprintf("%d", began), now, DefaultRouteSpan)
	if err != nil {
		t.Fatal(err)
	}
	if start != began {
		t.Fatalf("start = %d, want the carried %d", start, began)
	}
}

// Replay inside the span is the stability promise; outside it, the route
// dissolves.
func TestRouteStartDissolvesPastTheSpan(t *testing.T) {
	now := time.Now()
	for name, carried := range map[string]string{
		"past span":  fmt.Sprintf("%d", now.Add(-DefaultRouteSpan-time.Millisecond).UnixMilli()),
		"future":     fmt.Sprintf("%d", now.Add(time.Second).UnixMilli()),
		"not a time": "yesterday",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := RouteStart(carried, now, DefaultRouteSpan); !errors.Is(err, ErrRouteDissolved) {
				t.Fatalf("carried %q: err = %v, want route dissolved", carried, err)
			}
		})
	}
}

func TestDissolvedRouteIsRefusedBeforeTheBorder(t *testing.T) {
	border := &headerCapture{}
	borderSrv := httptest.NewServer(border)
	defer borderSrv.Close()

	resolver := agreementFor(t, borderSrv.URL+"/cluster")
	peers, err := ParsePeers([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		Resolver:    resolver,
		Forwarder:   &Forwarder{BorderKey: []byte(testKey), Canary: RandomCanary},
		Token:       testToken,
		Observer:    NewObserver(),
		Node:        "wan-b",
		RouteSpanMS: 15,
		Peers:       peers,
	}
	srv := httptest.NewServer(server.Handler())
	defer srv.Close()

	headers := authHeaders()
	headers[routeStartHeader] = fmt.Sprintf("%d", time.Now().Add(-time.Second).UnixMilli())
	status, body := doRequest(t, srv.Client(), http.MethodPost, srv.URL+"/forward?name=42", headers)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d (%s), want 422", status, body)
	}
	if decision := decisionFrom(t, body); decision.Reason != "route_dissolved" {
		t.Fatalf("reason = %q, want route_dissolved", decision.Reason)
	}
	if got := border.count(); got != 0 {
		t.Fatalf("a dissolved route reached the border %d times", got)
	}
}

// A live route keeps the start it was given, so every hop counts the same age.
func TestLiveRouteKeepsItsStart(t *testing.T) {
	border := &headerCapture{}
	borderSrv := httptest.NewServer(border)
	defer borderSrv.Close()

	resolver := agreementFor(t, borderSrv.URL+"/cluster")
	peers, err := ParsePeers([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		Resolver:    resolver,
		Forwarder:   &Forwarder{BorderKey: []byte(testKey), Canary: RandomCanary},
		Token:       testToken,
		Observer:    NewObserver(),
		Node:        "wan-b",
		RouteSpanMS: 15000,
		Peers:       peers,
	}
	srv := httptest.NewServer(server.Handler())
	defer srv.Close()

	began := time.Now().Add(-time.Second).UnixMilli()
	headers := authHeaders()
	headers[routeStartHeader] = fmt.Sprintf("%d", began)
	if status, body := doRequest(t, srv.Client(), http.MethodPost, srv.URL+"/forward?name=42", headers); status != http.StatusOK {
		t.Fatalf("status = %d (%s)", status, body)
	}
	got, _, _ := border.last()
	if start := got.Get(routeStartHeader); start != fmt.Sprintf("%d", began) {
		t.Fatalf("border saw route start %q, want the carried %d", start, began)
	}
}

// A caller that is not a trusted peer cannot backdate a route: the header is
// dropped and the route starts here.
func TestUntrustedCallerCannotBackdateTheRoute(t *testing.T) {
	border := &headerCapture{}
	borderSrv := httptest.NewServer(border)
	defer borderSrv.Close()

	resolver := agreementFor(t, borderSrv.URL+"/cluster")
	server := &Server{
		Resolver:    resolver,
		Forwarder:   &Forwarder{BorderKey: []byte(testKey), Canary: RandomCanary},
		Token:       testToken,
		Observer:    NewObserver(),
		Node:        "wan-b",
		RouteSpanMS: 15000,
	}
	srv := httptest.NewServer(server.Handler())
	defer srv.Close()

	headers := authHeaders()
	headers[routeStartHeader] = fmt.Sprintf("%d", time.Now().Add(-time.Hour).UnixMilli())
	if status, body := doRequest(t, srv.Client(), http.MethodPost, srv.URL+"/forward?name=42", headers); status != http.StatusOK {
		t.Fatalf("status = %d (%s), want 200 with a fresh route", status, body)
	}
	got, _, _ := border.last()
	start := got.Get(routeStartHeader)
	if start == "" || start == fmt.Sprintf("%d", time.Now().Add(-time.Hour).UnixMilli()) {
		t.Fatalf("an untrusted caller's backdated start was believed: %q", start)
	}
}
