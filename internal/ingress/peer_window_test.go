package ingress

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func peerServer(t *testing.T, windowMS int) (*httptest.Server, *headerCapture) {
	t.Helper()
	border := &headerCapture{}
	borderSrv := httptest.NewServer(border)
	t.Cleanup(borderSrv.Close)

	resolver := agreementFor(t, borderSrv.URL+"/cluster")
	peers, err := ParsePeers([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		Resolver:     resolver,
		Forwarder:    &Forwarder{BorderKey: []byte(testKey), Canary: RandomCanary},
		Token:        testToken,
		Observer:     NewObserver(),
		Node:         "wan-b",
		RouteSpanMS:  15000,
		PeerWindowMS: windowMS,
		Peers:        peers,
	}
	return httptest.NewServer(server.Handler()), border
}

// The peer window is the frequency discriminator: two adjacent edges either
// agree on "now" within their link's tolerance or one of them has wobbled. It is
// tighter than the route span on purpose, so a disagreement is settled in one
// round trip instead of waiting for the path to age out.
func TestPeerWindowRefusesAClockDisagreement(t *testing.T) {
	srv, _ := peerServer(t, 50)
	defer srv.Close()

	headers := authHeaders()
	headers[pathHeader] = fmt.Sprintf("wan-a@%d", time.Now().Add(-200*time.Millisecond).UnixMilli())
	status, body := doRequest(t, srv.Client(), http.MethodPost, srv.URL+"/forward?name=42", headers)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d (%s), want 422", status, body)
	}
	if decision := decisionFrom(t, body); decision.Reason != "clock_disagreement" {
		t.Fatalf("reason = %q, want clock_disagreement", decision.Reason)
	}
}

func TestPeerWindowAcceptsAgreement(t *testing.T) {
	srv, _ := peerServer(t, 50)
	defer srv.Close()

	headers := authHeaders()
	headers[pathHeader] = fmt.Sprintf("wan-a@%d", time.Now().Add(-10*time.Millisecond).UnixMilli())
	if status, body := doRequest(t, srv.Client(), http.MethodPost, srv.URL+"/forward?name=42", headers); status != http.StatusOK {
		t.Fatalf("status = %d (%s), want 200", status, body)
	}
}

// A hop from a peer that carries no stamp cannot be judged. Silence is not
// agreement: an unstamped hop is a disagreement, not a pass.
func TestUnstampedPeerHopIsADisagreement(t *testing.T) {
	srv, _ := peerServer(t, 1000)
	defer srv.Close()

	headers := authHeaders()
	headers[pathHeader] = "wan-a"
	status, body := doRequest(t, srv.Client(), http.MethodPost, srv.URL+"/forward?name=42", headers)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d (%s), want 422", status, body)
	}
	if decision := decisionFrom(t, body); decision.Reason != "clock_disagreement" {
		t.Fatalf("reason = %q, want clock_disagreement", decision.Reason)
	}
}

// The front stamps itself, so the next hop has something to judge.
func TestThisHopIsStamped(t *testing.T) {
	srv, border := peerServer(t, 1000)
	defer srv.Close()

	if status, body := doRequest(t, srv.Client(), http.MethodPost, srv.URL+"/forward?name=42", authHeaders()); status != http.StatusOK {
		t.Fatalf("status = %d (%s)", status, body)
	}
	got, _, _ := border.last()
	hops, err := ParsePath(got.Get(pathHeader))
	if err != nil {
		t.Fatal(err)
	}
	if len(hops) != 1 || hops[0].Name != "wan-b" || hops[0].At == 0 {
		t.Fatalf("hops = %+v, want one stamped wan-b", hops)
	}
	if age := time.Since(time.UnixMilli(hops[0].At)); age > time.Second {
		t.Fatalf("hop stamp is %s old", age)
	}
}
