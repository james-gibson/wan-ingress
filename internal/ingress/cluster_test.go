package ingress

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The declaration is derived, not stored (lab/SPLASH.md, *Derived values*):
// every node reports the isotope of what it is actually running, so two nodes
// that disagree are visible from outside either of them.

func TestTheSameDeclarationDerivesTheSameIsotope(t *testing.T) {
	first := `{"agreements":[
		{"id":"b","namespace":"session-b","border":"http://127.0.0.1:1/b","aliases":["y","x"],"rung":2},
		{"id":"a","namespace":"session-a","border":"http://127.0.0.1:1/a","aliases":["q"]}
	]}`
	// Same routes, different key order, different agreement order, different
	// alias order. A digest that changes here would make the comparison useless.
	second := `{"agreements":[
		{"aliases":["q"],"border":"http://127.0.0.1:1/a","namespace":"session-a","id":"a"},
		{"aliases":["x","y"],"rung":2,"namespace":"session-b","border":"http://127.0.0.1:1/b","id":"b"}
	]}`

	a, err := LoadAgreements(strings.NewReader(first))
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	b, err := LoadAgreements(strings.NewReader(second))
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if a.PolicyIsotope() != b.PolicyIsotope() {
		t.Fatalf("equivalent declarations derived %s and %s", a.PolicyIsotope(), b.PolicyIsotope())
	}
}

func TestADifferentDeclarationDerivesADifferentIsotope(t *testing.T) {
	base := `{"agreements":[{"id":"a","namespace":"session-42","border":"http://127.0.0.1:1/a","aliases":["42"]}]}`
	changed := []string{
		`{"agreements":[{"id":"a","namespace":"session-43","border":"http://127.0.0.1:1/a","aliases":["42"]}]}`,
		`{"agreements":[{"id":"a","namespace":"session-42","border":"http://127.0.0.1:2/a","aliases":["42"]}]}`,
		`{"agreements":[{"id":"a","namespace":"session-42","border":"http://127.0.0.1:1/a","aliases":["42"],"rung":3}]}`,
		`{"agreements":[{"id":"a","namespace":"session-42","border":"http://127.0.0.1:1/a","aliases":["42","43"]}]}`,
	}
	want, err := LoadAgreements(strings.NewReader(base))
	if err != nil {
		t.Fatal(err)
	}
	for i, declaration := range changed {
		got, err := LoadAgreements(strings.NewReader(declaration))
		if err != nil {
			t.Fatalf("variant %d: %v", i, err)
		}
		if got.PolicyIsotope() == want.PolicyIsotope() {
			t.Fatalf("variant %d derived the same isotope as the base: %s", i, got.PolicyIsotope())
		}
	}
}

func TestPolicyIsPublishedWithoutRouteContents(t *testing.T) {
	border := &headerCapture{}
	borderSrv := httptest.NewServer(border)
	defer borderSrv.Close()

	srv := testServer(t, agreementFor(t, borderSrv.URL+"/cluster"), &Forwarder{BorderKey: []byte(testKey)}, testToken)
	defer srv.Close()

	status, body := doRequest(t, srv.Client(), http.MethodGet, srv.URL+"/policy", nil)
	if status != http.StatusOK {
		t.Fatalf("policy status = %d (%s)", status, body)
	}
	var summary PolicySummary
	if err := json.Unmarshal(body, &summary); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	if summary.Isotope == "" || summary.Agreements != 1 || summary.Aliases != 1 {
		t.Fatalf("summary = %+v", summary)
	}
	// A digest is checkable; the declaration is not published.
	for _, secret := range []string{"cluster", "session-42", "workspace-42", "127.0.0.1"} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("policy leaked %q: %s", secret, body)
		}
	}
}

// A route carries its history, so a route that already contains this node is
// refused structurally rather than bounded by a timeout.

func clusterServer(t *testing.T, node string, peers []string, namespace string) (*httptest.Server, *headerCapture) {
	t.Helper()
	border := &headerCapture{}
	borderSrv := httptest.NewServer(border)
	t.Cleanup(borderSrv.Close)

	resolver := agreementFor(t, borderSrv.URL+"/cluster")
	if namespace != "" {
		body := fmt.Sprintf(`{"agreements":[{"id":"workspace-42","namespace":%q,"border":%q,"aliases":["42"],"rung":2}]}`, namespace, borderSrv.URL+"/cluster")
		res, err := LoadAgreements(strings.NewReader(body))
		if err != nil {
			t.Fatalf("agreements: %v", err)
		}
		resolver = res
	}
	peerSet, err := ParsePeers(peers)
	if err != nil {
		t.Fatalf("peers: %v", err)
	}
	server := &Server{
		Resolver:  resolver,
		Forwarder: &Forwarder{BorderKey: []byte(testKey), Node: node, Policy: resolver.PolicyIsotope()},
		Token:     testToken,
		Observer:  NewObserver(),
		Node:      node,
		Peers:     peerSet,
	}
	return httptest.NewServer(server.Handler()), border
}

func nowMS() string { return fmt.Sprintf("%d", time.Now().UnixMilli()) }

func TestRouteContainingThisNodeIsRefused(t *testing.T) {
	srv, border := clusterServer(t, "wan-a", []string{"127.0.0.1"}, "")
	defer srv.Close()

	headers := authHeaders()
	headers[pathHeader] = "wan-b@" + nowMS() + ",wan-a@" + nowMS()
	status, body := doRequest(t, srv.Client(), http.MethodPost, srv.URL+"/forward?name=42", headers)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d (%s), want 422", status, body)
	}
	if decision := decisionFrom(t, body); decision.Reason != "path_loop" {
		t.Fatalf("reason = %q, want path_loop", decision.Reason)
	}
	if got := border.count(); got != 0 {
		t.Fatalf("a looped route reached the border %d times", got)
	}
}

func TestUntrustedPathIsDiscarded(t *testing.T) {
	srv, border := clusterServer(t, "wan-a", nil, "")
	defer srv.Close()

	// No peers: the header is a caller's wish and is dropped, so an anonymous
	// caller cannot name a node and have it refuse a request it never saw.
	headers := authHeaders()
	headers[pathHeader] = "wan-b@" + nowMS()
	status, body := doRequest(t, srv.Client(), http.MethodPost, srv.URL+"/forward?name=42", headers)
	if status != http.StatusOK {
		t.Fatalf("status = %d (%s), want 200", status, body)
	}
	got, _, _ := border.last()
	if path := got.Get(pathHeader); !strings.HasPrefix(path, "wan-a@") || strings.Contains(path, ",") {
		t.Fatalf("border path = %q, want a fresh route rooted at wan-a", path)
	}
}

func TestTrustedPathIsExtendedAndSigned(t *testing.T) {
	srv, border := clusterServer(t, "wan-a", []string{"127.0.0.1"}, "")
	defer srv.Close()

	headers := authHeaders()
	headers[pathHeader] = "wan-b@" + nowMS() + ",wan-c@" + nowMS()
	status, body := doRequest(t, srv.Client(), http.MethodPost, srv.URL+"/forward?name=42", headers)
	if status != http.StatusOK {
		t.Fatalf("status = %d (%s)", status, body)
	}
	got, _, _ := border.last()
	if path := got.Get(pathHeader); !strings.HasPrefix(path, "wan-b@") || !strings.HasSuffix(path, ",wan-a@") && !strings.Contains(path, ",wan-a@") {
		t.Fatalf("border path = %q, want wan-b,wan-c,wan-a", path)
	}
	if policy := got.Get("X-Lab-Policy"); policy == "" {
		t.Fatal("the border saw no policy isotope")
	}
	if sig := got.Get("X-Lab-Signature"); len(sig) != 64 {
		t.Fatalf("signature = %q", sig)
	}
}

func TestPathIsBounded(t *testing.T) {
	if _, err := ParsePath(strings.Repeat("a,", maxPathHops)); err == nil {
		t.Fatal("a path over the hop limit was accepted")
	}
	path := make([]Hop, maxPathHops)
	for i := range path {
		path[i] = Hop{Name: fmt.Sprintf("n%d", i), At: time.Now().UnixMilli()}
	}
	if _, err := AppendHop(path, "wan-a", time.Now().UnixMilli()); err == nil {
		t.Fatal("a path over the hop limit was extended")
	}
}

// The policy and the path are inside the signature, so a node cannot rewrite
// either in transit and have the border accept it.
func TestPolicyAndPathAreInsideTheSignature(t *testing.T) {
	sign := func(policy, path string) string {
		border := &headerCapture{}
		borderSrv := httptest.NewServer(border)
		defer borderSrv.Close()
		target := Route{Address: borderSrv.URL + "/cluster", Namespace: "session-42"}
		f := &Forwarder{BorderKey: []byte(testKey), Policy: policy}
		hops, err := ParsePath(path)
		if err != nil {
			t.Fatalf("parse path: %v", err)
		}
		if _, err := f.ForwardPath(t.Context(), target, "42", []byte("x"), hops); err != nil {
			t.Fatalf("forward: %v", err)
		}
		h, _, _ := border.last()
		return h.Get("X-Lab-Signature")
	}
	if sign("policy-a", "wan-a") == sign("policy-b", "wan-a") {
		t.Fatal("the signature does not cover the policy")
	}
	if sign("policy-a", "wan-a") == sign("policy-a", "wan-a,wan-b") {
		t.Fatal("the signature does not cover the path")
	}
}

// Behind an nginx/LB every client arrives from the terminator's address. If the
// terminator were treated as a peer, an anonymous caller could write a path and
// have it believed — the flaw this split exists to prevent.
func TestPathIsNotBelievedThroughATerminator(t *testing.T) {
	border := &headerCapture{}
	borderSrv := httptest.NewServer(border)
	defer borderSrv.Close()

	resolver := agreementFor(t, borderSrv.URL+"/cluster")
	peers, err := ParsePeers([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	terminators, err := ParsePeers([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		Resolver:   resolver,
		Forwarder:  &Forwarder{BorderKey: []byte(testKey), Node: "wan-a", Policy: resolver.PolicyIsotope()},
		Token:      testToken,
		Observer:   NewObserver(),
		Node:       "wan-a",
		Peers:      peers,
		Terminator: terminators,
	}
	srv := httptest.NewServer(server.Handler())
	defer srv.Close()

	headers := authHeaders()
	headers[pathHeader] = "wan-b@" + nowMS()
	status, body := doRequest(t, srv.Client(), http.MethodPost, srv.URL+"/forward?name=42", headers)
	if status != http.StatusOK {
		t.Fatalf("status = %d (%s)", status, body)
	}
	got, _, _ := border.last()
	if path := got.Get(pathHeader); !strings.HasPrefix(path, "wan-a@") || strings.Contains(path, ",") {
		t.Fatalf("border path = %q, want the client path discarded", path)
	}
}

func TestCheckDeployableRefusesAPeerInsideTheTerminator(t *testing.T) {
	cfg := Config{
		Addr:       "127.0.0.1:8443",
		Node:       "wan-a",
		Peers:      []string{"10.0.0.0/24"},
		Terminator: []string{"10.0.0.7"},
	}
	if err := CheckDeployable(cfg); err == nil {
		t.Fatal("overlapping peer and terminator ranges were accepted")
	}
	cfg.Terminator = []string{"10.0.1.7"}
	if err := CheckDeployable(cfg); err != nil {
		t.Fatalf("disjoint ranges were refused: %v", err)
	}
}
