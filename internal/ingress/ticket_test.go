package ingress

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The address plane (lezz.go's seed-invite) may arm an expectation and attach a
// rotation ticket to a call. That ticket is evidence of an arrival, not a
// credential: the front still admits on its own bearer token, and a stolen
// ticket presented with someone else's token never reaches the border.
//
// This is the ingress half of the boundary claim. The address-plane half — that
// the invite proxy forwards with the operator token rather than relaying the
// caller's — lives beside seed-invite in lezz.go.
func TestTicketHeaderIsNotABearerToken(t *testing.T) {
	border := &capture{}
	borderSrv := httptest.NewServer(border)
	defer borderSrv.Close()

	agreements := fmt.Sprintf(`{"agreements":[{"id":"workspace-42","namespace":"session-42","border":%q,"aliases":["42"]}]}`, borderSrv.URL)
	resolver, err := LoadAgreements(strings.NewReader(agreements))
	if err != nil {
		t.Fatalf("load agreements: %v", err)
	}
	srv := testServer(t, resolver, &Forwarder{BorderKey: []byte(testKey)}, testToken)
	defer srv.Close()

	// A rotation ticket is not a replacement for the operator token.
	forged := map[string]string{
		"X-Invite":        "wan-ingress",
		"X-Invite-Ticket": "stolen-nonce",
		"Authorization":   "Bearer attacker",
	}
	status, body := doRequest(t, srv.Client(), http.MethodPost, srv.URL+"/forward?name=42", forged)
	if status != http.StatusForbidden {
		t.Fatalf("attacker status = %d (%s), want 403", status, body)
	}
	if got := border.count(); got != 0 {
		t.Fatalf("attacker reached the border %d times", got)
	}

	// The same headers with the right token are just an ordinary agreed call.
	status, body = doRequest(t, srv.Client(), http.MethodPost, srv.URL+"/forward?name=42", map[string]string{
		"X-Invite":        "wan-ingress",
		"X-Invite-Ticket": "stolen-nonce",
		"Authorization":   "Bearer " + testToken,
	})
	if status != http.StatusOK {
		t.Fatalf("good-token status = %d (%s), want 200", status, body)
	}
	if got := border.count(); got != 1 {
		t.Fatalf("border calls = %d, want one", got)
	}
}
