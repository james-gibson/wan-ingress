package ingress

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testGrant(t *testing.T, maxConns int) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestGrantRoundTrip(t *testing.T) {
	pub, priv := testGrant(t, 0)
	g := SignGrant(priv, Grant{
		Namespace: "session-42",
		Batch:     1024,
		MaxConns:  8000,
		Expires:   time.Now().Add(time.Hour).Unix(),
		Issuer:    "jack",
	})
	if err := VerifyGrant(pub, g, time.Now()); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// The whole point of asymmetric signing: the front can check a grant but cannot
// produce one, even though it must hold something to verify.
func TestGrantCannotBeForgedWithoutThePrivateKey(t *testing.T) {
	pub, _ := testGrant(t, 0)
	if _, other, err := ed25519.GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	} else {
		// An attacker who knows the public key still needs the private key.
		forged := SignGrant(other, Grant{
			Namespace: "session-42", Batch: 1 << 20, MaxConns: 1 << 20,
			Expires: time.Now().Add(time.Hour).Unix(),
		})
		if err := VerifyGrant(pub, forged, time.Now()); !errors.Is(err, ErrGrant) {
			t.Fatalf("a grant signed by another key verified: %v", err)
		}
	}
}

func TestGrantFieldsAreInsideTheSignature(t *testing.T) {
	pub, priv := testGrant(t, 0)
	base := SignGrant(priv, Grant{
		Namespace: "session-42", Batch: 64, MaxConns: 64,
		Expires: time.Now().Add(time.Hour).Unix(),
	})
	tampered := []Grant{
		{Version: base.Version, Namespace: "session-99", Batch: base.Batch, MaxConns: base.MaxConns, Expires: base.Expires, Issuer: base.Issuer, Signature: base.Signature},
		{Version: base.Version, Namespace: base.Namespace, Batch: 1 << 20, MaxConns: base.MaxConns, Expires: base.Expires, Issuer: base.Issuer, Signature: base.Signature},
		{Version: base.Version, Namespace: base.Namespace, Batch: base.Batch, MaxConns: 1 << 20, Expires: base.Expires, Issuer: base.Issuer, Signature: base.Signature},
		{Version: base.Version, Namespace: base.Namespace, Batch: base.Batch, MaxConns: base.MaxConns, Expires: base.Expires + 86400, Issuer: base.Issuer, Signature: base.Signature},
		{Version: base.Version, Namespace: base.Namespace, Batch: base.Batch, MaxConns: base.MaxConns, Expires: base.Expires, Issuer: "elsewhere", Signature: base.Signature},
	}
	for i, g := range tampered {
		if err := VerifyGrant(pub, g, time.Now()); !errors.Is(err, ErrGrant) {
			t.Fatalf("tampered grant %d verified: %+v", i, g)
		}
	}
}

func TestExpiredGrantIsRefused(t *testing.T) {
	pub, priv := testGrant(t, 0)
	g := SignGrant(priv, Grant{
		Namespace: "session-42", Batch: 1, MaxConns: 1,
		Expires: time.Now().Add(-time.Minute).Unix(),
	})
	if err := VerifyGrant(pub, g, time.Now()); !errors.Is(err, ErrGrant) {
		t.Fatalf("expired grant verified: %v", err)
	}
}

// The grant may raise the ceiling but never above the operator's local cap.
func TestEffectiveConnsClamps(t *testing.T) {
	cases := []struct {
		local int
		grant *Grant
		want  int
	}{
		{0, nil, 0},
		{100, nil, 100},
		{0, &Grant{MaxConns: 8000}, 8000},
		{100, &Grant{MaxConns: 8000}, 100},
		{100, &Grant{MaxConns: 50}, 50},
	}
	for i, tc := range cases {
		if got := EffectiveConns(tc.local, tc.grant); got != tc.want {
			t.Fatalf("case %d: EffectiveConns(%d, %+v) = %d, want %d", i, tc.local, tc.grant, got, tc.want)
		}
	}
}

func TestLoadGrantRefusesATamperedFile(t *testing.T) {
	pub, priv := testGrant(t, 0)
	g := SignGrant(priv, Grant{
		Namespace: "session-42", Batch: 8, MaxConns: 8, Expires: time.Now().Add(time.Hour).Unix(),
	})
	path := filepath.Join(t.TempDir(), "grant.json")
	raw, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGrant(path, pub, time.Now()); err != nil {
		t.Fatalf("valid grant refused: %v", err)
	}

	var edited map[string]any
	_ = json.Unmarshal(raw, &edited)
	edited["max_conns"] = 1 << 20
	raw, _ = json.Marshal(edited)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGrant(path, pub, time.Now()); !errors.Is(err, ErrGrant) {
		t.Fatalf("edited grant loaded: %v", err)
	}
}
