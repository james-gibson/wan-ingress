package ingress

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// A grant is an authority's signed statement of how much capacity an ingress may
// use: which namespace it may serve, how large a ticket batch it may hold, how
// many connections it may admit, and until when.
//
// The signature is Ed25519 rather than an HMAC on purpose. Verifying an HMAC
// requires the key, and a holder of the key can mint. A front that verifies with
// a public key can check a grant but cannot forge one, so "go faster" is
// something the authority says and not something the front decides.
const grantVersion = "wan-ingress-grant-v1"

// ErrGrant is the typed refusal for a grant that does not verify.
var ErrGrant = errors.New("grant does not verify")

// Grant is the capability the authority issues.
type Grant struct {
	Version   string `json:"version"`
	Namespace string `json:"namespace"`
	Batch     int    `json:"batch"`
	MaxConns  int    `json:"max_conns"`
	Expires   int64  `json:"expires"`
	Issuer    string `json:"issuer,omitempty"`
	Signature string `json:"signature"`
}

// Message is the signed material. Every field that grants something is inside
// it, so none can be edited in transit.
func (g Grant) Message() []byte {
	return []byte(fmt.Sprintf("%s\n%s\n%d\n%d\n%d\n%s",
		grantVersion, g.Namespace, g.Batch, g.MaxConns, g.Expires, g.Issuer))
}

// SignGrant fills the version and signature. The authority calls this; the front
// never holds the private key.
func SignGrant(priv ed25519.PrivateKey, g Grant) Grant {
	g.Version = grantVersion
	g.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, g.Message()))
	return g
}

// VerifyGrant checks the signature, the shape, and the expiry. now is injected so
// the check is testable and a skew allowance can be applied by the caller.
func VerifyGrant(pub ed25519.PublicKey, g Grant, now time.Time) error {
	if g.Version != grantVersion {
		return fmt.Errorf("%w: version %q", ErrGrant, g.Version)
	}
	if g.Namespace == "" {
		return fmt.Errorf("%w: no namespace", ErrGrant)
	}
	if g.Batch <= 0 || g.MaxConns <= 0 {
		return fmt.Errorf("%w: batch and max_conns must be positive", ErrGrant)
	}
	sig, err := base64.RawURLEncoding.DecodeString(g.Signature)
	if err != nil {
		return fmt.Errorf("%w: signature is not base64url", ErrGrant)
	}
	if !ed25519.Verify(pub, g.Message(), sig) {
		return ErrGrant
	}
	if g.Expires <= 0 || now.After(time.Unix(g.Expires, 0)) {
		return fmt.Errorf("%w: expired at %s", ErrGrant, time.Unix(g.Expires, 0).UTC().Format(time.RFC3339))
	}
	return nil
}

// LoadGrant reads and verifies a grant file.
func LoadGrant(path string, pub ed25519.PublicKey, now time.Time) (Grant, error) {
	file, err := os.Open(path) //nolint:gosec // the operator supplies the grant path
	if err != nil {
		return Grant{}, fmt.Errorf("open grant: %w", err)
	}
	defer func() { _ = file.Close() }()

	var g Grant
	dec := json.NewDecoder(file)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&g); err != nil {
		return Grant{}, fmt.Errorf("decode grant: %w", err)
	}
	if err := VerifyGrant(pub, g, now); err != nil {
		return Grant{}, err
	}
	return g, nil
}

// ParseGrantKey reads an Ed25519 public key from base64url or standard base64.
func ParseGrantKey(text string) (ed25519.PublicKey, error) {
	raw, err := decodeBase64(text)
	if err != nil {
		return nil, fmt.Errorf("grant key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("grant key: %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// EffectiveConns is the connection ceiling this process may use: the smaller of
// the operator's local cap and anything the grant allows. A local cap of 0 means
// "no local ceiling", so the grant decides; a grant can never raise the local cap.
func EffectiveConns(local int, g *Grant) int {
	switch {
	case g == nil:
		return local
	case local <= 0:
		return g.MaxConns
	case g.MaxConns < local:
		return g.MaxConns
	default:
		return local
	}
}

func decodeBase64(text string) ([]byte, error) {
	if raw, err := base64.RawURLEncoding.DecodeString(text); err == nil {
		return raw, nil
	}
	if raw, err := base64.StdEncoding.DecodeString(text); err == nil {
		return raw, nil
	}
	return base64.URLEncoding.DecodeString(text)
}
