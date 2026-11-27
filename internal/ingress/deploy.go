package ingress

import (
	"fmt"
	"net"
	"strings"
)

// MinWANSecretBytes is the floor for the two secrets that hold the boundary up.
// A bearer token shorter than this is a password, and a border HMAC key shorter
// than this is brute-forceable offline from a single captured envelope.
const MinWANSecretBytes = 32

// placeholderMarkers are the shapes a config carries before an operator has
// filled it in. A published repository is the threat model: these strings are
// known, so serving with one is serving with a public credential.
var placeholderMarkers = []string{"replace_with", "changeme", "generate_with", "<token>", "<key>", "example"}

// CheckDeployable refuses a configuration that would put an unauthenticated or
// weakly authenticated surface on the WAN. It is a fail-closed preflight: the
// process exits non-zero with the reason and the fix, rather than starting and
// hoping an operator notices.
//
// The rules are deliberately about the *effect* of the bind, not the intent:
//
//   - loopback is always allowed; the request path stays fail-closed there
//   - a non-loopback bind must carry a real token and a real border key, each at
//     least MinWANSecretBytes
//   - a non-loopback bind must terminate TLS here, or say out loud that TLS is
//     terminated in front of it (AllowPlaintextWAN)
//   - placeholder values are refused everywhere, because a placeholder is a
//     published credential no matter how narrow the bind
func CheckDeployable(cfg Config) error {
	if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
		return fmt.Errorf("tls_cert and tls_key must be set together")
	}
	if isPlaceholder(cfg.Token) {
		return fmt.Errorf("token is a placeholder (%q); generate one with: openssl rand -base64 32", cfg.Token)
	}
	if isPlaceholder(cfg.BorderKey) {
		return fmt.Errorf("border_key is a placeholder; generate one with: openssl rand -base64 32")
	}

	public, err := isPublicBind(cfg.Addr)
	if err != nil {
		return err
	}
	if !public {
		return nil
	}
	if cfg.Token == "" {
		return fmt.Errorf("refusing to bind %q with no token: a public listener that refuses everything is still a public listener", cfg.Addr)
	}
	if len(cfg.Token) < MinWANSecretBytes {
		return fmt.Errorf("refusing to bind %q: token is %d bytes, need at least %d", cfg.Addr, len(cfg.Token), MinWANSecretBytes)
	}
	if len(cfg.BorderKey) < MinWANSecretBytes {
		return fmt.Errorf("refusing to bind %q: border_key is %d bytes, need at least %d", cfg.Addr, len(cfg.BorderKey), MinWANSecretBytes)
	}
	if cfg.TLSCert == "" && !cfg.AllowPlaintextWAN {
		return fmt.Errorf("refusing to bind %q without TLS: set tls_cert/tls_key, or set allow_plaintext_wan with TLS terminated in front", cfg.Addr)
	}
	return nil
}

// PublicBind reports whether an address is reachable beyond the loopback
// interface. The empty host means every interface.
func isPublicBind(addr string) (bool, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false, fmt.Errorf("addr %q is not host:port: %w", addr, err)
	}
	if host == "" {
		return true, nil
	}
	if strings.EqualFold(host, "localhost") {
		return false, nil
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		// A hostname we cannot resolve at startup: treat as public, so the
		// strict rules apply rather than guessing it is loopback.
		return true, nil
	}
	return !ip.IsLoopback(), nil
}

func isPlaceholder(value string) bool {
	if value == "" {
		return false
	}
	lower := strings.ToLower(value)
	for _, marker := range placeholderMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
