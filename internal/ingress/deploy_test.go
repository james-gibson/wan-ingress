package ingress

import (
	"strings"
	"testing"
)

// A tokenless public bind is the capture posture, and it is a named exception:
// it needs both the flag and a capture file, so the guard still refuses an
// operator who forgets the token on a serving gateway.
func TestTokenlessPublicBindNeedsTheCapturePosture(t *testing.T) {
	public := Config{Addr: "0.0.0.0:8443", BorderKey: strings.Repeat("k", 32)}
	if err := CheckDeployable(public); err == nil {
		t.Fatal("a tokenless public bind was accepted without the capture posture")
	}
	gateway := public
	gateway.AllowEmpty = true
	if err := CheckDeployable(gateway); err == nil {
		t.Fatal("allow_empty without a capture file was accepted")
	}
	gateway.DumpUnexpected = "/var/log/scan.jsonl"
	gateway.AllowPlaintextWAN = true // the gateway terminates nothing; it observes
	if err := CheckDeployable(gateway); err != nil {
		t.Fatalf("the capture posture was refused: %v", err)
	}
}
