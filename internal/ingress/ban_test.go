package ingress

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read ban log: %v", err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func TestBanLogWritesAtTheThreshold(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bans.log")
	bans := NewBanLog(path, nil)
	defer func() { _ = bans.Close() }()
	if err := bans.Err(); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < bans.threshold-1; i++ {
		bans.Record("192.0.2.10:5555", "untrusted")
	}
	if lines := readLines(t, path); len(lines) != 0 {
		t.Fatalf("wrote %d lines below the threshold", len(lines))
	}
	bans.Record("192.0.2.10:5555", "untrusted")
	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("lines = %d, want 1", len(lines))
	}
	if !strings.Contains(lines[0], "wan-ingress ban ip=192.0.2.10 reason=untrusted") {
		t.Fatalf("line = %q", lines[0])
	}
}

// The jump host must never be bannable: a ban on the way in removes the way to
// fix what was banned.
func TestBanLogNeverBansTheAllowlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bans.log")
	never, err := ParsePeers([]string{"192.168.1.30"})
	if err != nil {
		t.Fatal(err)
	}
	bans := NewBanLog(path, never)
	defer func() { _ = bans.Close() }()

	for i := 0; i < bans.threshold*5; i++ {
		bans.Record("192.168.1.30:40000", "untrusted")
	}
	if lines := readLines(t, path); len(lines) != 0 {
		t.Fatalf("the jump host was banned: %v", lines)
	}
	// A different address in the same window still gets banned.
	for i := 0; i < bans.threshold; i++ {
		bans.Record("192.0.2.99:40000", "shape_mismatch")
	}
	if lines := readLines(t, path); len(lines) != 1 {
		t.Fatalf("a non-allowlisted address was not banned: %v", lines)
	}
}

func TestBanLogWindowResets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bans.log")
	bans := NewBanLog(path, nil)
	defer func() { _ = bans.Close() }()

	clock := time.Now()
	bans.now = func() time.Time { return clock }
	for i := 0; i < bans.threshold-1; i++ {
		bans.Record("192.0.2.5:1", "untrusted")
	}
	// The window passes; the count starts again rather than accumulating.
	clock = clock.Add(2 * time.Minute)
	bans.Record("192.0.2.5:1", "untrusted")
	if lines := readLines(t, path); len(lines) != 0 {
		t.Fatalf("a stale window banned: %v", lines)
	}
}

// An attacker cycling source addresses must not grow this front's memory.
func TestBanLogBoundOnDistinctAddresses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bans.log")
	bans := NewBanLog(path, nil)
	defer func() { _ = bans.Close() }()

	for i := 0; i < bans.maxKeys*2; i++ {
		addr := fmt.Sprintf("10.%d.%d.%d:1234", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
		bans.Record(addr, "untrusted")
	}
	bans.mu.Lock()
	size := len(bans.counts)
	bans.mu.Unlock()
	if size > bans.maxKeys {
		t.Fatalf("ban state grew to %d entries", size)
	}
}
