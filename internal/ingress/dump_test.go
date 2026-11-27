package ingress

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readDump(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read dump: %v", err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("dump line is not JSON: %q (%v)", line, err)
		}
		out = append(out, rec)
	}
	return out
}

// An empty gateway refuses everything, so the capture is the scan. A successful
// forward is not the interesting request and is not written.
func TestDumpCapturesRefusalsNotForwards(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.jsonl")
	dumper, err := NewDumper(path, 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dumper.Close() }()

	border := &headerCapture{}
	borderSrv := httptest.NewServer(border)
	defer borderSrv.Close()

	resolver := agreementFor(t, borderSrv.URL+"/cluster")
	server := &Server{
		Resolver:  resolver,
		Forwarder: &Forwarder{BorderKey: []byte(testKey), Canary: RandomCanary},
		Token:     testToken,
		Observer:  NewObserver(),
		Dump:      dumper,
	}
	srv := httptest.NewServer(server.Handler())
	defer srv.Close()

	// A scanner with no credential.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/wp-login.php", http.NoBody)
	req.Header.Set("User-Agent", "masscan")
	if resp, err := srv.Client().Do(req); err == nil {
		_ = resp.Body.Close()
	}
	// A path no route answers.
	if resp, err := srv.Client().Get(srv.URL + "/.env"); err == nil {
		_ = resp.Body.Close()
	}
	// A real forward: not written.
	if status, body := doRequest(t, srv.Client(), http.MethodPost, srv.URL+"/forward?name=42", authHeaders()); status != http.StatusOK {
		t.Fatalf("forward = %d (%s)", status, body)
	}

	lines := readDump(t, path)
	if len(lines) != 2 {
		t.Fatalf("dumped %d lines, want 2 refusals", len(lines))
	}
	if lines[0]["path"] != "/wp-login.php" && lines[1]["path"] != "/wp-login.php" {
		t.Fatalf("the scan path was not captured: %v", lines)
	}
	for _, rec := range lines {
		if rec["path"] == "/forward" {
			t.Fatalf("a successful forward was captured: %v", rec)
		}
		if rec["remote"] == "" || rec["at"] == "" {
			t.Fatalf("record is missing provenance: %v", rec)
		}
	}
}

// A capture file must never become a credential store.
func TestDumpNeverWritesTheToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.jsonl")
	dumper, _ := NewDumper(path, 1000)
	defer func() { _ = dumper.Close() }()

	server := &Server{
		Resolver:  NewEmptyResolver(),
		Forwarder: &Forwarder{BorderKey: []byte(testKey)},
		Token:     testToken,
		Observer:  NewObserver(),
		Dump:      dumper,
	}
	srv := httptest.NewServer(server.Handler())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/resolve?name=42", http.NoBody)
	req.Header.Set("Authorization", "Bearer secret-token-value")
	req.Header.Set("Cookie", "session=abc")
	if resp, err := srv.Client().Do(req); err == nil {
		_ = resp.Body.Close()
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-token-value", "session=abc"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("the capture wrote %q: %s", secret, raw)
		}
	}
}

// A flood must not fill the disk; the rate is a per-second budget.
func TestDumpIsRateLimited(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.jsonl")
	dumper, _ := NewDumper(path, 1)
	defer func() { _ = dumper.Close() }()

	clock := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)
	dumper.now = func() time.Time { return clock }

	req := httptest.NewRequest(http.MethodGet, "http://x/scan", http.NoBody)
	req.RemoteAddr = "192.0.2.9:1234"
	for i := 0; i < 20; i++ {
		dumper.Record(req, http.StatusNotFound)
	}
	if lines := readDump(t, path); len(lines) != 1 {
		t.Fatalf("wrote %d lines for a 1/s budget", len(lines))
	}

	clock = clock.Add(2 * time.Second)
	dumper.Record(req, http.StatusNotFound)
	if lines := readDump(t, path); len(lines) != 2 {
		t.Fatalf("the next window admitted %d lines, want 2", len(lines))
	}
}
