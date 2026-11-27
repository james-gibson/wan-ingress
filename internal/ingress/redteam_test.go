package ingress

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// This file is the adversarial half of the test suite: it assumes the caller is
// hostile and that the operator may have shipped the example config unchanged.
// Every case must fail closed before the border is reached.

// headerCapture records every header the border saw, which is the only honest
// way to prove a caller-supplied header did not travel.
type headerCapture struct {
	mu      sync.Mutex
	seen    []http.Header
	paths   []string
	methods []string
}

func (c *headerCapture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.seen = append(c.seen, r.Header.Clone())
	c.paths = append(c.paths, r.URL.Path)
	c.methods = append(c.methods, r.Method)
	c.mu.Unlock()
	if canary := r.Header.Get("X-Lab-Canary"); canary != "" {
		w.Header().Set("X-Lab-Canary", canary)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *headerCapture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

func (c *headerCapture) last() (http.Header, string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.seen) == 0 {
		return nil, "", ""
	}
	return c.seen[len(c.seen)-1], c.paths[len(c.paths)-1], c.methods[len(c.methods)-1]
}

func agreementFor(t *testing.T, borderURL string) *Resolver {
	t.Helper()
	body := fmt.Sprintf(`{"agreements":[{"id":"workspace-42","namespace":"session-42","border":%q,"aliases":["42"],"rung":2}]}`, borderURL)
	res, err := LoadAgreements(strings.NewReader(body))
	if err != nil {
		t.Fatalf("load agreements: %v", err)
	}
	return res
}

// The example config is published. If it can be run unchanged, the repository
// has shipped a public credential with a public bind.
func TestShippedExampleConfigIsNotDeployable(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "wan-ingress.example.json")
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = file.Close() }()

	var cfg Config
	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if err := CheckDeployable(cfg); err == nil {
		t.Fatalf("the shipped example is deployable: addr=%q token=%q", cfg.Addr, cfg.Token)
	}
}

func TestPublicBindRefusesWeakOrMissingSecrets(t *testing.T) {
	strong := strings.Repeat("a", MinWANSecretBytes)
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "no token",
			cfg:  Config{Addr: "0.0.0.0:8443", BorderKey: strong, TLSCert: "c", TLSKey: "k"},
			want: "no token",
		},
		{
			name: "short token",
			cfg:  Config{Addr: "0.0.0.0:8443", Token: "hunter2", BorderKey: strong, TLSCert: "c", TLSKey: "k"},
			want: "token is",
		},
		{
			name: "short border key",
			cfg:  Config{Addr: "0.0.0.0:8443", Token: strong, BorderKey: "k", TLSCert: "c", TLSKey: "k"},
			want: "border_key is",
		},
		{
			name: "no tls",
			cfg:  Config{Addr: "0.0.0.0:8443", Token: strong, BorderKey: strong},
			want: "without TLS",
		},
		{
			name: "wildcard without host",
			cfg:  Config{Addr: ":8443", Token: strong, BorderKey: strong},
			want: "without TLS",
		},
		{
			name: "placeholder token",
			cfg:  Config{Addr: "127.0.0.1:8443", Token: "REPLACE_WITH_ADMISSION_TOKEN", BorderKey: strong},
			want: "placeholder",
		},
		{
			name: "placeholder key",
			cfg:  Config{Addr: "127.0.0.1:8443", Token: strong, BorderKey: "REPLACE_WITH_BORDER_HMAC_KEY"},
			want: "placeholder",
		},
		{
			name: "half TLS",
			cfg:  Config{Addr: "127.0.0.1:8443", Token: strong, BorderKey: strong, TLSCert: "c"},
			want: "set together",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckDeployable(tc.cfg)
			if err == nil {
				t.Fatalf("accepted: %+v", tc.cfg)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestPublicBindWithRealSecretsAndTLSIsDeployable(t *testing.T) {
	strong := strings.Repeat("s", MinWANSecretBytes)
	if err := CheckDeployable(Config{Addr: "0.0.0.0:8443", Token: strong, BorderKey: strong, TLSCert: "c", TLSKey: "k"}); err != nil {
		t.Fatalf("refused a deployable config: %v", err)
	}
	// An explicit plaintext override is what it says: TLS is in front.
	if err := CheckDeployable(Config{Addr: "0.0.0.0:8443", Token: strong, BorderKey: strong, AllowPlaintextWAN: true}); err != nil {
		t.Fatalf("refused an explicit plaintext override: %v", err)
	}
}

func TestLoopbackStaysOpenForLocalWork(t *testing.T) {
	if err := CheckDeployable(Config{Addr: "127.0.0.1:8443"}); err != nil {
		t.Fatalf("refused loopback: %v", err)
	}
	if public, err := isPublicBind("127.0.0.1:8443"); err != nil || public {
		t.Fatalf("127.0.0.1 classified public=%v err=%v", public, err)
	}
	if public, err := isPublicBind("[::1]:8443"); err != nil || public {
		t.Fatalf("::1 classified public=%v err=%v", public, err)
	}
	if public, _ := isPublicBind("0.0.0.0:8443"); !public {
		t.Fatal("0.0.0.0 classified loopback")
	}
	if public, _ := isPublicBind(":8443"); !public {
		t.Fatal("empty host classified loopback")
	}
}

// The monitor's green light is the claim that agreed traffic crossed the
// border. A resolution is not a crossing: a caller can resolve any agreed name
// and never send a body. Before the split counters, one /resolve advertised
// ingress/forward and the light went green with the border untouched.
func TestResolveAloneDoesNotAdvertiseForwarding(t *testing.T) {
	border := &headerCapture{}
	borderSrv := httptest.NewServer(border)
	defer borderSrv.Close()

	resolver := agreementFor(t, borderSrv.URL+"/cluster")
	srv := testServer(t, resolver, &Forwarder{BorderKey: []byte(testKey)}, testToken)
	defer srv.Close()

	status, body := doRequest(t, srv.Client(), http.MethodGet, srv.URL+"/resolve?name=42", authHeaders())
	if status != http.StatusOK {
		t.Fatalf("resolve status = %d (%s)", status, body)
	}
	if got := border.count(); got != 0 {
		t.Fatalf("resolve reached the border %d times", got)
	}

	capabilities := advertisedCapabilities(t, srv)
	if _, ok := capabilities["ingress"]; ok {
		t.Fatalf("a resolution advertised %v without crossing the border", capabilities)
	}

	if status, body := doRequest(t, srv.Client(), http.MethodPost, srv.URL+"/forward?name=42", authHeaders()); status != http.StatusOK {
		t.Fatalf("forward status = %d (%s)", status, body)
	}
	capabilities = advertisedCapabilities(t, srv)
	if capabilities["ingress"] != "forward" {
		t.Fatalf("a completed forward did not advertise forwarding: %v", capabilities)
	}
}

func advertisedCapabilities(t *testing.T, srv *httptest.Server) map[string]any {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	status := resp.StatusCode
	if status != http.StatusOK {
		t.Fatalf("mcp status = %d (%s)", status, body)
	}
	var decoded struct {
		Result struct {
			Capabilities map[string]any `json:"capabilities"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode mcp: %v (%s)", err, body)
	}
	return decoded.Result.Capabilities
}

// A caller-supplied header is a wish. Only the agreement and the ingress's own
// signature may reach the border.
func TestCallerHeadersCannotReachTheBorder(t *testing.T) {
	border := &headerCapture{}
	borderSrv := httptest.NewServer(border)
	defer borderSrv.Close()

	resolver := agreementFor(t, borderSrv.URL+"/cluster")
	srv := testServer(t, resolver, &Forwarder{BorderKey: []byte(testKey)}, testToken)
	defer srv.Close()

	headers := authHeaders()
	headers["X-Lab-Address"] = "http://attacker.example/"
	headers["X-Lab-Namespace"] = "session-attacker"
	headers["X-Lab-Signature"] = "00"
	headers["X-Lab-Timestamp"] = "1"
	headers["X-Forwarded-For"] = "203.0.113.9"

	status, body := doRequest(t, srv.Client(), http.MethodPost, srv.URL+"/forward?name=42", headers)
	if status != http.StatusOK {
		t.Fatalf("forward status = %d (%s)", status, body)
	}
	got, path, method := border.last()
	if method != http.MethodPost {
		t.Fatalf("method = %q", method)
	}
	if !strings.HasPrefix(path, "/cluster/namespace/session-42/name/42") {
		t.Fatalf("border path = %q, caller-supplied address or namespace traveled", path)
	}
	if got.Get("X-Lab-Namespace") != "session-42" {
		t.Fatalf("border namespace = %q", got.Get("X-Lab-Namespace"))
	}
	if sig := got.Get("X-Lab-Signature"); len(sig) != 64 {
		t.Fatalf("border signature = %q, want the ingress's own 64-hex value", sig)
	}
	if got.Get("X-Lab-Address") != "" {
		t.Fatalf("caller-supplied X-Lab-Address reached the border: %q", got.Get("X-Lab-Address"))
	}
	if auth := got.Get("Authorization"); auth != "" {
		t.Fatalf("caller credential reached the border: %q", auth)
	}
	// The envelope carries milliseconds, so a window tighter than a second is
	// expressible. A seconds-resolution stamp could not support one.
	stampedMS, err := strconv.ParseInt(got.Get("X-Lab-Timestamp"), 10, 64)
	if err != nil {
		t.Fatalf("border timestamp = %q: %v", got.Get("X-Lab-Timestamp"), err)
	}
	if age := time.Since(time.UnixMilli(stampedMS)); age > time.Minute || age < -time.Minute {
		t.Fatalf("border timestamp is %s from now; the freshness window would refuse it", age)
	}
	if len(got.Get("X-Lab-Timestamp")) < 13 {
		t.Fatalf("timestamp %q looks like seconds, not milliseconds", got.Get("X-Lab-Timestamp"))
	}
}

// A body larger than the forward limit is refused before the border, and the
// refusal is visible as a quarantine rather than a silent truncation.
func TestOversizedBodyIsRefusedBeforeTheBorder(t *testing.T) {
	border := &headerCapture{}
	borderSrv := httptest.NewServer(border)
	defer borderSrv.Close()

	resolver := agreementFor(t, borderSrv.URL+"/cluster")
	srv := testServer(t, resolver, &Forwarder{BorderKey: []byte(testKey)}, testToken)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/forward?name=42", strings.NewReader(strings.Repeat("x", maxForwardBody+1)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("oversized body status = %d, want 422", resp.StatusCode)
	}
	if got := border.count(); got != 0 {
		t.Fatalf("oversized body reached the border %d times", got)
	}
}

// Duplicate query parameters are legal, and two parsers may disagree about
// which one wins. The ingress resolves and forwards the same one (the first),
// so a name cannot be resolved as one thing and forwarded as another.
func TestDuplicateNameParametersResolveAndForwardTheSameName(t *testing.T) {
	border := &headerCapture{}
	borderSrv := httptest.NewServer(border)
	defer borderSrv.Close()

	resolver := agreementFor(t, borderSrv.URL+"/cluster")
	srv := testServer(t, resolver, &Forwarder{BorderKey: []byte(testKey)}, testToken)
	defer srv.Close()

	status, body := doRequest(t, srv.Client(), http.MethodPost, srv.URL+"/forward?name=42&name=nowhere", authHeaders())
	if status != http.StatusOK {
		t.Fatalf("forward status = %d (%s), want the first name to win", status, body)
	}
	_, path, _ := border.last()
	if !strings.HasSuffix(path, "/name/42") {
		t.Fatalf("border path = %q, want name/42", path)
	}
}

// Anonymous callers get surfaces that cannot enumerate the map: no route, no
// border address, no namespace.
func TestAnonymousSurfacesLeakNoRoute(t *testing.T) {
	strong := strings.Repeat("s", MinWANSecretBytes)
	borderSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer borderSrv.Close()

	srv := testServer(t, agreementFor(t, borderSrv.URL+"/cluster"), &Forwarder{BorderKey: []byte(strong)}, strong)
	defer srv.Close()

	for _, probe := range []struct {
		method, path string
	}{
		{http.MethodGet, "/resolve?name=42"},
		{http.MethodPost, "/forward?name=42"},
	} {
		status, body := doRequest(t, srv.Client(), probe.method, srv.URL+probe.path, nil)
		if status != http.StatusForbidden {
			t.Fatalf("%s without auth = %d (%s)", probe.path, status, body)
		}
		if strings.Contains(string(body), "cluster") || strings.Contains(string(body), "session-42") {
			t.Fatalf("%s leaked the route: %s", probe.path, body)
		}
	}
	for _, path := range []string{"/status", "/readyz", "/healthz"} {
		status, body := doRequest(t, srv.Client(), http.MethodGet, srv.URL+path, nil)
		if status/100 != 2 && status != http.StatusServiceUnavailable {
			t.Fatalf("%s = %d (%s)", path, status, body)
		}
		if strings.Contains(string(body), "cluster") || strings.Contains(string(body), "session-42") {
			t.Fatalf("%s leaked the route: %s", path, body)
		}
	}
}

// The namespace is spliced into the border's path. An agreement file is
// operator-owned, but a typo or a bad template must fail loudly rather than
// silently rewrite the route, which the signature would then bless.
func TestAgreementNamespaceCannotEscapeItsPathSegment(t *testing.T) {
	for _, namespace := range []string{"../admin", "session/../../x", "session\\42", ".", "..", "", "session\x00"} {
		body := fmt.Sprintf(`{"agreements":[{"id":"a","namespace":%q,"border":"http://127.0.0.1:1/cluster","aliases":["42"]}]}`, namespace)
		if _, err := LoadAgreements(strings.NewReader(body)); err == nil {
			t.Fatalf("accepted namespace %q", namespace)
		}
	}
	body := `{"agreements":[{"id":"a","namespace":"session-42","border":"http://127.0.0.1:1/cluster","aliases":["42"]}]}`
	if _, err := LoadAgreements(strings.NewReader(body)); err != nil {
		t.Fatalf("refused a valid namespace: %v", err)
	}
}
