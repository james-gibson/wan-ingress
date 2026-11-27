package ingress

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"
)

// ErrBorderUnconfigured is the typed refusal when no signed border is available.
var ErrBorderUnconfigured = errors.New("border key or border address not configured")

const maxForwardBody = 1 << 20

// Envelope headers. The canary and the border's own count travel with every
// forward so the front is not the only witness: the canary proves the border
// carried the marker into its answer, and the count lets the front compare what
// it forwarded with what the border actually saw.
const (
	canaryHeader = "X-Lab-Canary"
	seenHeader   = "X-Lab-Seen"
)

// borderTransport is shared by every forward so the border connection pool is
// reused across requests and across a SIGHUP swap. http.DefaultTransport keeps
// only two idle connections per host, so at concurrency the front would open
// and close a connection per request — churn the border pays for.
var borderTransport = &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	MaxIdleConns:          256,
	MaxIdleConnsPerHost:   64,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

// Forwarder signs and sends one request to an agreed border. It never accepts
// a destination from the caller.
type Forwarder struct {
	Client    *http.Client
	BorderKey []byte

	// Node is this ingress in the route path; Policy is the derived isotope of
	// the declaration the route was resolved under. Both travel inside the
	// signature, so a stale route table is a refusal at the border rather than
	// a silently wrong forward.
	Node   string
	Policy string

	// Canary, when set, is generated per request and must come back in the
	// response. A border that drops it is a border that is not carrying the
	// marker forward, and the front says so instead of assuming success.
	Canary func() (string, error)
}

// RandomCanary makes a per-request marker for the forced-inclusion check.
func RandomCanary() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// Outcome is what a forward observed, not just what it asked for.
type Outcome struct {
	Status       int
	CanaryEchoed bool
	BorderSeen   uint64 // 0 when the border did not report a count
}

// Ready reports whether a signed border is configured.
func (f *Forwarder) Ready() bool {
	return f != nil && len(f.BorderKey) > 0
}

// Forward copies the route's address into a URL, signs the envelope and posts
// the body. Any destination supplied by the caller is ignored.
func (f *Forwarder) Forward(ctx context.Context, route Route, name string, body []byte) (int, error) {
	out, err := f.ForwardObserved(ctx, route, name, body, nil, time.Now().UnixMilli())
	return out.Status, err
}

// ForwardPath is Forward with the route's history. Kept as the simple form for
// callers that only need the status.
func (f *Forwarder) ForwardPath(ctx context.Context, route Route, name string, body []byte, hops []string) (int, error) {
	out, err := f.ForwardObserved(ctx, route, name, body, hops, time.Now().UnixMilli())
	return out.Status, err
}

// ForwardObserved is ForwardPath returning what came back as well as what
// happened: whether the canary survived the round trip and how many requests the
// border says it has seen.
func (f *Forwarder) ForwardObserved(ctx context.Context, route Route, name string, body []byte, hops []string, start int64) (Outcome, error) {
	if !f.Ready() || route.Address == "" {
		return Outcome{}, ErrBorderUnconfigured
	}
	if len(body) > maxForwardBody {
		return Outcome{}, fmt.Errorf("body exceeds %d bytes", maxForwardBody)
	}

	u, err := url.Parse(route.Address)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return Outcome{}, ErrBorderUnconfigured
	}
	cleanName, err := ParseName(name)
	if err != nil {
		return Outcome{}, err
	}
	u.Path = path.Join(u.Path, "namespace", route.Namespace, "name", cleanName)
	u.RawQuery = ""

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return Outcome{}, err
	}
	canary := ""
	if f.Canary != nil {
		canary, err = f.Canary()
		if err != nil {
			return Outcome{}, fmt.Errorf("canary: %w", err)
		}
		req.Header.Set(canaryHeader, canary)
	}
	digest := sha256.Sum256(body)
	// Milliseconds, not seconds: a freshness window tighter than one second has
	// to be expressible before it can be enforced. The 5 s tick exists for clock
	// skew across a cluster; the envelope can carry a much tighter claim.
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	mac := hmac.New(sha256.New, f.BorderKey)
	_, _ = fmt.Fprintf(mac, "%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%d",
		http.MethodPost, u.EscapedPath(), route.Namespace, f.Policy, FormatPath(hops),
		canary, hex.EncodeToString(digest[:]), timestamp, start)
	req.Header.Set("X-Lab-Signature", hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-Lab-Namespace", route.Namespace)
	req.Header.Set("X-Lab-Policy", f.Policy)
	req.Header.Set("X-Lab-Path", FormatPath(hops))
	req.Header.Set(routeStartHeader, strconv.FormatInt(start, 10))
	req.Header.Set("X-Lab-Timestamp", timestamp)
	req.Header.Set("Content-Type", "application/octet-stream")

	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second, Transport: borderTransport}
	}
	resp, err := client.Do(req)
	if err != nil {
		return Outcome{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	out := Outcome{
		Status:       resp.StatusCode,
		CanaryEchoed: canary == "" || resp.Header.Get(canaryHeader) == canary,
	}
	if seen, err := strconv.ParseUint(resp.Header.Get(seenHeader), 10, 64); err == nil {
		out.BorderSeen = seen
	}
	return out, nil
}
