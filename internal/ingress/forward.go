package ingress

import (
	"bytes"
	"context"
	"crypto/hmac"
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
}

// Ready reports whether a signed border is configured.
func (f *Forwarder) Ready() bool {
	return f != nil && len(f.BorderKey) > 0
}

// Forward copies the route's address into a URL, signs the envelope and posts
// the body. Any destination supplied by the caller is ignored.
func (f *Forwarder) Forward(ctx context.Context, route Route, name string, body []byte) (int, error) {
	return f.ForwardPath(ctx, route, name, body, nil)
}

// ForwardPath is Forward with the route's history. The path is part of the
// signed material, so a hop cannot be added or removed in transit.
func (f *Forwarder) ForwardPath(ctx context.Context, route Route, name string, body []byte, hops []string) (int, error) {
	if !f.Ready() || route.Address == "" {
		return 0, ErrBorderUnconfigured
	}
	if len(body) > maxForwardBody {
		return 0, fmt.Errorf("body exceeds %d bytes", maxForwardBody)
	}

	u, err := url.Parse(route.Address)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return 0, ErrBorderUnconfigured
	}
	cleanName, err := ParseName(name)
	if err != nil {
		return 0, err
	}
	u.Path = path.Join(u.Path, "namespace", route.Namespace, "name", cleanName)
	u.RawQuery = ""

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	digest := sha256.Sum256(body)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, f.BorderKey)
	_, _ = fmt.Fprintf(mac, "%s\n%s\n%s\n%s\n%s\n%s\n%s",
		http.MethodPost, u.EscapedPath(), route.Namespace, f.Policy, FormatPath(hops),
		hex.EncodeToString(digest[:]), timestamp)
	req.Header.Set("X-Lab-Signature", hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-Lab-Namespace", route.Namespace)
	req.Header.Set("X-Lab-Policy", f.Policy)
	req.Header.Set("X-Lab-Path", FormatPath(hops))
	req.Header.Set("X-Lab-Timestamp", timestamp)
	req.Header.Set("Content-Type", "application/octet-stream")

	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second, Transport: borderTransport}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, nil
}
