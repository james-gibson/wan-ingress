package ingress

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
)

// Config is the operator-owned policy. It is deliberately small: an agreement
// file, the admission token, the border key, and the registry to register with.
// A config file lets SIGHUP swap all of it in place as traffic is added; flags
// override the file so an operator can still launch with one command.
type Config struct {
	Addr       string `json:"addr,omitempty"`
	Agreements string `json:"agreements,omitempty"`
	Token      string `json:"token,omitempty"`
	BorderKey  string `json:"border_key,omitempty"`
	SmokeAlarm string `json:"smoke_alarm,omitempty"`

	// Node is this instance's name in a route path. Empty means the path is not
	// extended, which is the single-instance case. In a sub-cluster every
	// instance needs its own value, or the loop check refuses its peers.
	Node string `json:"node,omitempty"`

	// Peers are ingress instances reached directly, whose route path is
	// believed. A path from any other source is ignored, so an anonymous
	// caller cannot name a node and have it refuse a request it never saw.
	Peers []string `json:"peers,omitempty"`

	// Terminator is the TLS terminator or load balancer in front of this
	// instance (nginx, a cloud LB). It relays arbitrary clients, so a path
	// arriving from it is a *client's* header, not a peer's: it is ignored even
	// when the address is also listed in peers.
	Terminator []string `json:"terminator,omitempty"`

	// TLSCert and TLSCertKey terminate TLS in this process. A public bind
	// without them is refused unless AllowPlaintextWAN is set, and that flag
	// means "TLS is terminated in front of me", not "TLS does not matter".
	TLSCert           string `json:"tls_cert,omitempty"`
	TLSKey            string `json:"tls_key,omitempty"`
	AllowPlaintextWAN bool   `json:"allow_plaintext_wan,omitempty"`
}

// LoadConfigFile reads a JSON config. Unknown keys are refused: a typo must not
// silently leave the ingress defensive when an operator believes it is serving.
func LoadConfigFile(path string) (Config, error) {
	if path == "" {
		return Config{}, nil
	}
	file, err := os.Open(path) //nolint:gosec // the operator supplies the config path
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer func() { _ = file.Close() }()

	var cfg Config
	dec := json.NewDecoder(io.LimitReader(file, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	return cfg, nil
}

// NewServer builds a server from a config. The observer is passed in so a
// reload keeps the counters the monitor has already seen; a new observer would
// make the light forget every quarantine it had reported.
func NewServer(cfg Config, observer *Observer) (*Server, error) {
	resolver := NewEmptyResolver()
	if cfg.Agreements != "" {
		file, err := os.Open(cfg.Agreements)
		if err != nil {
			return nil, fmt.Errorf("open agreements: %w", err)
		}
		resolver, err = LoadAgreements(file)
		_ = file.Close()
		if err != nil {
			return nil, err
		}
	}
	if observer == nil {
		observer = NewObserver()
	}
	peers, err := ParsePeers(cfg.Peers)
	if err != nil {
		return nil, err
	}
	terminators, err := ParsePeers(cfg.Terminator)
	if err != nil {
		return nil, err
	}
	srv := &Server{
		Resolver:   resolver,
		Forwarder:  &Forwarder{BorderKey: []byte(cfg.BorderKey), Node: cfg.Node, Policy: resolver.PolicyIsotope()},
		Token:      cfg.Token,
		Observer:   observer,
		Node:       cfg.Node,
		Peers:      peers,
		Terminator: terminators,
	}
	srv.Handler() // build the mux once, at swap time
	return srv, nil
}

// Runtime is the atomic config switch. SIGHUP builds a new Server off to the
// side and swaps it in; a request in flight finishes on the old policy, and the
// next one sees the new one. An invalid config never replaces a good one.
type Runtime struct {
	current atomic.Pointer[Server]
}

// Swap installs a server as the current policy.
func (rt *Runtime) Swap(srv *Server) {
	if srv == nil {
		return
	}
	srv.Handler()
	rt.current.Store(srv)
}

// Current returns the server serving right now.
func (rt *Runtime) Current() *Server {
	if rt == nil {
		return nil
	}
	return rt.current.Load()
}

// ServeHTTP dispatches to the current policy. A nil runtime is not ready; it
// never falls through to an empty, permissive handler.
func (rt *Runtime) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	srv := rt.Current()
	if srv == nil {
		http.Error(w, "not configured", http.StatusServiceUnavailable)
		return
	}
	srv.Handler().ServeHTTP(w, r)
}
