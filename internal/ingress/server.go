package ingress

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// Server is the WAN front: thin admission, resolution by agreement, signed
// forwarding, and observable refusals. It is built from the feature in
// features/wan-ingress.feature.
type Server struct {
	Resolver   *Resolver
	Forwarder  *Forwarder
	Token      string
	Observer   *Observer
	Node       string
	Peers      PeerSet
	Terminator PeerSet
	Shapes     *ShapeSet
	Bans       *BanLog

	handler http.Handler // built once by Handler, reused by the runtime switch
}

// Handler wires the surfaces. Defaults are fail-closed: no agreements means
// every name is unknown; no token means every caller is untrusted. The POST
// /mcp surface is the smoke-alarm probe: it advertises forwarding only once
// real agreed traffic has crossed the border.
func (s *Server) Handler() http.Handler {
	if s.handler != nil {
		return s.handler
	}
	if s.Observer == nil {
		s.Observer = NewObserver()
	}
	if s.Resolver == nil {
		s.Resolver = NewEmptyResolver()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", ServeHealthz)
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ServeReadyz(s.ready(), w, r)
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		s.Observer.ServeStatus(s.ready(), w, r)
	})
	// The derived declaration, published so another node or a monitor can
	// answer "do we agree?" without reading the file. No route contents.
	mux.HandleFunc("GET /policy", s.servePolicy)
	mux.HandleFunc("GET /resolve", s.serveResolve)
	mux.HandleFunc("POST /forward", s.serveForward)
	mux.HandleFunc("POST /mcp", s.serveMonitor)
	s.handler = mux
	return mux
}

func (s *Server) ready() bool {
	return s != nil && s.Resolver != nil && s.Token != "" && s.Forwarder.Ready()
}

func (s *Server) serveResolve(w http.ResponseWriter, r *http.Request) {
	if !Admit(r.Header.Get("Authorization"), s.Token) {
		s.refuse(w, r, http.StatusForbidden, "untrusted")
		return
	}

	decision := s.Resolver.Resolve(rawQueryValue(r.URL.RawQuery, "name"))
	s.Observer.RecordResolve(decision)
	status := http.StatusUnprocessableEntity
	if decision.Decision == "forward" {
		status = http.StatusOK
	}
	writeDecision(w, status, decision)
}

func (s *Server) serveForward(w http.ResponseWriter, r *http.Request) {
	if !Admit(r.Header.Get("Authorization"), s.Token) {
		s.refuse(w, r, http.StatusForbidden, "untrusted")
		return
	}

	rawName := rawQueryValue(r.URL.RawQuery, "name")
	decision := s.Resolver.Resolve(rawName)
	if decision.Decision != "forward" {
		s.Observer.Record(decision)
		writeDecision(w, http.StatusUnprocessableEntity, decision)
		return
	}
	if !s.Forwarder.Ready() {
		s.refuse(w, r, http.StatusUnprocessableEntity, "border_unconfigured")
		return
	}

	// A loop is refused before the body is read: a refusal should not cost the
	// caller an upload.
	path, ok := s.routePath(w, r)
	if !ok {
		return
	}

	// The class is decided from the declared header and the body length, and the
	// budget is taken before the body is read: refusing after reading is the
	// memory cost the budget exists to avoid.
	limit, err := s.Shapes.Decide(r.Header.Get(shapeHeader), r.ContentLength)
	if err != nil {
		reason := "shape_unknown"
		if errors.Is(err, ErrShapeMismatch) {
			reason = "shape_mismatch"
		}
		s.refuse(w, r, http.StatusUnprocessableEntity, reason)
		return
	}
	release, ok := s.Shapes.Take(limit)
	if !ok {
		// A retryable refusal with a constant shape. The budget itself is
		// published on /policy, so probing cannot discover anything hidden: the
		// signal an attacker wants is already public.
		w.Header().Set("Retry-After", "1")
		w.Header().Set("Cache-Control", "no-store")
		s.refuse(w, r, http.StatusTooManyRequests, "shape_full")
		return
	}
	defer release()

	body, err := io.ReadAll(io.LimitReader(r.Body, maxForwardBody+1))
	if err != nil || len(body) > maxForwardBody {
		s.refuse(w, r, http.StatusUnprocessableEntity, "malformed")
		return
	}
	outcome, err := s.Forwarder.ForwardObserved(r.Context(), *decision.Route, rawName, body, path)
	if err != nil {
		s.refuse(w, r, http.StatusBadGateway, "upstream")
		return
	}
	s.Observer.ObserveBorder(outcome.BorderSeen)
	if !outcome.CanaryEchoed {
		// The border accepted the request but did not carry the marker into its
		// answer. That is a forced-inclusion failure: the written record and the
		// received record disagree.
		s.refuse(w, r, http.StatusBadGateway, "canary_lost")
		return
	}

	forwarded := Decision{Decision: "forward", Route: decision.Route, UpstreamStatus: outcome.Status}
	s.Observer.Record(forwarded)
	writeDecision(w, http.StatusOK, forwarded)
}

// servePolicy publishes the derived isotope of the declaration this node is
// running. It is unauthenticated on purpose: it is a digest and two counts, it
// is what a peer compares against, and a value that cannot be read from outside
// the node that computed it is not checkable (lab/SPLASH.md, *Derived values*).
func (s *Server) servePolicy(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(policyBody{
		PolicySummary: s.Resolver.Summary(),
		Shapes:        s.Shapes.Limits(),
	})
}

// policyBody is the public view of what this node is running. The shape budgets
// are published on purpose: a capacity that is already inferable by probing is
// better published than probed, and publishing removes the timing oracle without
// hiding anything that was ever secret.
type policyBody struct {
	PolicySummary
	Shapes []ShapeLimit `json:"shapes,omitempty"`
}

// routePath extends the route history with this node. A caller-supplied path is
// believed only from a configured peer; otherwise it is discarded so that an
// anonymous caller cannot make this node refuse a request on another's behalf.
func (s *Server) routePath(w http.ResponseWriter, r *http.Request) ([]string, bool) {
	// A terminator relays arbitrary clients, so its address proves nothing
	// about the path it forwards. Only a directly reached peer is believed.
	trusted := s.Peers.Contains(r.RemoteAddr) && !s.Terminator.Contains(r.RemoteAddr)
	var carried []string
	if trusted {
		parsed, err := ParsePath(r.Header.Get(pathHeader))
		if err != nil {
			s.refuse(w, r, http.StatusUnprocessableEntity, "malformed")
			return nil, false
		}
		carried = parsed
	}
	path, err := AppendHop(carried, s.Node)
	if err != nil {
		reason := "path_loop"
		if !errors.Is(err, ErrPathLoop) {
			reason = "malformed"
		}
		s.refuse(w, r, http.StatusUnprocessableEntity, reason)
		return nil, false
	}
	return path, true
}

// refuse records and answers one typed quarantine, and offers the caller to the
// ban log. Recording is centralized so every refusal is counted and attributable
// in one place.
func (s *Server) refuse(w http.ResponseWriter, r *http.Request, status int, reason string) {
	refusal := quarantine(reason)
	s.Observer.Record(refusal)
	if s.Bans != nil && r != nil {
		s.Bans.Record(r.RemoteAddr, reason)
	}
	writeDecision(w, status, refusal)
}

func writeDecision(w http.ResponseWriter, status int, decision Decision) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(decision)
}

// rawQueryValue takes the raw (still percent-encoded) value so ParseName is
// the single decoder. url.Values.Get would decode once here and ParseName would
// decode twice — a classic way to smuggle a second interpretation.
func rawQueryValue(rawQuery, key string) string {
	for _, pair := range strings.Split(rawQuery, "&") {
		k, v, ok := strings.Cut(pair, "=")
		if ok && k == key {
			return v
		}
	}
	return ""
}
