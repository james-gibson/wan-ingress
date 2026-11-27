package ingress

import (
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"time"
)

// Dumper records traffic the front refused. Pointed at an empty gateway — no
// agreements, no token — every request is refused, so the file becomes a record
// of what the internet says to an unconfigured host: scanners, path probes, and
// whatever they believe about a server that has not answered yet.
//
// It is deliberately not a request log. A successful forward is not written; the
// interesting request is the one the gateway did not expect. And it is bounded:
// attacker-controlled strings are length-capped and JSON-escaped, the rate is a
// per-second budget, and the body is never read — the request line, source and
// headers are the scan, and reading bodies would put the capture back in the
// memory path the front exists to avoid.
type Dumper struct {
	mu     sync.Mutex
	file   *os.File
	rate   int
	window time.Time
	used   int
	drop   int
	now    func() time.Time
}

const (
	dumpMaxLine    = 4096
	dumpMaxHeaders = 32
	dumpMaxValue   = 256
)

// NewDumper opens the capture file. An empty path returns nil, which every
// method tolerates.
func NewDumper(path string, rate int) (*Dumper, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, err
	}
	if rate <= 0 {
		rate = 50
	}
	return &Dumper{file: file, rate: rate, now: time.Now}, nil
}

// Serve records every response that was not a success. 404 and 405 from the mux
// are included: a scanner's most interesting request is the one no route answers.
// It is called through the server rather than wrapped once, so the capture file
// can be attached after the mux is built.
func (d *Dumper) Serve(next http.Handler, w http.ResponseWriter, r *http.Request) {
	if d == nil {
		next.ServeHTTP(w, r)
		return
	}
	rec := &statusRecorder{ResponseWriter: w}
	next.ServeHTTP(rec, r)
	if rec.status == 0 {
		rec.status = http.StatusOK
	}
	if rec.status >= http.StatusBadRequest {
		d.Record(r, rec.status)
	}
}

type dumpRecord struct {
	At      string            `json:"at"`
	Remote  string            `json:"remote"`
	Method  string            `json:"method"`
	Host    string            `json:"host"`
	Path    string            `json:"path"`
	Query   string            `json:"query,omitempty"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
}

// Record writes one refused request, within the rate budget.
func (d *Dumper) Record(r *http.Request, status int) {
	if d == nil || d.file == nil || r == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	now := d.now()
	if now.Sub(d.window) >= time.Second {
		d.window = now
		d.used = 0
	}
	if d.used >= d.rate {
		d.drop++
		return
	}
	d.used++

	rec := dumpRecord{
		At:      now.UTC().Format(time.RFC3339Nano),
		Remote:  clip(r.RemoteAddr, dumpMaxValue),
		Method:  clip(r.Method, 16),
		Host:    clip(r.Host, dumpMaxValue),
		Path:    clip(r.URL.Path, dumpMaxValue),
		Query:   clip(r.URL.RawQuery, dumpMaxValue),
		Status:  status,
		Headers: dumpHeaders(r.Header),
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	if len(line) > dumpMaxLine {
		line = line[:dumpMaxLine-2]
		line = append(line, '}', '\n')
	} else {
		line = append(line, '\n')
	}
	_, _ = d.file.Write(line)

	// A drop counter, so a flood is visible rather than silently lost.
	if d.drop > 0 && now.Sub(d.window) >= time.Second {
		d.drop = 0
	}
}

// dumpHeaders keeps the headers a scan is made of and nothing that could be a
// credential: the front's own token must never be written to a capture file.
func dumpHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	n := 0
	for name, values := range h {
		if n >= dumpMaxHeaders {
			break
		}
		switch http.CanonicalHeaderKey(name) {
		case "Authorization", "Cookie", "Set-Cookie", "X-Api-Key":
			continue
		}
		if len(values) == 0 {
			continue
		}
		out[clip(name, 64)] = clip(values[0], dumpMaxValue)
		n++
	}
	return out
}

func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// Close flushes and closes the capture file.
func (d *Dumper) Close() error {
	if d == nil || d.file == nil {
		return nil
	}
	return d.file.Close()
}

// statusRecorder keeps the status a handler wrote so the dumper can decide
// whether the request was expected.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }
