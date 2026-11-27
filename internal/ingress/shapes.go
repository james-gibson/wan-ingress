package ingress

import (
	"errors"
	"fmt"
	"sort"
)

// shapeHeader lets a caller declare its class. A declaration is a claim that can
// be scored: it must name a configured class and must cover the body it carries.
// Inferring from size alone cannot tell a heavy legitimate client from a hostile
// one, which is the drift this header closes.
const shapeHeader = "X-Lab-Shape"

// ErrShapeUnknown is a declaration naming no configured class.
var ErrShapeUnknown = errors.New("unknown shape class")

// ErrShapeMismatch is a declaration smaller than the body it carries — a caller
// asking for a larger budget than its traffic justifies.
var ErrShapeMismatch = errors.New("declared shape does not cover the body")

// ShapeSet enforces a per-class concurrency budget. The class is chosen by body
// size before the body is read, so a bulk request cannot occupy one of the slots
// reserved for small ones — and a request that would exceed its class is refused
// rather than queued, because queuing a body is exactly the memory a shape budget
// exists to bound.
type ShapeSet struct {
	limits  []ShapeLimit // ascending by MaxBytes
	byClass map[string]ShapeLimit
	sem     map[string]chan struct{}
}

// NewShapeSet builds the budgets from a grant. An empty list means no shape
// enforcement, which is the behavior of a front with no grant.
func NewShapeSet(limits []ShapeLimit) *ShapeSet {
	if len(limits) == 0 {
		return nil
	}
	ordered := append([]ShapeLimit(nil), limits...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].MaxBytes != ordered[j].MaxBytes {
			return ordered[i].MaxBytes < ordered[j].MaxBytes
		}
		return ordered[i].Class < ordered[j].Class
	})
	set := &ShapeSet{
		limits:  ordered,
		byClass: make(map[string]ShapeLimit, len(ordered)),
		sem:     make(map[string]chan struct{}, len(ordered)),
	}
	for _, l := range ordered {
		set.sem[l.Class] = make(chan struct{}, l.MaxConns)
		set.byClass[l.Class] = l
	}
	return set
}

// Classify returns the class a body of this length belongs to. A negative length
// (chunked, no Content-Length) and anything larger than the biggest class take
// the largest class, which carries the tightest budget.
func (s *ShapeSet) Classify(bodyLen int64) ShapeLimit {
	if s == nil || len(s.limits) == 0 {
		return ShapeLimit{Class: "unshaped"}
	}
	for _, l := range s.limits {
		if bodyLen >= 0 && bodyLen <= l.MaxBytes {
			return l
		}
	}
	return s.limits[len(s.limits)-1]
}

// Decide resolves the class for a request. A declared class must be configured
// and must cover the body; an undeclared request falls back to size.
func (s *ShapeSet) Decide(declared string, bodyLen int64) (ShapeLimit, error) {
	if s == nil {
		return ShapeLimit{Class: "unshaped"}, nil
	}
	if declared == "" {
		return s.Classify(bodyLen), nil
	}
	limit, ok := s.byClass[declared]
	if !ok {
		return ShapeLimit{}, fmt.Errorf("%w: %q", ErrShapeUnknown, declared)
	}
	if bodyLen >= 0 && limit.MaxBytes < bodyLen {
		return ShapeLimit{}, fmt.Errorf("%w: declared %q covers %d bytes, body is %d",
			ErrShapeMismatch, declared, limit.MaxBytes, bodyLen)
	}
	return limit, nil
}

// Take reserves a slot in the resolved class without blocking. A false return
// means the class is full and the caller should refuse with a retryable status.
func (s *ShapeSet) Take(limit ShapeLimit) (release func(), ok bool) {
	if s == nil {
		return func() {}, true
	}
	sem := s.sem[limit.Class]
	if sem == nil {
		return func() {}, true
	}
	select {
	case sem <- struct{}{}:
		return func() { <-sem }, true
	default:
		return nil, false
	}
}

// Acquire is the size-only form, kept for callers that do not declare.
func (s *ShapeSet) Acquire(bodyLen int64) (release func(), class string, ok bool) {
	limit, err := s.Decide("", bodyLen)
	if err != nil {
		return func() {}, limit.Class, false
	}
	release, ok = s.Take(limit)
	if !ok {
		return nil, limit.Class, false
	}
	return release, limit.Class, true
}

// Limits is a copy of the configured classes, for logging and for the status
// surface.
func (s *ShapeSet) Limits() []ShapeLimit {
	if s == nil {
		return nil
	}
	return append([]ShapeLimit(nil), s.limits...)
}

// InFlight reports the classes currently holding slots.
func (s *ShapeSet) InFlight() map[string]int {
	if s == nil {
		return nil
	}
	out := make(map[string]int, len(s.sem))
	for class, sem := range s.sem {
		out[class] = len(sem)
	}
	return out
}
