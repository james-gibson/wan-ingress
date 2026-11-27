package ingress

import "sort"

// ShapeSet enforces a per-class concurrency budget. The class is chosen by body
// size before the body is read, so a bulk request cannot occupy one of the slots
// reserved for small ones — and a request that would exceed its class is refused
// rather than queued, because queuing a body is exactly the memory a shape budget
// exists to bound.
type ShapeSet struct {
	limits []ShapeLimit // ascending by MaxBytes
	sem    map[string]chan struct{}
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
	set := &ShapeSet{limits: ordered, sem: make(map[string]chan struct{}, len(ordered))}
	for _, l := range ordered {
		set.sem[l.Class] = make(chan struct{}, l.MaxConns)
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

// Acquire takes a slot in the body's class without blocking. A false return means
// the class is full and the caller should refuse with a retryable status.
func (s *ShapeSet) Acquire(bodyLen int64) (release func(), class string, ok bool) {
	if s == nil {
		return func() {}, "unshaped", true
	}
	limit := s.Classify(bodyLen)
	sem := s.sem[limit.Class]
	if sem == nil {
		return func() {}, limit.Class, true
	}
	select {
	case sem <- struct{}{}:
		return func() { <-sem }, limit.Class, true
	default:
		return nil, limit.Class, false
	}
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
