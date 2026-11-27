package ingress

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

// A route is not re-authenticated per request: replaying a path within its span
// is the stability promise ("follow the cluster rules and the path holds"). What
// bounds it is age, not freshness. Each hop carries the instant the route began;
// a hop that cannot present a start within the span dissolves the route, and a
// node whose clock wobbles shifts that start and destroys the path for everyone
// downstream.
//
// The span is expressed in milliseconds rather than ticks so a link may run at
// any baud — 1 ms or 1 s — without the protocol assuming a cadence. A tick is a
// scheduling convenience; the grace budget is time.
const routeStartHeader = "X-Lab-Route-Start"

// ErrRouteDissolved is the typed refusal for a route whose grace has run out.
var ErrRouteDissolved = errors.New("route dissolved")

// DefaultRouteSpan is three grace ticks. A route that chains more grace than
// this has stopped being a stable path and become a stale one.
const DefaultRouteSpan = 15 * time.Second

// RouteStart resolves the start of the route from a carried header. A missing
// header starts a new route at now, which is what a caller or a first hop looks
// like.
func RouteStart(carried string, now time.Time, span time.Duration) (int64, error) {
	if carried == "" {
		return now.UnixMilli(), nil
	}
	startMS, err := strconv.ParseInt(carried, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: start %q is not milliseconds", ErrRouteDissolved, carried)
	}
	start := time.UnixMilli(startMS)
	// A start in the future is a wobbling clock, not a long route.
	if start.After(now) {
		return 0, fmt.Errorf("%w: start is in the future", ErrRouteDissolved)
	}
	if now.Sub(start) > span {
		return 0, fmt.Errorf("%w: started %s ago, span is %s", ErrRouteDissolved, now.Sub(start).Round(time.Millisecond), span)
	}
	return startMS, nil
}
