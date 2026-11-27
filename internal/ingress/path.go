package ingress

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// The path is the route's own history: the ingress nodes a request has already
// passed through. It is carried in the signed envelope so that a route cannot
// contain the node it is offered to — the structural form of loop rejection
// (lab/SPLASH.md *The proxy*; SLA.md §12 "path vector, not distance vector").
//
// A caller-supplied path is only believed when the caller is a configured peer.
// Otherwise any anonymous caller could name a node and have that node refuse a
// request it never saw — a supply of header-shaped denial of service.
const (
	pathHeader  = "X-Lab-Path"
	maxPathHops = 8
)

// ErrPathLoop is the typed refusal for a route that already contains this node.
var ErrPathLoop = errors.New("route contains this node")

// ErrClockDisagreement is the typed refusal for a hop whose stamp does not fit
// the window for its link. Two adjacent edges that cannot agree on "now" within
// their window have a wobble to settle; discovering it at the window rather than
// at the route span is the whole point of a tight edge window.
var ErrClockDisagreement = errors.New("hop timestamp outside the link window")

// DefaultPeerWindow is how far adjacent edges may disagree by default: far
// tighter than the route span, and still 5x the LAN round trip. The measured
// floor is ~1 ms; a deployment may go tighter at the cost of dissolving routes
// under load.
const DefaultPeerWindow = 100 * time.Millisecond

// ErrHopUnstamped is a hop from a peer that carries no stamp, so its age cannot
// be judged at all.
var ErrHopUnstamped = errors.New("hop carries no timestamp")

// Hop is one node on the path, with the instant it appended itself. The stamp is
// the hop's own clock, which is what a tight link window can disagree with.
type Hop struct {
	Name string
	At   int64 // UnixMilli; 0 when the peer did not stamp
}

// ParsePath reads a comma-separated path of name@millis items. An empty value is
// no path. A name without a stamp is accepted here and refused later, where the
// distinction between "no peer" and "a peer that cannot be judged" is known.
func ParsePath(raw string) ([]Hop, error) {
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > maxPathHops {
		return nil, fmt.Errorf("path carries %d hops, limit %d", len(parts), maxPathHops)
	}
	hops := make([]Hop, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" || len(item) > 80 || strings.ContainsAny(item, "\t\n\r") {
			return nil, fmt.Errorf("malformed hop %q", part)
		}
		name, atText, hasAt := strings.Cut(item, "@")
		if name == "" || len(name) > 64 {
			return nil, fmt.Errorf("malformed hop %q", part)
		}
		hop := Hop{Name: name}
		if hasAt {
			at, err := strconv.ParseInt(atText, 10, 64)
			if err != nil || at < 0 {
				return nil, fmt.Errorf("malformed hop stamp %q", part)
			}
			hop.At = at
		}
		hops = append(hops, hop)
	}
	return hops, nil
}

// AppendHop adds this node to the path, refusing a route that already contains
// it. A node that has already seen a request must not see it again: that is a
// loop, and a loop is refused by construction rather than bounded by a timeout.
func AppendHop(path []Hop, node string, at int64) ([]Hop, error) {
	if node == "" {
		return path, nil
	}
	for _, hop := range path {
		if hop.Name == node {
			return nil, ErrPathLoop
		}
	}
	if len(path)+1 > maxPathHops {
		return nil, fmt.Errorf("path would carry %d hops, limit %d", len(path)+1, maxPathHops)
	}
	return append(append([]Hop(nil), path...), Hop{Name: node, At: at}), nil
}

// CheckHopAges judges every stamped hop against the window for its link. A hop
// with no stamp from a peer cannot be judged, which is a disagreement rather
// than a pass: silence is not agreement.
func CheckHopAges(path []Hop, now time.Time, window time.Duration) error {
	if window <= 0 {
		return nil
	}
	for _, hop := range path {
		if hop.At == 0 {
			return fmt.Errorf("%w: %q", ErrHopUnstamped, hop.Name)
		}
		at := time.UnixMilli(hop.At)
		if at.After(now.Add(window)) {
			return fmt.Errorf("%w: %q is %s in the future", ErrClockDisagreement, hop.Name, at.Sub(now).Round(time.Millisecond))
		}
		if age := now.Sub(at); age > window {
			return fmt.Errorf("%w: %q is %s old, window is %s", ErrClockDisagreement, hop.Name, age.Round(time.Millisecond), window)
		}
	}
	return nil
}

// FormatPath renders a path for the envelope. The stamp travels with the name so
// the next hop can judge this one against its own link window.
func FormatPath(path []Hop) string {
	parts := make([]string, 0, len(path))
	for _, hop := range path {
		if hop.At == 0 {
			parts = append(parts, hop.Name)
			continue
		}
		parts = append(parts, fmt.Sprintf("%s@%d", hop.Name, hop.At))
	}
	return strings.Join(parts, ",")
}

// PeerSet is the set of addresses whose path claims are believed.
type PeerSet []*net.IPNet

// ParsePeers reads IP addresses or CIDR blocks. Anything unparseable is a loud
// startup error: a typo here must not silently narrow the trust set, and it
// must not silently widen it either.
func ParsePeers(values []string) (PeerSet, error) {
	var peers PeerSet
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.Contains(value, "/") {
			_, block, err := net.ParseCIDR(value)
			if err != nil {
				return nil, fmt.Errorf("peer %q: %w", value, err)
			}
			peers = append(peers, block)
			continue
		}
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, fmt.Errorf("peer %q is not an IP or CIDR", value)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		peers = append(peers, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return peers, nil
}

// Overlaps reports whether two sets share any address. CIDR blocks either
// nest or are disjoint, so checking each block's network address is exact.
func (p PeerSet) Overlaps(other PeerSet) bool {
	for _, a := range p {
		for _, b := range other {
			if a.Contains(b.IP) || b.Contains(a.IP) {
				return true
			}
		}
	}
	return false
}

// Contains reports whether a remote address belongs to a configured peer.
func (p PeerSet) Contains(remoteAddr string) bool {
	if len(p) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	for _, block := range p {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}
