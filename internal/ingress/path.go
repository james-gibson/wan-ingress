package ingress

import (
	"errors"
	"fmt"
	"net"
	"strings"
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

// ParsePath reads a comma-separated path. An empty value is no path.
func ParsePath(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > maxPathHops {
		return nil, fmt.Errorf("path carries %d hops, limit %d", len(parts), maxPathHops)
	}
	hops := make([]string, 0, len(parts))
	for _, part := range parts {
		hop := strings.TrimSpace(part)
		if hop == "" || len(hop) > 64 || strings.ContainsAny(hop, "\t\n\r") {
			return nil, fmt.Errorf("malformed hop %q", part)
		}
		hops = append(hops, hop)
	}
	return hops, nil
}

// AppendHop adds this node to the path, refusing a route that already contains
// it. A node that has already seen a request must not see it again: that is a
// loop, and a loop is refused by construction rather than bounded by a timeout.
func AppendHop(path []string, node string) ([]string, error) {
	if node == "" {
		return path, nil
	}
	for _, hop := range path {
		if hop == node {
			return nil, ErrPathLoop
		}
	}
	if len(path)+1 > maxPathHops {
		return nil, fmt.Errorf("path would carry %d hops, limit %d", len(path)+1, maxPathHops)
	}
	return append(append([]string(nil), path...), node), nil
}

// FormatPath renders a path for the envelope.
func FormatPath(path []string) string { return strings.Join(path, ",") }

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
