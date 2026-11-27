package ingress

import (
	"net"
	"sync"
)

// LimitListener bounds the number of accepted connections. The excess waits in
// the kernel's accept queue rather than in this process, which is the point: the
// front's memory becomes a function of MaxConns, not of how fast a caller can
// open sockets.
//
// This is the local hard cap. A signed grant may raise the number of connections
// an ingress is *allowed* to admit (docs/placement.md), but the grant is clamped
// to this value, so no amount of standing lets a front exceed the footprint the
// host can survive.
type LimitListener struct {
	net.Listener
	sem chan struct{}
}

// NewLimitListener bounds a listener. max <= 0 leaves the listener unbounded.
func NewLimitListener(l net.Listener, limit int) net.Listener {
	if limit <= 0 {
		return l
	}
	return &LimitListener{Listener: l, sem: make(chan struct{}, limit)}
}

// Accept blocks until a connection slot is free, then accepts.
func (l *LimitListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
