package ingress

import (
	"net"
	"sync"
)

// LimitListener bounds the number of accepted connections. The excess waits in
// the kernel's accept queue rather than in this process, which is the point: the
// front's memory becomes a function of the limit, not of how fast a caller can
// open sockets.
//
// The limit is mutable so a renewed grant can raise or lower it without a
// restart — "go faster if authorized" is a live statement, not a config edit.
type LimitListener struct {
	net.Listener

	mu   sync.Mutex
	cond *sync.Cond
	cur  int
	max  int
}

// NewLimitListener bounds a listener. limit <= 0 means no local ceiling; a grant
// may still impose one through SetLimit.
func NewLimitListener(l net.Listener, limit int) *LimitListener {
	ll := &LimitListener{Listener: l, max: limit}
	ll.cond = sync.NewCond(&ll.mu)
	return ll
}

// SetLimit changes the ceiling for subsequent accepts. Conns already admitted are
// not dropped: shrinking the limit stops new accepts until releases bring the
// count back under it.
func (l *LimitListener) SetLimit(limit int) {
	l.mu.Lock()
	l.max = limit
	l.mu.Unlock()
	l.cond.Broadcast()
}

// Limit reports the current ceiling (0 = unbounded).
func (l *LimitListener) Limit() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.max
}

func (l *LimitListener) acquire() {
	l.mu.Lock()
	for l.max > 0 && l.cur >= l.max {
		l.cond.Wait()
	}
	l.cur++
	l.mu.Unlock()
}

func (l *LimitListener) release() {
	l.mu.Lock()
	if l.cur > 0 {
		l.cur--
	}
	l.mu.Unlock()
	l.cond.Broadcast()
}

// Accept blocks until a slot is free, then accepts.
func (l *LimitListener) Accept() (net.Conn, error) {
	l.acquire()
	c, err := l.Listener.Accept()
	if err != nil {
		l.release()
		return nil, err
	}
	return &limitConn{Conn: c, release: l.release}, nil
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
