package ingress

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// BanLog turns repeated refusals from one address into a line a fail2ban filter
// can read. It is deliberately not an in-process blocker: the front's job is to
// refuse and to say who, and the host's job is to decide what that means for the
// network. Keeping enforcement outside means a misconfigured threshold cannot
// lock an operator out of the thing that would let them fix it.
//
// `never` is the allowlist. The jump host belongs in it: the machine an operator
// reaches the lab through must not be bannable, or the ban removes the way to
// undo the ban.
type BanLog struct {
	path      string
	never     PeerSet
	threshold int
	window    time.Duration
	maxKeys   int

	mu     sync.Mutex
	counts map[string]*banCount
	now    func() time.Time
	file   *os.File
	err    error
}

type banCount struct {
	n     int
	first time.Time
}

// NewBanLog opens the ban log. A nil result means "no ban log configured" and
// every method is a no-op. An empty path does the same.
func NewBanLog(path string, never PeerSet) *BanLog {
	if path == "" {
		return nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640) //nolint:gosec // operator-supplied path
	return &BanLog{
		path:      path,
		never:     never,
		threshold: 20,
		window:    time.Minute,
		maxKeys:   4096,
		counts:    make(map[string]*banCount),
		now:       time.Now,
		file:      file,
		err:       err,
	}
}

// Err reports the open error, if any. The caller logs it; a ban log that cannot
// be written must not take the front down.
func (b *BanLog) Err() error {
	if b == nil {
		return nil
	}
	return b.err
}

// Record counts one refusal from a remote address and writes a ban line when the
// threshold is crossed inside the window. The count is then cleared, so an
// address that stops misbehaving is not banned twice for one burst.
func (b *BanLog) Record(remoteAddr, reason string) {
	if b == nil || b.file == nil {
		return
	}
	ip := hostOf(remoteAddr)
	if ip == "" || b.never.Contains(remoteAddr) {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	entry := b.counts[ip]
	if entry == nil || now.Sub(entry.first) > b.window {
		entry = &banCount{first: now}
		b.counts[ip] = entry
	}
	entry.n++
	if entry.n < b.threshold {
		// Bound the map: an attacker who cycles source addresses must not grow
		// this front's memory. Dropping the counts costs accuracy, never safety.
		if len(b.counts) > b.maxKeys {
			b.counts = make(map[string]*banCount)
		}
		return
	}

	delete(b.counts, ip)
	_, _ = fmt.Fprintf(b.file, "%s wan-ingress ban ip=%s reason=%s count=%d\n",
		now.UTC().Format(time.RFC3339), ip, reason, entry.n)
}

// hostOf strips the port from a remote address.
func hostOf(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	if net.ParseIP(host) == nil {
		return ""
	}
	return host
}

// Close flushes and closes the log.
func (b *BanLog) Close() error {
	if b == nil || b.file == nil {
		return nil
	}
	return b.file.Close()
}
