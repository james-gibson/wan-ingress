package ingress

import (
	"net"
	"testing"
	"time"
)

// The cap is on accepted connections, so the excess waits in the kernel rather
// than growing this process. A front's footprint is then a function of the cap.
func TestLimitListenerHoldsExcessInTheBacklog(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inner.Close() }()

	ln := NewLimitListener(inner, 1)
	defer func() { _ = ln.Close() }()

	// Two dials succeed at the TCP level — the kernel accepted the handshake.
	first, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	second, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()

	accepted, err := ln.Accept()
	if err != nil {
		t.Fatalf("first accept: %v", err)
	}

	// The second connection is in the queue; the listener must not hand it over
	// while the slot is held.
	done := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("a second connection was accepted past the cap")
	case <-time.After(150 * time.Millisecond):
	}

	// Releasing the slot admits the waiting connection.
	_ = accepted.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the waiting connection was not admitted after a release")
	}
}

func TestZeroMaxConnsLeavesTheListenerUnbounded(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inner.Close() }()
	if got := NewLimitListener(inner, 0); got != interface{}(inner) {
		t.Fatal("0 did not leave the listener unwrapped")
	}
	if got := NewLimitListener(inner, -1); got != interface{}(inner) {
		t.Fatal("a negative cap did not leave the listener unwrapped")
	}
}
