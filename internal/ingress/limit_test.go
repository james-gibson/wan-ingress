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

// A renewed grant changes the ceiling live: raising it admits a connection the
// previous limit would have held.
func TestLimitListenerRaisesAndLowersLive(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inner.Close() }()

	ln := NewLimitListener(inner, 1)
	defer func() { _ = ln.Close() }()

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

	held, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan net.Conn, 1)
	go func() {
		c, acceptErr := ln.Accept()
		if acceptErr == nil {
			done <- c
		}
	}()
	select {
	case <-done:
		t.Fatal("accepted past the cap")
	case <-time.After(100 * time.Millisecond):
	}

	// The authority renews with more room.
	ln.SetLimit(2)
	select {
	case c := <-done:
		_ = c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("raising the limit did not admit the waiting connection")
	}

	// Shrinking again stops new accepts until the count falls back under it.
	ln.SetLimit(1)
	_ = held.Close()

	third, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = third.Close() }()
	admitted := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
			close(admitted)
		}
	}()
	select {
	case <-admitted:
	case <-time.After(2 * time.Second):
		t.Fatal("a legal connection was not admitted after the shrink")
	}
}

func TestZeroLimitIsUnbounded(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inner.Close() }()
	ln := NewLimitListener(inner, 0)
	defer func() { _ = ln.Close() }()
	if ln.Limit() != 0 {
		t.Fatalf("limit = %d, want 0 (unbounded)", ln.Limit())
	}
}
