// Package sillad is the Go port of the sillad dialer framework. It defines the
// Pipe interface (a bidirectional byte stream with metadata) and the Dialer
// interface (produces a Pipe), plus the combinators used by geph5-client's
// route-to-dialer compiler: race, fallback, timeout, delay.
//
// A Pipe is essentially a net.Conn with a protocol() label and an optional
// shared_secret() (used by the exit handshake to short-circuit X25519 when the
// transport already established a shared secret, e.g. sosistab3).
package sillad

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Pipe is a bidirectional byte stream. It mirrors sillad::Pipe: a net.Conn
// augmented with protocol/remote-addr/shared-secret metadata.
type Pipe interface {
	net.Conn
	// Protocol returns a short label like "tcp", "sosistab3", "meeklike".
	Protocol() string
	// RemoteAddrStr returns the remote address as a string, or "" if unknown.
	RemoteAddrStr() string
	// SharedSecret returns the transport-level shared secret (e.g. the
	// sosistab3 X25519 output), or nil if the transport has none. When present,
	// the exit handshake uses a shared-secret challenge instead of X25519.
	SharedSecret() []byte
}

// Dialer produces a Pipe.
type Dialer interface {
	Dial(ctx context.Context) (Pipe, error)
}

// FailingDialer always fails with the given error.
type FailingDialer struct{ Err error }

func (d FailingDialer) Dial(ctx context.Context) (Pipe, error) {
	if d.Err == nil {
		return nil, errors.New("sillad: failing dialer")
	}
	return nil, d.Err
}

// DynDialer wraps a Dialer function for dynamic dispatch (mirrors DynDialer).
type DynDialer struct {
	Func func(ctx context.Context) (Pipe, error)
}

func (d DynDialer) Dial(ctx context.Context) (Pipe, error) { return d.Func(ctx) }

// RaceDialer dials all inner dialers concurrently and returns the first
// successful Pipe, cancelling the rest. Mirrors sillad's DialerExt::race.
type RaceDialer struct {
	Inner []Dialer
}

func (d RaceDialer) Dial(ctx context.Context) (Pipe, error) {
	if len(d.Inner) == 0 {
		return nil, errors.New("sillad: race dialer has no inner dialers")
	}
	type result struct {
		pipe Pipe
		err  error
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan result, len(d.Inner))
	for _, dialer := range d.Inner {
		go func(dl Dialer) {
			pipe, err := dl.Dial(ctx)
			results <- result{pipe, err}
		}(dialer)
	}
	var firstErr error
	for i := 0; i < len(d.Inner); i++ {
		r := <-results
		if r.err == nil {
			cancel() // cancel remaining dials
			return r.pipe, nil
		}
		if firstErr == nil {
			firstErr = r.err
		}
	}
	if firstErr == nil {
		firstErr = errors.New("sillad: all race dialers failed")
	}
	return nil, fmt.Errorf("sillad: race dial failed: %w", firstErr)
}

// FallbackDialer dials inner dialers in order, returning the first success.
// Mirrors sillad's DialerExt::fallback.
type FallbackDialer struct {
	Inner []Dialer
}

func (d FallbackDialer) Dial(ctx context.Context) (Pipe, error) {
	if len(d.Inner) == 0 {
		return nil, errors.New("sillad: fallback dialer has no inner dialers")
	}
	var firstErr error
	for _, dialer := range d.Inner {
		pipe, err := dialer.Dial(ctx)
		if err == nil {
			return pipe, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, fmt.Errorf("sillad: fallback dial failed: %w", firstErr)
}

// TimeoutDialer wraps a dialer with an overall deadline.
type TimeoutDialer struct {
	Inner    Dialer
	Timeout  time.Duration
}

func (d TimeoutDialer) Dial(ctx context.Context) (Pipe, error) {
	ctx, cancel := context.WithTimeout(ctx, d.Timeout)
	defer cancel()
	return d.Inner.Dial(ctx)
}

// DelayDialer sleeps before dialing. Mirrors sillad's DialerExt::delay.
type DelayDialer struct {
	Inner   Dialer
	Delay   time.Duration
}

func (d DelayDialer) Dial(ctx context.Context) (Pipe, error) {
	select {
	case <-time.After(d.Delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return d.Inner.Dial(ctx)
}

// ConnPipe wraps a net.Conn to implement Pipe with the given protocol label.
type ConnPipe struct {
	net.Conn
	ProtocolStr  string
	RemoteStr    string
	SharedSecretBytes []byte
}

func (c *ConnPipe) Protocol() string { return c.ProtocolStr }
func (c *ConnPipe) RemoteAddrStr() string {
	if c.RemoteStr != "" {
		return c.RemoteStr
	}
	if c.Conn != nil {
		return c.Conn.RemoteAddr().String()
	}
	return ""
}
func (c *ConnPipe) SharedSecret() []byte { return c.SharedSecretBytes }

// Ensure ConnPipe satisfies Pipe.
var _ Pipe = (*ConnPipe)(nil)

// ClosePipe closes a pipe, tolerating nil.
func ClosePipe(p Pipe) {
	if p != nil {
		_ = p.Close()
	}
}

// CopyN copies up to n bytes from src to dst, returning the number copied.
// Used by the proxy loops.
func CopyN(dst io.Writer, src io.Reader, n int64) (int64, error) {
	return io.CopyN(dst, src, n)
}
