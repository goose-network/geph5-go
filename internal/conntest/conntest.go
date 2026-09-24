// Package conntest implements the sillad-conntest connection-quality test.
//
// Before handing a connection upstream, the client performs `pingCount` rounds:
// each round sends a 2-byte BE u16 payload size, then that many random bytes,
// then reads back the echo and compares. A final 2-byte [0x00,0x00] terminates
// the test. Wire-compatible with sillad_conntest::ConnTestDialer.
package conntest

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/geph-official/geph5-go/internal/sillad"
)

// Dialer wraps an inner Dialer with a connection-quality ping test.
type Dialer struct {
	Inner     sillad.Dialer
	PingCount int
}

func (d Dialer) Dial(ctx context.Context) (sillad.Pipe, error) {
	pipe, err := d.Inner.Dial(ctx)
	if err != nil {
		return nil, err
	}
	for i := 0; i < d.PingCount; i++ {
		// size in 1..=999, matching Rust random_range(1..1000u16)
		nBig, err := rand.Int(rand.Reader, big.NewInt(999))
		if err != nil {
			pipe.Close()
			return nil, fmt.Errorf("conntest: rand: %w", err)
		}
		size := uint16(nBig.Int64()) + 1
		var sizeBuf [2]byte
		binary.BigEndian.PutUint16(sizeBuf[:], size)
		if _, err := pipe.Write(sizeBuf[:]); err != nil {
			pipe.Close()
			return nil, fmt.Errorf("conntest: write size: %w", err)
		}
		payload := make([]byte, size)
		if _, err := rand.Read(payload); err != nil {
			pipe.Close()
			return nil, fmt.Errorf("conntest: rand payload: %w", err)
		}
		if _, err := pipe.Write(payload); err != nil {
			pipe.Close()
			return nil, fmt.Errorf("conntest: write payload: %w", err)
		}
		echo := make([]byte, size)
		if _, err := io.ReadFull(pipe, echo); err != nil {
			pipe.Close()
			return nil, fmt.Errorf("conntest: read echo: %w", err)
		}
		for j := range payload {
			if payload[j] != echo[j] {
				pipe.Close()
				return nil, fmt.Errorf("conntest: ping returned incorrect data")
			}
		}
	}
	// Termination message: 0 length.
	if _, err := pipe.Write([]byte{0x00, 0x00}); err != nil {
		pipe.Close()
		return nil, fmt.Errorf("conntest: write termination: %w", err)
	}
	return pipe, nil
}
