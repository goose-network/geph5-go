// Package picomux implements the picomux stream multiplexer, wire-compatible
// with the Rust picomux crate (v0.3.1).
//
// A picomux multiplexes many independent bidirectional streams over a single
// ordered, reliable byte stream (e.g. a TCP connection or a sosistab3 pipe).
// Each frame has an 8-byte header:
//
//   version:u8 | command:u8 | body_len:u16 LE | stream_id:u32 LE
//
// Commands:
//   SYN(0)  - open a new stream (body = metadata)
//   FIN(1)  - close the write direction of a stream
//   PSH(2)  - push data (body = payload)
//   NOP(3)  - no-op
//   MORE(4) - increase the peer's send window (body = u16 LE quantum)
//   PING(0xa0) - liveness probe (body = JSON PingInfo)
//   PONG(0xa1) - liveness response (empty body)
//
// Flow control: each direction has a send window (in frames). The receiver
// sends MORE frames to increase the peer's window. INIT_WINDOW=10, MAX_WINDOW=1500,
// MSS=8192. The receiver tracks remote_window (frames the peer may still send
// before getting a MORE) and tops it up to target_remote_window (MAX_WINDOW by
// default; debloat adjusts it based on bandwidth estimate).
//
// Liveness: a PING is sent every ping_interval; if no PONG arrives within
// `timeout`, the mux dies. The PING body is JSON {"next_ping_in_ms":N}.
package picomux

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Frame commands.
const (
	CmdSYN  uint8 = 0
	CmdFIN  uint8 = 1
	CmdPSH  uint8 = 2
	CmdNOP  uint8 = 3
	CmdMORE uint8 = 4
	CmdPING uint8 = 0xa0
	CmdPONG uint8 = 0xa1
)

// Header is 8 bytes, little-endian, #[repr(C)] in Rust.
type Header struct {
	Version  uint8
	Command  uint8
	BodyLen  uint16
	StreamID uint32
}

const headerSize = 8

const (
	initWindow  = 10
	maxWindow   = 1500
	mss         = 8192
	maxBodyLen  = 65535
)

// LivenessConfig configures ping/pong liveness.
type LivenessConfig struct {
	PingInterval time.Duration
	Timeout      time.Duration
}

// DefaultLiveness matches Rust's default: 1800s ping, 30s timeout.
func DefaultLiveness() LivenessConfig {
	return LivenessConfig{PingInterval: 1800 * time.Second, Timeout: 30 * time.Second}
}

// PingInfo is the JSON body of a PING frame.
type PingInfo struct {
	NextPingInMs uint32 `json:"next_ping_in_ms"`
}

// PicoMux multiplexes streams over a single connection.
type PicoMux struct {
	conn net.Conn

	mu       sync.Mutex
	streams  map[uint32]*streamState
	nextID   uint32
	alive    atomic.Bool
	deadErr  error
	deadCh   chan struct{}

	acceptCh chan *Stream

	// liveness
	liveness    LivenessConfig
	livenessMu  sync.Mutex
	lastLatency atomic.Int64 // nanoseconds, -1 = none

	// debloat records the SetDebloat flag (see SetDebloat). Currently unused
	// beyond storage; the BDP-based window adjustment is not implemented.
	debloat bool

	// pong signaling
	pongCh chan struct{}

	writeMu sync.Mutex
}

type streamState struct {
	id       uint32
	metadata []byte

	// inbound frames queue (PSH/FIN)
	recvCh   chan []byte
	recvEOF  atomic.Bool
	closed   atomic.Bool

	// leftover from a partially-consumed PSH payload
	recvMu      sync.Mutex
	leftover    []byte

	// send window (frames the remote allows us to send)
	sendWindow chan struct{} // semaphore; init initWindow, capped maxWindow
	sendWindowMu sync.Mutex
	sendWindowCap int

	// outbound write side
	writeCh chan []byte
	writeEOF atomic.Bool

	// signals
	finSent atomic.Bool
}

// pushLeftover stashes unconsumed bytes from a PSH payload for the next Read.
func (ss *streamState) pushLeftover(b []byte) {
	ss.recvMu.Lock()
	ss.leftover = append(ss.leftover, b...)
	ss.recvMu.Unlock()
}

// New wraps a connection (which must be a reliable ordered byte stream).
func New(conn net.Conn) *PicoMux {
	pm := &PicoMux{
		conn:     conn,
		streams:  make(map[uint32]*streamState),
		acceptCh: make(chan *Stream, 100),
		liveness: DefaultLiveness(),
		deadCh:   make(chan struct{}),
		pongCh:   make(chan struct{}, 1),
	}
	pm.alive.Store(true)
	go pm.readLoop()
	go pm.pingLoop()
	return pm
}

// SetLiveness updates the ping/pong configuration.
func (pm *PicoMux) SetLiveness(lc LivenessConfig) {
	pm.livenessMu.Lock()
	pm.liveness = lc
	pm.livenessMu.Unlock()
}

// debloat is the debloat flag. The Rust picomux SetDebloat(true) adjusts the
// receive-side target window based on a bandwidth estimate to avoid bloating
// the send buffer. This Go port does not implement the BDP-based window
// adjustment, so SetDebloat is a no-op that merely records the flag for
// interface compatibility with the session manager (which calls SetDebloat(true)).
func (pm *PicoMux) SetDebloat(on bool) {
	pm.livenessMu.Lock()
	pm.debloat = on
	pm.livenessMu.Unlock()
}

// IsAlive reports whether the mux is still alive.
func (pm *PicoMux) IsAlive() bool { return pm.alive.Load() }

// Close shuts down the mux: it marks it dead, closes all streams, and closes
// the underlying connection. It is idempotent. Mirrors Rust picomux::PicoMux's
// close(), which simply drops the inner Arc (closing the connection) and lets
// the read/ping loops observe the error.
func (pm *PicoMux) Close() error {
	pm.die(errors.New("picomux: closed"))
	return nil
}

// LastLatency returns the last measured ping latency, or -1 if none.
func (pm *PicoMux) LastLatency() time.Duration {
	v := pm.lastLatency.Load()
	if v < 0 {
		return -1
	}
	return time.Duration(v)
}

// WaitUntilDead blocks until the mux dies and returns the error.
func (pm *PicoMux) WaitUntilDead() error {
	<-pm.deadCh
	return pm.deadErr
}

func (pm *PicoMux) die(err error) {
	if pm.alive.CompareAndSwap(true, false) {
		pm.deadErr = err
		close(pm.deadCh)
		// Close all streams.
		pm.mu.Lock()
		for _, ss := range pm.streams {
			ss.closed.Store(true)
			close(ss.recvCh)
			close(ss.writeCh)
		}
		pm.streams = make(map[uint32]*streamState)
		pm.mu.Unlock()
		_ = pm.conn.Close()
	}
}

// Open opens a new stream to the peer with the given metadata.
func (pm *PicoMux) Open(metadata []byte) (*Stream, error) {
	if !pm.alive.Load() {
		return nil, errors.New("picomux: mux is dead")
	}
	pm.mu.Lock()
	// Pick a random stream ID not currently in use.
	var id uint32
	for {
		id = rand.Uint32()
		if _, ok := pm.streams[id]; !ok {
			break
		}
	}
	ss := pm.newStreamState(id, metadata)
	pm.streams[id] = ss
	pm.mu.Unlock()

	// Send SYN with metadata as body.
	synBody := make([]byte, len(metadata))
	copy(synBody, metadata)
	if err := pm.sendFrame(id, CmdSYN, synBody); err != nil {
		pm.mu.Lock()
		delete(pm.streams, id)
		pm.mu.Unlock()
		return nil, err
	}
	return &Stream{pm: pm, state: ss}, nil
}

// Accept waits for the peer to open a new stream.
func (pm *PicoMux) Accept() (*Stream, error) {
	select {
	case s, ok := <-pm.acceptCh:
		if !ok {
			return nil, errors.New("picomux: mux is dead")
		}
		return s, nil
	case <-pm.deadCh:
		return nil, pm.deadErr
	}
}

func (pm *PicoMux) newStreamState(id uint32, metadata []byte) *streamState {
	ss := &streamState{
		id:            id,
		metadata:      metadata,
		recvCh:        make(chan []byte, 256),
		writeCh:       make(chan []byte, 256),
		sendWindowCap: initWindow,
	}
	// sendWindow semaphore: initWindow permits.
	ss.sendWindow = make(chan struct{}, maxWindow)
	for i := 0; i < initWindow; i++ {
		ss.sendWindow <- struct{}{}
	}
	return ss
}

// sendFrame writes a single frame to the connection. Thread-safe.
func (pm *PicoMux) sendFrame(streamID uint32, command uint8, body []byte) error {
	if len(body) > maxBodyLen {
		return fmt.Errorf("picomux: body too large (%d)", len(body))
	}
	var hdr [headerSize]byte
	hdr[0] = 1 // version
	hdr[1] = command
	binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(body)))
	binary.LittleEndian.PutUint32(hdr[4:8], streamID)
	pm.writeMu.Lock()
	defer pm.writeMu.Unlock()
	if _, err := pm.conn.Write(hdr[:]); err != nil {
		return err
	}
	if len(body) > 0 {
		if _, err := pm.conn.Write(body); err != nil {
			return err
		}
	}
	return nil
}

// readFrame reads a single frame from the connection.
func (pm *PicoMux) readFrame() (Header, []byte, error) {
	var hdr [headerSize]byte
	if _, err := io.ReadFull(pm.conn, hdr[:]); err != nil {
		return Header{}, nil, err
	}
	h := Header{
		Version:  hdr[0],
		Command:  hdr[1],
		BodyLen:  binary.LittleEndian.Uint16(hdr[2:4]),
		StreamID: binary.LittleEndian.Uint32(hdr[4:8]),
	}
	var body []byte
	if h.BodyLen > 0 {
		body = make([]byte, h.BodyLen)
		if _, err := io.ReadFull(pm.conn, body); err != nil {
			return h, nil, err
		}
	}
	return h, body, nil
}

func (pm *PicoMux) readLoop() {
	for {
		h, body, err := pm.readFrame()
		if err != nil {
			pm.die(fmt.Errorf("picomux: read: %w", err))
			return
		}
		switch h.Command {
		case CmdSYN:
			pm.handleSYN(h.StreamID, body)
		case CmdMORE:
			pm.handleMORE(h.StreamID, body)
		case CmdPSH:
			pm.handlePSH(h.StreamID, body)
		case CmdFIN:
			pm.handleFIN(h.StreamID)
		case CmdNOP:
			// no-op
		case CmdPING:
			pm.handlePING(body)
		case CmdPONG:
			// Signal the ping loop.
			select {
			case pm.pongCh <- struct{}{}:
			default:
			}
		default:
			pm.die(fmt.Errorf("picomux: invalid command %d", h.Command))
			return
		}
	}
}

func (pm *PicoMux) handleSYN(id uint32, metadata []byte) {
	pm.mu.Lock()
	if _, exists := pm.streams[id]; exists {
		pm.mu.Unlock()
		pm.die(fmt.Errorf("picomux: duplicate SYN for stream %d", id))
		return
	}
	ss := pm.newStreamState(id, metadata)
	pm.streams[id] = ss
	pm.mu.Unlock()
	// Offer to accept loop. If queue is full, Rust warns and ignores; we drop
	// the SYN (non-blocking send) to avoid blocking the read loop.
	select {
	case pm.acceptCh <- &Stream{pm: pm, state: ss}:
	default:
		// Queue full; ignore SYN (matches Rust's "ignoring SYN" warn path).
		pm.mu.Lock()
		delete(pm.streams, id)
		pm.mu.Unlock()
	}
}

func (pm *PicoMux) handleMORE(id uint32, body []byte) {
	if len(body) < 2 {
		pm.die(errors.New("picomux: corrupt window increase message"))
		return
	}
	quantum := binary.LittleEndian.Uint16(body[:2])
	pm.mu.Lock()
	ss, ok := pm.streams[id]
	pm.mu.Unlock()
	if !ok {
		return
	}
	ss.sendWindowMu.Lock()
	for i := uint16(0); i < quantum; i++ {
		select {
		case ss.sendWindow <- struct{}{}:
			ss.sendWindowCap++
		default:
		}
	}
	ss.sendWindowMu.Unlock()
}

func (pm *PicoMux) handlePSH(id uint32, body []byte) {
	pm.mu.Lock()
	ss, ok := pm.streams[id]
	pm.mu.Unlock()
	if !ok {
		return
	}
	// Enqueue the payload (copy, since body is owned by read loop).
	payload := make([]byte, len(body))
	copy(payload, body)
	select {
	case ss.recvCh <- payload:
	default:
		// Backpressure: block until space. This preserves ordering.
		ss.recvCh <- payload
	}
	// Send MORE to replenish the peer's window (receive-side flow control).
	pm.maybeSendMORE(ss, len(payload))
}

func (pm *PicoMux) handleFIN(id uint32) {
	pm.mu.Lock()
	ss, ok := pm.streams[id]
	pm.mu.Unlock()
	if !ok {
		return
	}
	if !ss.recvEOF.Swap(true) {
		close(ss.recvCh)
	}
}

func (pm *PicoMux) handlePING(body []byte) {
	var info PingInfo
	_ = json.Unmarshal(body, &info) // best-effort; Rust errors on failure
	// Respond with an empty PONG on stream 0.
	_ = pm.sendFrame(0, CmdPONG, nil)
}

// maybeSendMORE sends a MORE frame to top up the peer's send window. The Rust
// receiver tracks remote_window (frames the peer has left) and tops it up to
// target_remote_window (MAX_WINDOW). We approximate by sending a MORE whenever
// the number of un-acked inbound frames drops below the target.
func (pm *PicoMux) maybeSendMORE(ss *streamState, justReceived int) {
	// Simplified flow control: after each PSH, send a MORE of 1 to keep the
	// peer's window topped up. This is conservative but correct (the peer never
	// stalls as long as MORE keeps arriving). The Rust impl sends larger quanta
	// based on a BDP estimate; for interop, the exact quantum does not need to
	// match — only that the peer's window is replenished before it hits 0.
	_ = pm.sendFrame(ss.id, CmdMORE, []byte{0x01, 0x00})
}

func (pm *PicoMux) pingLoop() {
	for {
		pm.livenessMu.Lock()
		lc := pm.liveness
		pm.livenessMu.Unlock()
		select {
		case <-time.After(lc.PingInterval):
		case <-pm.deadCh:
			return
		}
		if !pm.alive.Load() {
			return
		}
		body, _ := json.Marshal(PingInfo{NextPingInMs: uint32(lc.PingInterval / time.Millisecond)})
		if err := pm.sendFrame(0, CmdPING, body); err != nil {
			pm.die(err)
			return
		}
		start := time.Now()
		select {
		case <-pm.pongCh:
			pm.lastLatency.Store(int64(time.Since(start)))
		case <-time.After(lc.Timeout):
			pm.die(errors.New("picomux: ping-pong timed out"))
			return
		case <-pm.deadCh:
			return
		}
	}
}

// Stream is a single multiplexed bidirectional stream.
type Stream struct {
	pm    *PicoMux
	state *streamState
}

// Metadata returns the metadata supplied at open/accept.
func (s *Stream) Metadata() []byte { return s.state.metadata }

// Read reads decrypted stream data.
func (s *Stream) Read(b []byte) (int, error) {
	// First drain any leftover from a previously partially-consumed PSH.
	s.state.recvMu.Lock()
	if len(s.state.leftover) > 0 {
		n := copy(b, s.state.leftover)
		s.state.leftover = s.state.leftover[n:]
		s.state.recvMu.Unlock()
		return n, nil
	}
	s.state.recvMu.Unlock()
	if s.state.closed.Load() {
		return 0, io.EOF
	}
	payload, ok := <-s.state.recvCh
	if !ok {
		return 0, io.EOF
	}
	n := copy(b, payload)
	if n < len(payload) {
		s.state.pushLeftover(payload[n:])
	}
	return n, nil
}

// Write writes data to the stream (split into MSS-sized PSH frames).
func (s *Stream) Write(b []byte) (int, error) {
	if s.state.closed.Load() {
		return 0, errors.New("picomux: stream closed")
	}
	total := 0
	for len(b) > 0 {
		chunkLen := len(b)
		if chunkLen > mss {
			chunkLen = mss
		}
		chunk := b[:chunkLen]
		// Wait for a send-window permit (flow control).
		select {
		case <-s.state.sendWindow:
		case <-s.pm.deadCh:
			return total, errors.New("picomux: mux dead")
		}
		if err := s.pm.sendFrame(s.state.id, CmdPSH, chunk); err != nil {
			return total, err
		}
		total += chunkLen
		b = b[chunkLen:]
	}
	return total, nil
}

// Close closes the stream (sends FIN for the write direction).
func (s *Stream) Close() error {
	if s.state.closed.Swap(true) {
		return nil
	}
	_ = s.pm.sendFrame(s.state.id, CmdFIN, nil)
	s.pm.mu.Lock()
	delete(s.pm.streams, s.state.id)
	s.pm.mu.Unlock()
	return nil
}

func (s *Stream) LocalAddr() net.Addr  { return s.pm.conn.LocalAddr() }
func (s *Stream) RemoteAddr() net.Addr { return s.pm.conn.RemoteAddr() }
func (s *Stream) SetDeadline(t time.Time) error      { return s.pm.conn.SetDeadline(t) }
func (s *Stream) SetReadDeadline(t time.Time) error  { return s.pm.conn.SetReadDeadline(t) }
func (s *Stream) SetWriteDeadline(t time.Time) error { return s.pm.conn.SetWriteDeadline(t) }
