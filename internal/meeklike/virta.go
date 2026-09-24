// This file ports the virta 0.1.2 reliable-stream state machine
// (libraries/virta/src/{lib.rs,stream_state.rs,reorderer.rs,inflight/}) to Go.
//
// virta provides a reliable, ordered byte stream over an unreliable datagram
// layer. The state machine (StreamState) is driven by a "tick" loop: each tick
// processes incoming messages, sends outgoing messages via a callback, and
// returns the next time it should be ticked. A user-facing Stream facade
// exposes AsyncRead/AsyncWrite over shared queues.
//
// In Go we adapt this to a blocking net.Conn model: a Stream exposes Read/Write
// backed by byte queues, and a background ticker goroutine drives the
// StreamState, ferrying outgoing StreamMessages to and incoming StreamMessages
// from a datagram connection.
package meeklike

import (
	"sync"
	"time"

	"github.com/geph-official/geph5-go/internal/stdcode"
)

// RelKind mirrors virta::RelKind: the control flag on a Reliable StreamMessage.
type RelKind uint8

const (
	RelSyn     RelKind = 0
	RelSynAck  RelKind = 1
	RelData    RelKind = 2
	RelDataAck RelKind = 3
	RelFin     RelKind = 4
	RelFinAck  RelKind = 5
	RelRst     RelKind = 6
)

// StreamMessage mirrors virta::StreamMessage. It is stdcode-serialized on the
// wire as an externally-tagged enum:
//
//	Reliable { kind: RelKind, seqno: u64, payload: Bytes }  => variant 0
//	Empty                                                    => variant 1
//
// RelKind itself serializes as a u8 (serde enum with explicit repr(u8)-style
// indices: Syn=0, SynAck=1, Data=2, DataAck=3, Fin=4, FinAck=5, Rst=6).
type StreamMessage struct {
	Kind    RelKind
	Seqno   uint64
	Payload []byte
	Empty   bool // true for the Empty variant
}

// MarshalStdcode encodes a StreamMessage with external enum tagging.
func (m *StreamMessage) MarshalStdcode() ([]byte, error) {
	enc := stdcode.NewEncoder()
	if m.Empty {
		enc.EncodeU32(1) // Empty variant
		return enc.Bytes(), nil
	}
	enc.EncodeU32(0) // Reliable variant
	// RelKind is a serde enum: bincode encodes it as a u32 variant index
	// (varint). For the small indices 0..=6 this is a single byte, identical
	// to a u8, but we use EncodeU32 to match bincode's enum encoding exactly.
	enc.EncodeU32(uint32(m.Kind))
	enc.EncodeU64(m.Seqno)
	enc.EncodeBytes(m.Payload)
	return enc.Bytes(), nil
}

// UnmarshalStdcode decodes a StreamMessage.
func (m *StreamMessage) UnmarshalStdcode(b []byte) error {
	dec := stdcode.NewDecoder(b)
	variant, err := dec.DecodeU32()
	if err != nil {
		return err
	}
	switch variant {
	case 0:
		k, err := dec.DecodeU32()
		if err != nil {
			return err
		}
		seq, err := dec.DecodeU64()
		if err != nil {
			return err
		}
		payload, err := dec.DecodeBytes()
		if err != nil {
			return err
		}
		if dec.Remaining() != 0 {
			return errTrailing
		}
		m.Kind = RelKind(k)
		m.Seqno = seq
		m.Payload = payload
		m.Empty = false
		return nil
	case 1:
		if dec.Remaining() != 0 {
			return errTrailing
		}
		m.Empty = true
		return nil
	default:
		return errBadVariant
	}
}

var errTrailing = errString("virta: trailing bytes in StreamMessage")
var errBadVariant = errString("virta: unknown StreamMessage variant")

type errString string

func (e errString) Error() string { return string(e) }

// reorderer mirrors virta::reorderer::Reorderer<Bytes>. It buffers out-of-order
// packets by seqno and yields them in order via take().
type reorderer struct {
	pkts map[uint64][]byte
	min  uint64
}

func newReorderer() *reorderer { return &reorderer{pkts: make(map[uint64][]byte)} }

// insert adds an item at seq. Returns true iff the item is accepted (seq within
// the acceptance window) or has been accepted in the past (seq < min).
func (r *reorderer) insert(seq uint64, item []byte) bool {
	if seq >= r.min && seq <= r.min+20000 {
		r.pkts[seq] = item
		return true
	}
	// if less than min, we still "accept" (already seen).
	return seq < r.min
}

// take drains all contiguous packets starting at min, advancing min.
func (r *reorderer) take() []reorderedPkt {
	var out []reorderedPkt
	for {
		item, ok := r.pkts[r.min]
		if !ok {
			break
		}
		out = append(out, reorderedPkt{seq: r.min, data: item})
		delete(r.pkts, r.min)
		r.min++
	}
	return out
}

type reorderedPkt struct {
	seq  uint64
	data []byte
}

// inflightEntry tracks a single in-flight (sent, unacked) packet.
type inflightEntry struct {
	payload    StreamMessage
	sendTime   time.Time
	retrans    int
	retransTime time.Time
}

// inflight mirrors virta::inflight::Inflight. It tracks unacked packets and
// their retransmission timeouts, plus a simple RTT estimator.
type inflight struct {
	segments map[uint64]*inflightEntry
	// rtos is a sorted-by-time structure; we use a slice of (time, seqno) kept
	// sorted on insert. For the small windows here this is sufficient.
	rtos []rtoEntry

	estimatedRTT time.Duration
	devRTT       time.Duration
	minRTT       time.Duration
	minRTTTime   time.Time
	rttTime      time.Time
}

type rtoEntry struct {
	t time.Time
	s uint64
}

func newInflight() *inflight {
	now := time.Now()
	return &inflight{
		segments:     make(map[uint64]*inflightEntry),
		estimatedRTT: time.Second,
		minRTT:       time.Second,
		minRTTTime:   now,
		rttTime:      now,
	}
}

func (f *inflight) count() int { return len(f.segments) }

// lostAt returns the number of in-flight packets whose RTO has expired by now.
func (f *inflight) lostAt(now time.Time) int {
	n := 0
	for _, e := range f.rtos {
		if !e.t.After(now) {
			n++
		} else {
			break
		}
	}
	return n
}

// markAckedLt marks all packets with seqno < seq as acked. Returns the count
// newly acked.
func (f *inflight) markAckedLt(seq uint64) int {
	var toRemove []uint64
	for k := range f.segments {
		if k < seq {
			toRemove = append(toRemove, k)
		}
	}
	// sort toRemove ascending for deterministic behavior
	for i := 1; i < len(toRemove); i++ {
		for j := i; j > 0 && toRemove[j] < toRemove[j-1]; j-- {
			toRemove[j], toRemove[j-1] = toRemove[j-1], toRemove[j]
		}
	}
	sum := 0
	for _, s := range toRemove {
		if f.markAcked(s) {
			sum++
		}
	}
	return sum
}

// markAcked marks a single seqno as acked. Returns whether it was present.
func (f *inflight) markAcked(seq uint64) bool {
	e, ok := f.segments[seq]
	if !ok {
		return false
	}
	delete(f.segments, seq)
	now := time.Now()
	if e.retrans == 0 {
		f.recordSample(now.Sub(e.sendTime))
	}
	f.removeRTO(e.retransTime, seq)
	return true
}

// insert adds a new in-flight packet.
func (f *inflight) insert(msg StreamMessage) {
	seq := msg.Seqno
	now := time.Now()
	rto := f.rto()
	entry := &inflightEntry{
		payload:     msg,
		sendTime:    now,
		retrans:     0,
		retransTime: now.Add(rto),
	}
	f.segments[seq] = entry
	f.insertRTO(entry.retransTime, seq)
}

// firstRTO returns the (seqno, retransTime) of the earliest RTO, skipping
// already-lost packets (those whose time has passed are still returned as the
// earliest, matching the Rust semantics where lost_at counts them but
// first_rto returns the first entry).
func (f *inflight) firstRTO() (uint64, time.Time, bool) {
	if len(f.rtos) == 0 {
		return 0, time.Time{}, false
	}
	e := f.rtos[0]
	return e.s, e.t, true
}

// retransmit retransmits the given seqno: bumps its retrans count, schedules a
// new (backoff) RTO, and returns a clone of its payload.
func (f *inflight) retransmit(seq uint64) (StreamMessage, bool) {
	e, ok := f.segments[seq]
	if !ok {
		return StreamMessage{}, false
	}
	oldRetrans := e.retransTime
	e.retrans++
	shift := uint(e.retrans)
	if shift > 6 {
		shift = 6
	}
	backoff := float64(int64(1) << shift)
	if backoff > 60 {
		backoff = 60
	}
	rto := f.rto()
	e.retransTime = time.Now().Add(time.Duration(float64(rto) * backoff))
	f.removeRTO(oldRetrans, seq)
	f.insertRTO(e.retransTime, seq)
	return e.payload, true
}

func (f *inflight) insertRTO(t time.Time, seq uint64) {
	entry := rtoEntry{t: t, s: seq}
	// keep rtos sorted by time
	i := 0
	for i < len(f.rtos) && !f.rtos[i].t.After(t) {
		i++
	}
	f.rtos = append(f.rtos, rtoEntry{})
	copy(f.rtos[i+1:], f.rtos[i:])
	f.rtos[i] = entry
}

func (f *inflight) removeRTO(t time.Time, seq uint64) {
	for i, e := range f.rtos {
		if e.t.Equal(t) && e.s == seq {
			f.rtos = append(f.rtos[:i], f.rtos[i+1:]...)
			return
		}
	}
}

func (f *inflight) recordSample(sample time.Duration) {
	const alpha = 0.125
	const beta = 0.25
	now := time.Now()
	if sample < f.minRTT || now.Sub(f.minRTTTime) > 30*time.Second {
		f.minRTT = sample
		f.minRTTTime = now
	}
	if now.Sub(f.rttTime) > f.estimatedRTT {
		f.estimatedRTT = time.Duration((1-alpha)*float64(f.estimatedRTT) + alpha*float64(sample))
		dev := float64(sample) - float64(f.estimatedRTT)
		if dev < 0 {
			dev = -dev
		}
		f.devRTT = time.Duration((1-beta)*float64(f.devRTT) + beta*dev)
		f.rttTime = now
	}
}

func (f *inflight) rto() time.Duration {
	return f.estimatedRTT + time.Duration(4*float64(f.devRTT)) + 250*time.Millisecond
}

// streamPhase mirrors virta::stream_state::Phase.
type streamPhase int

const (
	phasePending streamPhase = iota
	phaseSynSent
	phaseEstablished
	phaseClosed
)

// streamState mirrors virta::stream_state::StreamState. It is NOT safe for
// concurrent use; the caller (the ticker) owns it and guards access with a
// mutex.
type streamState struct {
	mss int

	phase streamPhase
	// next_resend for phaseSynSent
	nextResend time.Time

	incomingQueue []StreamMessage
	queues        *streamQueues

	// read side
	nextUnseenSeqno uint64
	reorderer       *reorderer

	// write side
	inflight       *inflight
	nextWriteSeqno uint64
	cwnd           float64
	ssthresh       float64
	inRecovery     bool
	lastWriteTime  time.Time
}

// streamQueues is the shared byte-buffer bridge between the user-facing Stream
// and the StreamState, mirroring virta::StreamQueues.
type streamQueues struct {
	mu       sync.Mutex
	readBuf  []byte // bytes available for user Read
	writeBuf []byte // bytes queued by user Write
	connected bool
	closed   bool
	cond     *sync.Cond
}

func newStreamQueues() *streamQueues {
	q := &streamQueues{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *streamQueues) read(p []byte) (int, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.readBuf) == 0 && !q.closed {
		q.cond.Wait()
	}
	if len(q.readBuf) == 0 && q.closed {
		return 0, true // EOF
	}
	n := copy(p, q.readBuf)
	q.readBuf = q.readBuf[n:]
	return n, false
}

func (q *streamQueues) tryRead(p []byte) (int, bool, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.readBuf) == 0 {
		return 0, q.closed, false
	}
	n := copy(p, q.readBuf)
	q.readBuf = q.readBuf[n:]
	return n, false, true
}

func (q *streamQueues) write(p []byte) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return 0
	}
	// Backpressure: if write buffer exceeds 100KB, accept nothing (caller
	// will retry). This mirrors virta's poll_write readiness gate.
	if len(q.writeBuf) > 100_000 {
		return 0
	}
	q.writeBuf = append(q.writeBuf, p...)
	q.cond.Broadcast()
	return len(p)
}

func (q *streamQueues) writeBufLen() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.writeBuf)
}

func (q *streamQueues) readBufLen() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.readBuf)
}

func (q *streamQueues) setConnected() {
	q.mu.Lock()
	q.connected = true
	q.cond.Broadcast()
	q.mu.Unlock()
}

func (q *streamQueues) setClosed() {
	q.mu.Lock()
	q.closed = true
	q.cond.Broadcast()
	q.mu.Unlock()
}

func (q *streamQueues) isClosed() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.closed
}

func (q *streamQueues) isConnected() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.connected
}

func (q *streamQueues) appendRead(b []byte) {
	q.mu.Lock()
	q.readBuf = append(q.readBuf, b...)
	q.cond.Broadcast()
	q.mu.Unlock()
}

func (q *streamQueues) consumeWrite(max int) []byte {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.writeBuf) == 0 {
		return nil
	}
	n := len(q.writeBuf)
	if n > max {
		n = max
	}
	out := make([]byte, n)
	copy(out, q.writeBuf[:n])
	q.writeBuf = q.writeBuf[n:]
	return out
}

// newStreamStatePending creates a StreamState in the Pending phase (client
// side: will send SYN). Returns the state and a user-facing Stream.
func newStreamStatePending(mss int) (*streamState, *Stream) {
	return newStreamState(mss, phasePending)
}

// newStreamStateEstablished creates a StreamState in the Established phase
// (server side: a SYN was already received).
func newStreamStateEstablished(mss int) (*streamState, *Stream) {
	return newStreamState(mss, phaseEstablished)
}

func newStreamState(mss int, phase streamPhase) (*streamState, *Stream) {
	q := newStreamQueues()
	if phase == phaseEstablished {
		q.setConnected()
	}
	st := &streamState{
		mss:          mss,
		phase:        phase,
		queues:       q,
		reorderer:    newReorderer(),
		inflight:     newInflight(),
		cwnd:         4.0,
		ssthresh:     0.0,
		lastWriteTime: time.Now(),
	}
	return st, &Stream{queues: q}
}

// injectIncoming queues an incoming StreamMessage for processing on the next
// tick.
func (s *streamState) injectIncoming(msg StreamMessage) {
	s.incomingQueue = append(s.incomingQueue, msg)
}

// tick advances the state machine. outgoing is called for each StreamMessage
// that should be transmitted. Returns the next time to tick, or a zero time +
// false if the stream is finished and should be deleted.
func (s *streamState) tick(now time.Time, outgoing func(StreamMessage)) (time.Time, bool) {
	switch s.phase {
	case phasePending:
		outgoing(StreamMessage{Kind: RelSyn, Seqno: 0})
		next := now.Add(time.Second)
		s.phase = phaseSynSent
		s.nextResend = next
		return next, true
	case phaseSynSent:
		gotSynAck := false
		var kept []StreamMessage
		for _, msg := range s.incomingQueue {
			if msg.Kind == RelSynAck && !gotSynAck {
				gotSynAck = true
			} else {
				kept = append(kept, msg)
			}
		}
		s.incomingQueue = kept
		if gotSynAck {
			s.phase = phaseEstablished
			s.queues.setConnected()
			return now, true
		}
		if !now.Before(s.nextResend) {
			outgoing(StreamMessage{Kind: RelSyn, Seqno: 0})
			s.nextResend = now.Add(time.Second)
			return s.nextResend, true
		}
		return s.nextResend, true
	case phaseEstablished:
		s.tickRead(now, outgoing)
		s.tickWrite(now, outgoing)
		if s.queues.isClosed() {
			s.phase = phaseClosed
		}
		return s.retickTime(now), true
	case phaseClosed:
		s.queues.setClosed()
		// Drain incoming, sending RST for each (matches Rust).
		for range s.incomingQueue {
			outgoing(StreamMessage{Kind: RelRst, Seqno: 0})
		}
		s.incomingQueue = nil
		return time.Time{}, false
	}
	return time.Time{}, false
}

func (s *streamState) tickRead(now time.Time, outgoing func(StreamMessage)) {
	var toAck []uint64
	for _, packet := range s.incomingQueue {
		if s.queues.readBufLen() > 10_000_000 {
			continue
		}
		switch packet.Kind {
		case RelData:
			if s.reorderer.insert(packet.Seqno, packet.Payload) {
				toAck = append(toAck, packet.Seqno)
			}
		case RelDataAck:
			// packet.Seqno = lowest_unseen_seqno; payload = selective acks (Vec<u64> stdcode)
			ackCount := s.inflight.markAckedLt(packet.Seqno)
			if len(packet.Payload) > 0 {
				dec := stdcode.NewDecoder(packet.Payload)
				n, err := dec.DecodeSeqLen()
				if err == nil {
					for i := 0; i < n; i++ {
						sack, err := dec.DecodeU64()
						if err != nil {
							break
						}
						if s.inflight.markAcked(sack) {
							ackCount++
						}
					}
				}
			}
			// BIC congestion-window growth.
			for i := 0; i < ackCount; i++ {
				var bicInc float64
				if s.cwnd < s.ssthresh {
					bicInc = (s.ssthresh - s.cwnd) / 2.0
				} else {
					bicInc = s.cwnd - s.ssthresh
				}
				if bicInc < 1.0 {
					bicInc = 1.0
				} else if bicInc > 50.0 {
					bicInc = 50.0
				}
				if bicInc > s.cwnd {
					bicInc = s.cwnd
				}
				s.cwnd += bicInc / s.cwnd
			}
		case RelSyn:
			// retransmit our syn-ack
			outgoing(StreamMessage{Kind: RelSynAck, Seqno: packet.Seqno, Payload: packet.Payload})
		case RelRst, RelFin:
			s.phase = phaseClosed
		}
	}
	s.incomingQueue = nil

	// Drain the reorderer into the read buffer.
	for _, pkt := range s.reorderer.take() {
		s.nextUnseenSeqno = pkt.seq + 1
		s.queues.appendRead(pkt.data)
	}

	// Generate an ack for newly-accepted data packets.
	if len(toAck) > 0 {
		kept := toAck[:0]
		for _, a := range toAck {
			if a >= s.nextUnseenSeqno {
				kept = append(kept, a)
			}
		}
		toAck = kept
		if len(toAck) > 0 {
			// Encode selective acks as Vec<u64> stdcode.
			enc := stdcode.NewEncoder()
			enc.EncodeSeqLen(len(toAck))
			for _, a := range toAck {
				enc.EncodeU64(a)
			}
			outgoing(StreamMessage{Kind: RelDataAck, Seqno: s.nextUnseenSeqno, Payload: enc.Bytes()})
		}
	}
}

func (s *streamState) startRecovery() {
	if !s.inRecovery {
		const beta = 0.15
		if s.cwnd < s.ssthresh {
			s.ssthresh = s.cwnd * (2.0 - beta) / 2.0
		} else {
			s.ssthresh = s.cwnd
		}
		s.cwnd *= 1.0 - beta
		if s.cwnd < 1.0 {
			s.cwnd = 1.0
		}
		s.inRecovery = true
	}
}

func (s *streamState) stopRecovery() { s.inRecovery = false }

func (s *streamState) congested(now time.Time) bool {
	return s.inflight.count()-s.inflight.lostAt(now) >= int(s.cwnd)
}

func (s *streamState) speed() float64 {
	minRtt := s.inflight.minRTT
	if minRtt <= 0 {
		minRtt = 1
	}
	v := s.cwnd / minRtt.Seconds()
	if v < 1.0 {
		v = 1.0
	}
	return v
}

func (s *streamState) tickWrite(now time.Time, outgoing func(StreamMessage)) {
	if s.inflight.lostAt(now) > 0 {
		s.startRecovery()
	} else {
		s.stopRecovery()
	}

	speed := s.speed()
	writesAllowed := int(now.Sub(s.lastWriteTime).Seconds() * speed)
	if writesAllowed < 0 {
		writesAllowed = 0
	}

	for !s.congested(now) && writesAllowed > 0 {
		// Retransmit if the earliest RTO has expired.
		if seq, rtoTime, ok := s.inflight.firstRTO(); ok {
			if !now.Before(rtoTime) {
				msg, ok := s.inflight.retransmit(seq)
				if ok {
					writesAllowed--
					outgoing(msg)
					continue
				}
			}
		}
		// Otherwise send new data from the write buffer.
		chunk := s.queues.consumeWrite(s.mss)
		if len(chunk) > 0 {
			seqno := s.nextWriteSeqno
			s.nextWriteSeqno++
			msg := StreamMessage{Kind: RelData, Seqno: seqno, Payload: chunk}
			s.inflight.insert(msg)
			s.lastWriteTime = now
			writesAllowed--
			outgoing(msg)
			continue
		}
		break
	}
}

func (s *streamState) retickTime(now time.Time) time.Time {
	idle := s.inflight.count() == 0 && s.queues.writeBufLen() == 0
	if idle {
		return now.Add(100000 * time.Second)
	}
	return now.Add(time.Duration(float64(time.Second) / s.speed()))
}

// Stream is the user-facing reliable stream, implementing net.Conn-style
// blocking Read/Write over the shared streamQueues. It mirrors virta::Stream.
type Stream struct {
	queues *streamQueues
}

// Read blocks until bytes are available (or the stream is closed), then copies
// up to len(p) bytes into p.
func (s *Stream) Read(p []byte) (int, error) {
	n, eof := s.queues.read(p)
	if eof && n == 0 {
		return 0, errEOF
	}
	return n, nil
}

// Write queues p for transmission. Returns the number of bytes accepted (0 if
// the write buffer is full and the caller should retry).
func (s *Stream) Write(p []byte) (int, error) {
	if s.queues.isClosed() {
		return 0, errClosed
	}
	n := s.queues.write(p)
	if n == 0 {
		return 0, errWouldBlock
	}
	return n, nil
}

// Close marks the stream closed. Future reads return EOF and writes return an
// error.
func (s *Stream) Close() error {
	s.queues.setClosed()
	return nil
}

var (
	errEOF        = errString("virta: stream closed")
	errClosed     = errString("virta: stream closed")
	errWouldBlock = errString("virta: write buffer full")
)
