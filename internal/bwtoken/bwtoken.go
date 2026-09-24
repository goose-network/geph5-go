// Package bwtoken ports geph5-client's bandwidth-token refresh loop and
// accounting (binaries/geph5-client/src/bw_token.rs and bw_accounting.rs) to Go.
//
// Plus-tier clients must periodically consume bandwidth tokens to prove they
// are authorized to relay traffic. The refresh loop keeps at least 5 unblinded
// (ClientToken, SingleUnblindedSignature) pairs on hand, blinding fresh random
// tokens, asking the broker to blind-sign them (get_bw_token), and unblinding
// the result. The accounting loop reads 8-byte big-endian remote byte counts
// from the exit and, each time the cumulative count crosses a BW_TOKEN_BYTES
// (10_000_000) boundary, pops a token, stdcode-encodes the (token, sig) tuple,
// base64-no-pad-encodes it, and writes it followed by a newline back to the
// exit.
//
// Adaptation from the Rust SQL-backed design: the Rust code stores tokens in a
// SQLite table (bw_tokens). The Go database is a key/value store
// (internal/database), so tokens are persisted under keys "bw_token_<n>" with a
// monotonic counter and loaded into an in-memory queue at startup. The
// event_listener / ManualResetEvent signaling is replaced with channels and a
// sync.Cond: a "supplied" channel wakes consumers when a token is added, and a
// "consumed" channel wakes the refresh loop when one is removed.
package bwtoken

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/geph-official/geph5-go/internal/auth"
	"github.com/geph-official/geph5-go/internal/brokerproto"
	"github.com/geph-official/geph5-go/internal/config"
	"github.com/geph-official/geph5-go/internal/database"
	"github.com/geph-official/geph5-go/internal/mizaru2"
	"github.com/geph-official/geph5-go/internal/stdcode"
)

// BWTokenBytes is the number of bytes of relayed traffic that consumes one
// bandwidth token. Mirrors Rust BW_TOKEN_BYTES.
const BWTokenBytes uint64 = 10_000_000

// targetTokenCount is the minimum number of tokens to keep on hand (Rust: 5).
const targetTokenCount = 5

// tokenKeyPrefix is the KV key prefix under which token blobs are persisted.
const tokenKeyPrefix = "bw_token_"

// Handle is the write side of the accounting pair, mirroring Rust
// BwAccountingHandle. It is cloneable and used by the exit-facing accounting
// loop to notify the refresh loop that tokens are due.
type Handle struct {
	forceRefresh   chan struct{}
	accountedBytes atomic.Uint64
}

// Loop is the read side of the accounting pair, mirroring Rust
// BwAccountingLoop. It receives force-refresh signals from the Handle. It
// holds a *Handle (not a value) because Handle contains an atomic.Uint64,
// which must not be copied.
type Loop struct {
	handle       *Handle
	forceRefresh <-chan struct{}
}

// NewPair creates a (Handle, Loop) pair connected by an unbuffered signal
// channel, mirroring bw_accounting_pair (which uses an unbounded channel; we
// use a buffered-1 channel so non-blocking sends never drop a refresh due to a
// momentarily-blocked receiver). Returns pointers so the noCopy atomic inside
// Handle is never copied.
func NewPair() (*Handle, *Loop) {
	ch := make(chan struct{}, 1)
	h := &Handle{forceRefresh: ch}
	l := &Loop{handle: h, forceRefresh: ch}
	return h, l
}

// NotifyBwAccounting records that `consumed` bytes were relayed and, if the
// cumulative count crosses a BWTokenBytes boundary, signals the refresh loop
// (one signal per token due). Mirrors notify_bw_accounting. No-op when the
// client is not Plus.
func (h *Handle) NotifyBwAccounting(consumed int, isPlus bool) {
	if !isPlus {
		return
	}
	old := h.accountedBytes.Add(uint64(consumed))
	newBytes := old + uint64(consumed)
	tokensDue := newBytes/BWTokenBytes - old/BWTokenBytes
	for i := uint64(0); i < tokensDue; i++ {
		select {
		case h.forceRefresh <- struct{}{}:
		default:
			// Channel full: a refresh is already pending, no need to queue more.
		}
	}
}

// ForceRefresh returns the receive side of the refresh signal, for the
// accounting client loop to wait on.
func (l *Loop) ForceRefresh() <-chan struct{} { return l.forceRefresh }

// Handle returns the handle side (used to read accounted bytes / notify).
func (l *Loop) Handle() *Handle { return l.handle }

// tokenStore is the in-memory queue of stdcode-encoded (ClientToken,
// SingleUnblindedSignature) blobs, backed by the KV database for persistence.
type tokenStore struct {
	db    *database.Database
	mu    sync.Mutex
	queue [][]byte // persisted blobs, front = next to consume
	// supplied is broadcast when a token is added (wakes consumers).
	supplied *sync.Cond
	// consumedCh signals the refresh loop that a token was consumed.
	consumedCh chan struct{}
}

func newTokenStore(ctx context.Context, db *database.Database) (*tokenStore, error) {
	s := &tokenStore{db: db, consumedCh: make(chan struct{}, 1)}
	s.supplied = sync.NewCond(&s.mu)
	// Load any persisted tokens back into the in-memory queue.
	if db != nil {
		keys, err := db.Keys(ctx)
		if err != nil {
			return nil, fmt.Errorf("bwtoken: list keys: %w", err)
		}
		// Sort keys by numeric suffix so the queue order is stable.
		var idxs []int
		idxByKey := make(map[string]int)
		for _, k := range keys {
			if strings.HasPrefix(k, tokenKeyPrefix) {
				n, err := strconv.Atoi(strings.TrimPrefix(k, tokenKeyPrefix))
				if err == nil {
					idxs = append(idxs, n)
					idxByKey[k] = n
				}
			}
		}
		// Simple insertion sort by index.
		for i := 1; i < len(idxs); i++ {
			for j := i; j > 0 && idxs[j] < idxs[j-1]; j-- {
				idxs[j], idxs[j-1] = idxs[j-1], idxs[j]
			}
		}
		for _, n := range idxs {
			blob, err := db.Read(ctx, tokenKeyPrefix+strconv.Itoa(n))
			if err == nil && len(blob) > 0 {
				s.queue = append(s.queue, blob)
			}
		}
	}
	return s, nil
}

// count returns the current number of stored tokens (caller must NOT hold mu).
func (s *tokenStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.queue)
}

// add appends a token blob to the queue, persists it, and broadcasts supplied.
func (s *tokenStore) add(ctx context.Context, blob []byte) {
	s.mu.Lock()
	s.queue = append(s.queue, blob)
	if s.db != nil {
		// Persist under a key derived from the queue length; collisions are
		// impossible because we hold the lock and keys are removed on consume.
		key := tokenKeyPrefix + strconv.Itoa(len(s.queue)-1)
		// Best-effort persist; a flush failure is logged but does not lose the
		// in-memory token.
		if err := s.db.Write(ctx, key, blob); err != nil {
			log.Printf("bwtoken: persist token failed: %v", err)
		}
	}
	s.supplied.Broadcast()
	s.mu.Unlock()
}

// pop removes and returns the front token blob, deletes it from the DB, and
// signals consumed. Returns nil if the queue is empty.
func (s *tokenStore) pop(ctx context.Context) []byte {
	s.mu.Lock()
	if len(s.queue) == 0 {
		s.mu.Unlock()
		return nil
	}
	blob := s.queue[0]
	s.queue = s.queue[1:]
	if s.db != nil {
		// Remove all persisted keys and re-persist the remaining queue under
		// fresh sequential keys, so the front is always index 0.
		keys, _ := s.db.Keys(ctx)
		for _, k := range keys {
			if strings.HasPrefix(k, tokenKeyPrefix) {
				_ = s.db.Remove(ctx, k)
			}
		}
		for i, b := range s.queue {
			_ = s.db.Write(ctx, tokenKeyPrefix+strconv.Itoa(i), b)
		}
	}
	s.mu.Unlock()
	// Signal consumed (non-blocking).
	select {
	case s.consumedCh <- struct{}{}:
	default:
	}
	return blob
}

// waitForSupplied registers a waiter for the next supplied broadcast. Returns a
// function to call to wait. The caller MUST hold no locks and MUST call the
// returned wait function.
func (s *tokenStore) waitForSupplied() func() {
	s.mu.Lock()
	// Capture the cond; we wait after re-checking the queue (double-check
	// pattern, mirroring Rust's listen -> consume_inner -> waiter.await).
	cond := s.supplied
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		cond.Wait()
		s.mu.Unlock()
	}
}

// RefreshLoop runs the bandwidth-token refresh loop, mirroring
// bw_token_refresh_loop. It blocks forever (pending) if no broker or broker
// keys are configured; otherwise it repeatedly calls refreshInner.
func RefreshLoop(ctx context.Context, cfg *config.Config, authMgr *auth.Manager, broker *brokerproto.BrokerClient, db *database.Database) error {
	store, err := newTokenStore(ctx, db)
	if err != nil {
		return err
	}
	if cfg == nil || cfg.Broker == nil || cfg.BrokerKeys == nil || cfg.BrokerKeys.MizaruBw == "" {
		log.Printf("bwtoken: no broker info, so cannot obtain tokens")
		<-ctx.Done()
		return ctx.Err()
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := refreshInner(ctx, cfg, authMgr, broker, store); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("bwtoken: refresh inner failed: %v", err)
		}
	}
}

// refreshInner mirrors bw_token_refresh_inner. If fewer than 5 tokens are
// stored, it spawns goroutines to blind+fetch+unblind+store the missing ones
// (with exponential backoff on failure). Otherwise it waits for a consume
// signal then sleeps 100ms.
func refreshInner(ctx context.Context, cfg *config.Config, authMgr *auth.Manager, broker *brokerproto.BrokerClient, store *tokenStore) error {
	der, err := hex.DecodeString(cfg.BrokerKeys.MizaruBw)
	if err != nil {
		return fmt.Errorf("bad hex in mizaru_bw: %w", err)
	}
	mizaruBW := mizaru2.SinglePublicKeyFromDER(der)

	count := store.count()
	missing := targetTokenCount - count
	if missing > 0 {
		log.Printf("bwtoken: fetching %d missing tokens from the broker", missing)
		var wg sync.WaitGroup
		for i := 0; i < missing; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				fetchOneToken(ctx, cfg, authMgr, broker, mizaruBW, store)
			}()
		}
		wg.Wait()
	} else {
		// Wait for a consume signal, then sleep 100ms (mirrors
		// BW_TOKEN_CONSUMED.wait().reset() + sleep 100ms).
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-store.consumedCh:
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil
}

// fetchOneToken blinds a fresh random token, asks the broker to blind-sign it,
// unblinds the signature, stdcode-encodes the (token, sig) tuple, and stores
// it. Retries with exponential backoff (1s, rand 1..2x, cap 120s) on failure.
func fetchOneToken(ctx context.Context, cfg *config.Config, authMgr *auth.Manager, broker *brokerproto.BrokerClient, mizaruBW *mizaru2.SinglePublicKey, store *tokenStore) {
	retrySecs := 1.0
	for {
		if ctx.Err() != nil {
			return
		}
		err := func() error {
			if broker == nil {
				return fmt.Errorf("no broker configured")
			}
			token := mizaru2.RandomToken()
			pub, err := mizaruBW.Inner()
			if err != nil {
				return fmt.Errorf("mizaru_bw.inner: %w", err)
			}
			blindedMsg, secret, err := token.Blind(pub)
			if err != nil {
				return fmt.Errorf("token.blind: %w", err)
			}
			// The blinded token is a byte array; serialize it as a JSON array
			// of ints (NOT base64, which is Go's default for []byte).
			blindTokenJSON, err := byteArrayJSON(blindedMsg)
			if err != nil {
				return fmt.Errorf("encode blind token: %w", err)
			}
			authToken, err := authMgr.GetAuthToken(ctx)
			if err != nil {
				return fmt.Errorf("get_auth_token: %w", err)
			}
			sigJSON, err := broker.GetBwToken(ctx, authToken, blindTokenJSON)
			if err != nil {
				return fmt.Errorf("get_bw_token: %w", err)
			}
			var blindedSig mizaru2.SingleBlindedSignature
			if err := json.Unmarshal(sigJSON, &blindedSig); err != nil {
				return fmt.Errorf("decode blinded sig: %w", err)
			}
			sig, err := blindedSig.Unblind(secret, token)
			if err != nil {
				return fmt.Errorf("lele.unblind: %w", err)
			}
			blob, err := encodeTokenSig(token, sig)
			if err != nil {
				return fmt.Errorf("encode token+sig: %w", err)
			}
			store.add(ctx, blob)
			return nil
		}()
		if err != nil {
			log.Printf("bwtoken: cannot obtain bw token (retry in %.1fs): %v", retrySecs, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(retrySecs * float64(time.Second))):
			}
			// retry_secs = rand(retry_secs..retry_secs*2).min(120)
			upper := retrySecs * 2
			if upper > retrySecs {
				retrySecs = retrySecs + rand.Float64()*(upper-retrySecs)
			}
			if retrySecs > 120 {
				retrySecs = 120
			}
		} else {
			return
		}
	}
}

// encodeTokenSig stdcode-encodes the (ClientToken, SingleUnblindedSignature)
// tuple, mirroring Rust (token, sig).stdcode(). The tuple is a 2-element
// sequence: the ClientToken (a [u8; 32] fixed array, encoded as 32 raw bytes)
// followed by the SingleUnblindedSignature (encoded via its own
// MarshalStdcode).
func encodeTokenSig(token mizaru2.ClientToken, sig *mizaru2.SingleUnblindedSignature) ([]byte, error) {
	enc := stdcode.NewEncoder()
	// ClientToken is [u8; 32]; stdcode encodes fixed arrays as raw bytes
	// (no length prefix). EncodeRaw appends the 32 bytes verbatim.
	enc.EncodeRaw(token[:])
	// SingleUnblindedSignature encodes itself via MarshalStdcode.
	sigBytes, err := sig.MarshalStdcode()
	if err != nil {
		return nil, err
	}
	enc.EncodeRaw(sigBytes)
	return enc.Bytes(), nil
}

// decodeTokenSig stdcode-decodes a (ClientToken, SingleUnblindedSignature)
// tuple blob back into its parts, mirroring Rust
// stdcode::deserialize::<(ClientToken, SingleUnblindedSignature)>.
func decodeTokenSig(blob []byte) (mizaru2.ClientToken, *mizaru2.SingleUnblindedSignature, error) {
	if len(blob) < 32 {
		return mizaru2.ClientToken{}, nil, fmt.Errorf("bwtoken: token blob too short (%d bytes)", len(blob))
	}
	var token mizaru2.ClientToken
	copy(token[:], blob[:32])
	sig := &mizaru2.SingleUnblindedSignature{}
	if err := sig.UnmarshalStdcode(blob[32:]); err != nil {
		return mizaru2.ClientToken{}, nil, fmt.Errorf("bwtoken: decode sig: %w", err)
	}
	return token, sig, nil
}

// Consume pops one stored token and returns it, blocking until one is
// available. Mirrors bw_token_consume: loop { consume_inner; if Some return;
// else listen; consume_inner; if Some return; else wait }.
func Consume(ctx context.Context, db *database.Database) (mizaru2.ClientToken, *mizaru2.SingleUnblindedSignature, error) {
	store, err := newTokenStore(ctx, db)
	if err != nil {
		return mizaru2.ClientToken{}, nil, err
	}
	for {
		if ctx.Err() != nil {
			return mizaru2.ClientToken{}, nil, ctx.Err()
		}
		if blob := store.pop(ctx); blob != nil {
			return decodeTokenSig(blob)
		}
		// Register a supplied waiter, then double-check (mirrors Rust's
		// listen -> consume_inner -> waiter.await pattern to avoid races).
		wait := store.waitForSupplied()
		if blob := store.pop(ctx); blob != nil {
			return decodeTokenSig(blob)
		}
		// Wait for the next supplied signal. We cannot observe ctx cancellation
		// while blocked on a sync.Cond, so we race the wait against ctx on a
		// goroutine that broadcasts on ctx.Done().
		waitDone := make(chan struct{})
		go func() {
			wait()
			close(waitDone)
		}()
		select {
		case <-ctx.Done():
			return mizaru2.ClientToken{}, nil, ctx.Err()
		case <-waitDone:
		}
	}
}

// AccountingClientLoop handles the exit-to-client bandwidth accounting
// protocol, mirroring bw_accounting_client_loop. It splits the stream into a
// reader and writer, races a read loop (8-byte BE remote byte counts; a zero
// count forces a refresh) against a write loop (on each refresh signal, if
// Plus, consume a token, base64-no-pad-encode stdcode(token, sig), write it +
// "\n"). Returns when either direction ends.
func AccountingClientLoop(ctx context.Context, isPlus func() bool, stream interface {
	io.Reader
	io.Writer
}, loop *Loop, consume func(context.Context) (mizaru2.ClientToken, *mizaru2.SingleUnblindedSignature, error)) error {
	log.Printf("bwtoken: starting bandwidth accounting")

	readErr := make(chan error, 1)
	writeErr := make(chan error, 1)

	// read_fut: loop read 8 bytes BE u64; if 0, force a refresh (blocking send).
	go func() {
		buf := make([]byte, 8)
		lastLog := time.Now().Add(-5 * time.Second)
		for {
			if _, err := io.ReadFull(stream, buf); err != nil {
				readErr <- err
				return
			}
			currentBytes := uint64(buf[7]) | uint64(buf[6])<<8 | uint64(buf[5])<<16 | uint64(buf[4])<<24 |
				uint64(buf[3])<<32 | uint64(buf[2])<<40 | uint64(buf[1])<<48 | uint64(buf[0])<<56
			if time.Since(lastLog) >= 5*time.Second {
				log.Printf("bwtoken: received remote bandwidth accounting update: %d bytes", currentBytes)
				lastLog = time.Now()
			}
			if currentBytes == 0 {
				log.Printf("bwtoken: remote bytes went to zero, FORCING a refresh")
				select {
				case loop.handle.forceRefresh <- struct{}{}:
				case <-ctx.Done():
					readErr <- ctx.Err()
					return
				}
			}
		}
	}()

	// write_fut: loop recv on force_refresh; if !isPlus skip; consume a token;
	// enc = base64-no-pad(stdcode(token, sig)); write enc + "\n".
	go func() {
		for {
			select {
			case <-ctx.Done():
				writeErr <- ctx.Err()
				return
			case <-loop.forceRefresh:
			}
			if !isPlus() {
				log.Printf("bwtoken: not plus, skipping bandwidth token send")
				continue
			}
			token, sig, err := consume(ctx)
			if err != nil {
				writeErr <- fmt.Errorf("bw_token_consume: %w", err)
				return
			}
			blob, err := encodeTokenSig(token, sig)
			if err != nil {
				writeErr <- fmt.Errorf("encode token+sig: %w", err)
				return
			}
			enc := base64.RawStdEncoding.EncodeToString(blob)
			if _, err := stream.Write([]byte(enc + "\n")); err != nil {
				writeErr <- fmt.Errorf("write token: %w", err)
				return
			}
			log.Printf("bwtoken: consuming a bandwidth token")
		}
	}()

	// Race: return the first error from either direction.
	select {
	case err := <-readErr:
		return err
	case err := <-writeErr:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// byteArrayJSON encodes a byte slice as a JSON array of integers (0..255),
// matching serde_json's serialization of a Vec<u8> / &[u8] in geph5. This is
// NOT base64 (which is Go's default for []byte).
func byteArrayJSON(b []byte) (json.RawMessage, error) {
	ints := make([]int, len(b))
	for i, v := range b {
		ints[i] = int(v)
	}
	return json.Marshal(ints)
}
