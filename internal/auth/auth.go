// Package auth implements the geph5-client authentication loop, a port of
// binaries/geph5-client/src/auth.rs.
//
// It manages two kinds of tokens cached in the database:
//
//   - "auth_token": the broker-issued bearer token (a string) obtained once
//     from broker.get_auth_token(credential) and reused.
//   - "conn_token_{epoch}": a stdcode-encoded (AccountLevel, ClientToken,
//     UnblindedSignature) tuple, refreshed by auth_loop. The connect token
//     is what the exit handshake presents to prove the client is a paying
//     member (plus or free).
//
// auth_loop periodically (every 400..800s) refreshes the conn tokens for the
// current and next epoch by blind-signing a fresh ClientToken with the
// broker's mizaru2 subkeys, verifying the Merkle membership proof against the
// configured broker_keys, unblinding, and storing the result.
package auth

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/geph-official/geph5-go/internal/brokerproto"
	"github.com/geph-official/geph5-go/internal/config"
	"github.com/geph-official/geph5-go/internal/database"
	"github.com/geph-official/geph5-go/internal/mizaru2"
	"github.com/geph-official/geph5-go/internal/nanorpc"
	"github.com/geph-official/geph5-go/internal/stdcode"
)

// accountStatusWaitTimeout mirrors Rust ACCOUNT_STATUS_WAIT_TIMEOUT.
const accountStatusWaitTimeout = 10 * time.Second

// IS_PLUS is set by get_connect_token to reflect whether the current connect
// token is a Plus-level token. Mirrors Rust IS_PLUS.
var ISPlus atomic.Bool

// Manager owns the auth state for a single client: the broker client, the
// database, and the cached account-status event. It is safe for concurrent
// use.
type Manager struct {
	Broker *brokerproto.BrokerClient
	DB     *database.Database
	Cfg    *config.Config

	// accountStatusChecked is set once the first refresh_conn_token completes
	// (successfully or not), so get_connect_token knows whether to wait for a
	// fresh token or fall back to a cached one. Mirrors Rust
	// ACCOUNT_STATUS_CHECKED.
	accountStatusChecked chan struct{}
	accountStatusOnce    sync.Once

	// authTokenMu serializes get_auth_token to avoid redundant broker calls.
	authTokenMu sync.Mutex
}

// NewManager constructs a Manager. broker may be nil (in which case auth_loop
// blocks forever, matching Rust's `if ctx.init().broker.is_none() { pending }`).
func NewManager(cfg *config.Config, db *database.Database, broker *brokerproto.BrokerClient) *Manager {
	return &Manager{
		Broker:               broker,
		DB:                   db,
		Cfg:                  cfg,
		accountStatusChecked: make(chan struct{}),
	}
}

// markAccountStatusChecked closes the account-status channel once. Mirrors
// Rust ACCOUNT_STATUS_CHECKED.set().
func (m *Manager) markAccountStatusChecked() {
	m.accountStatusOnce.Do(func() { close(m.accountStatusChecked) })
}

// ConnectToken is the decoded (level, token, sig) tuple stored under
// "conn_token_{epoch}".
type ConnectToken struct {
	Level brokerproto.AccountLevel
	Token mizaru2.ClientToken
	Sig   mizaru2.UnblindedSignature
}

// marshalConnectToken stdcode-encodes (level, token, sig), matching Rust's
// &(level, token, u_sig).stdcode(). AccountLevel is an externally-tagged enum
// serialized as a u32 varint variant index (Free=0, Plus=1).
func marshalConnectToken(level brokerproto.AccountLevel, token mizaru2.ClientToken, sig *mizaru2.UnblindedSignature) ([]byte, error) {
	enc := stdcode.NewEncoder()
	switch level {
	case brokerproto.AccountLevelFree:
		enc.EncodeU32(0)
	case brokerproto.AccountLevelPlus:
		enc.EncodeU32(1)
	default:
		return nil, fmt.Errorf("auth: unknown account level %q", level)
	}
	enc.EncodeRaw(token.AsBytes()[:])
	if sig == nil {
		return nil, errors.New("auth: nil unblinded signature")
	}
	sigBytes, err := sig.MarshalStdcode()
	if err != nil {
		return nil, err
	}
	enc.EncodeRaw(sigBytes)
	return enc.Bytes(), nil
}

// MarshalStdcode stdcode-encodes the connect token as the (level, token, sig)
// tuple that the exit handshake presents as its credentials blob. It is the
// exported form of marshalConnectToken, used by the session manager.
func (c *ConnectToken) MarshalStdcode() ([]byte, error) {
	return marshalConnectToken(c.Level, c.Token, &c.Sig)
}

// unmarshalConnectToken reverses marshalConnectToken.
func unmarshalConnectToken(data []byte) (*ConnectToken, error) {
	dec := stdcode.NewDecoder(data)
	levelIdx, err := dec.DecodeU32()
	if err != nil {
		return nil, fmt.Errorf("auth: decode level: %w", err)
	}
	var level brokerproto.AccountLevel
	switch levelIdx {
	case 0:
		level = brokerproto.AccountLevelFree
	case 1:
		level = brokerproto.AccountLevelPlus
	default:
		return nil, fmt.Errorf("auth: unknown account level index %d", levelIdx)
	}
	tokenBytes, err := dec.DecodeFixedBytes(32)
	if err != nil {
		return nil, fmt.Errorf("auth: decode token: %w", err)
	}
	var token mizaru2.ClientToken
	copy(token[:], tokenBytes)
	var sig mizaru2.UnblindedSignature
	// The remainder of the buffer is the stdcode-encoded UnblindedSignature.
	rest := dec.RemainingBytes()
	if err := sig.UnmarshalStdcode(rest); err != nil {
		return nil, fmt.Errorf("auth: decode sig: %w", err)
	}
	return &ConnectToken{Level: level, Token: token, Sig: sig}, nil
}

// GetConnectToken returns the connect token for the current epoch, waiting up
// to accountStatusWaitTimeout for the first refresh to land. Mirrors Rust
// get_connect_token.
func (m *Manager) GetConnectToken(ctx context.Context) (*ConnectToken, error) {
	waitForToken := false
	select {
	case <-m.accountStatusChecked:
		waitForToken = true
	case <-time.After(accountStatusWaitTimeout):
		log.Printf("auth: ACCOUNT STATUS NOT READY; proceeding with cached connect token anyway")
		waitForToken = false
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	epoch := mizaru2.CurrentEpoch()
	ct, err := m.getConnTokenInner(ctx, epoch, waitForToken)
	if err != nil {
		return nil, err
	}
	ISPlus.Store(ct.Level == brokerproto.AccountLevelPlus)
	return ct, nil
}

func (m *Manager) getConnTokenInner(ctx context.Context, epoch uint16, wait bool) (*ConnectToken, error) {
	key := fmt.Sprintf("conn_token_%d", epoch)
	if !wait {
		raw, err := m.DB.Read(ctx, key)
		if err != nil {
			return nil, err
		}
		if raw == nil {
			return nil, errors.New("auth: conn token absent right now")
		}
		return unmarshalConnectToken(raw)
	}
	raw, err := m.DB.ReadOrWait(ctx, key)
	if err != nil {
		return nil, err
	}
	return unmarshalConnectToken(raw)
}

// GetAuthToken returns the cached broker auth token, fetching it from the
// broker on first use. Mirrors Rust get_auth_token.
func (m *Manager) GetAuthToken(ctx context.Context) (string, error) {
	m.authTokenMu.Lock()
	defer m.authTokenMu.Unlock()
	raw, err := m.DB.Read(ctx, "auth_token")
	if err != nil {
		return "", err
	}
	if raw != nil {
		return string(raw), nil
	}
	if m.Broker == nil {
		return "", errors.New("auth: no broker configured to fetch auth token")
	}
	log.Printf("auth: obtaining auth token from broker")
	credJSON, err := m.marshalCredential()
	if err != nil {
		return "", err
	}
	token, err := m.Broker.GetAuthToken(ctx, credJSON)
	if err != nil {
		return "", err
	}
	if err := m.DB.Write(ctx, "auth_token", []byte(token)); err != nil {
		return "", err
	}
	return token, nil
}

// marshalCredential encodes the configured Credential as the JSON the broker
// expects (the externally-tagged serde form). config.Credential implements
// json.Marshaler.
func (m *Manager) marshalCredential() (json.RawMessage, error) {
	if m.Cfg == nil {
		return nil, errors.New("auth: nil config")
	}
	return json.Marshal(m.Cfg.Credentials)
}

// AuthLoop runs the conn-token refresh loop until ctx is canceled. If no
// broker is configured, it blocks forever (matching Rust). Mirrors Rust
// auth_loop.
func (m *Manager) AuthLoop(ctx context.Context) error {
	if m.Broker == nil {
		<-ctx.Done()
		return ctx.Err()
	}
	authToken, err := m.GetAuthToken(ctx)
	if err != nil {
		return fmt.Errorf("auth: get auth token: %w", err)
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := m.refreshConnToken(ctx, authToken); err != nil {
			log.Printf("auth: failed to refresh conn token: %v", err)
			if err := sleepCtx(ctx, 10*time.Second); err != nil {
				return err
			}
		} else {
			sleepSecs := 400 + rand.Intn(400) // 400..800
			if err := sleepCtx(ctx, time.Duration(sleepSecs)*time.Second); err != nil {
				return err
			}
		}
	}
}

// refreshConnToken refreshes conn tokens for the current and next epoch.
// Mirrors Rust refresh_conn_token (with a 30s timeout).
func (m *Manager) refreshConnToken(ctx context.Context, authToken string) error {
	innerCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	epoch := mizaru2.CurrentEpoch()

	// get_user_info -> plus_expires_unix.
	info, err := m.Broker.GetUserInfo(innerCtx, authToken)
	if err != nil {
		return fmt.Errorf("get_user_info: %w", err)
	}
	if info == nil {
		return errors.New("auth: no such user")
	}
	var plusExpiry uint64
	if info.PlusExpiresUnix != nil {
		plusExpiry = *info.PlusExpiresUnix
	}
	now := uint64(time.Now().Unix())
	isPlus := plusExpiry > now
	ISPlus.Store(isPlus)
	log.Printf("auth: got latest plus expiry=%d (isPlus=%v)", plusExpiry, isPlus)

	// currently_plus: check the cached current-epoch token's level.
	currentlyPlus := false
	if ct, err := m.getConnTokenInner(innerCtx, epoch, false); err == nil {
		currentlyPlus = ct.Level == brokerproto.AccountLevelPlus
	}

	if (plusExpiry > 0 && !currentlyPlus) || (currentlyPlus && plusExpiry == 0) {
		log.Printf("auth: gained or lost plus; cleaning conn token cache")
		if err := m.DB.Remove(innerCtx, fmt.Sprintf("conn_token_%d", epoch)); err != nil {
			return err
		}
		if err := m.DB.Remove(innerCtx, fmt.Sprintf("conn_token_%d", epoch+1)); err != nil {
			return err
		}
	}

	m.markAccountStatusChecked()

	for _, e := range [2]uint16{epoch, epoch + 1} {
		key := fmt.Sprintf("conn_token_%d", e)
		existing, err := m.DB.Read(innerCtx, key)
		if err != nil {
			return err
		}
		if existing != nil {
			continue
		}
		if err := m.refreshEpoch(innerCtx, authToken, e); err != nil {
			return err
		}
	}
	return nil
}

// refreshEpoch blinds a fresh token, asks the broker to blind-sign it for
// each level (plus then free), verifies the Merkle proof, unblinds, and
// stores the result. Mirrors the inner loop of Rust refresh_conn_token.
func (m *Manager) refreshEpoch(ctx context.Context, authToken string, epoch uint16) error {
	token := mizaru2.RandomToken()
	for _, level := range [2]brokerproto.AccountLevel{brokerproto.AccountLevelPlus, brokerproto.AccountLevelFree} {
		log.Printf("auth: refreshing conn token epoch=%d level=%s", epoch, level)
		subkeyDER, err := m.Broker.GetMizaruSubkey(ctx, level, epoch)
		if err != nil {
			return fmt.Errorf("get_mizaru_subkey: %w", err)
		}
		subkeyPub, err := mizaru2.ParsePKCS1PublicKey(subkeyDER)
		if err != nil {
			return fmt.Errorf("decode subkey: %w", err)
		}
		blindedMsg, secret, err := token.Blind(subkeyPub)
		if err != nil {
			return fmt.Errorf("blind token: %w", err)
		}
		// The broker expects BlindedClientToken, which serde serializes as a
		// byte array (array of ints). Encode the blinded message accordingly.
		blindedTokenJSON := encodeByteArrayJSON(blindedMsg)
		args := brokerproto.GetConnectTokenArgs{
			AuthToken:  authToken,
			Level:      level,
			Epoch:      epoch,
			BlindToken: blindedTokenJSON,
		}
		rawResp, err := m.Broker.GetConnectToken(ctx, args)
		if err != nil {
			// WrongLevel -> try the next level (matches Rust AuthError::WrongLevel).
			if isWrongLevelErr(err) {
				log.Printf("auth: epoch=%d level=%s switching to next level", epoch, level)
				continue
			}
			return fmt.Errorf("get_connect_token: %w", err)
		}
		var blindedSig mizaru2.BlindedSignature
		if err := json.Unmarshal(rawResp, &blindedSig); err != nil {
			return fmt.Errorf("decode blinded signature: %w", err)
		}
		if blindedSig.Epoch != epoch {
			return fmt.Errorf("auth: wrong epoch in response: got %d want %d", blindedSig.Epoch, epoch)
		}
		// Verify the Merkle membership proof against the configured broker key.
		if m.Cfg != nil && m.Cfg.BrokerKeys != nil {
			if err := m.verifyMerkle(level, epoch, &blindedSig); err != nil {
				return fmt.Errorf("verify_member: %w", err)
			}
		}
		uSig, err := blindedSig.Unblind(secret, token)
		if err != nil {
			return fmt.Errorf("unblind: %w", err)
		}
		data, err := marshalConnectToken(level, token, uSig)
		if err != nil {
			return err
		}
		if err := m.DB.Write(ctx, fmt.Sprintf("conn_token_%d", epoch), data); err != nil {
			return err
		}
		return nil
	}
	return errors.New("auth: could not obtain a connect token for any level")
}

// verifyMerkle verifies the blinded signature's Merkle membership proof
// against the configured mizaru_free / mizaru_plus root. This mirrors the
// Rust mizaru_key.verify_member(epoch, &res.used_key, &res.merkle_branch),
// which checks ONLY the Merkle proof (the RSA signature is still blinded at
// this point and is verified after unblinding via BlindVerify elsewhere).
func (m *Manager) verifyMerkle(level brokerproto.AccountLevel, epoch uint16, sig *mizaru2.BlindedSignature) error {
	var hexKey string
	if level == brokerproto.AccountLevelPlus {
		hexKey = m.Cfg.BrokerKeys.MizaruPlus
	} else {
		hexKey = m.Cfg.BrokerKeys.MizaruFree
	}
	rootBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return fmt.Errorf("decode mizaru hex: %w", err)
	}
	if len(rootBytes) != 32 {
		return fmt.Errorf("mizaru key: expected 32 bytes, got %d", len(rootBytes))
	}
	var root mizaru2.Hash
	copy(root[:], rootBytes)
	return mizaru2.VerifyMember(epoch, sig.UsedKey, sig.MerkleBranch, root)
}

// sleepCtx sleeps for d or until ctx is canceled.
func sleepCtx(ctx context.Context, d time.Duration) error {
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// isWrongLevelErr reports whether err is the broker's WrongLevel auth error.
// nanorpc surfaces it as a *nanorpc.ServerError whose message is "wrong_level".
func isWrongLevelErr(err error) bool {
	if err == nil {
		return false
	}
	var se *nanorpc.ServerError
	if errors.As(err, &se) {
		return se.Message == "wrong_level"
	}
	return false
}

// encodeByteArrayJSON encodes a byte slice as a JSON array of integers
// (0..255), matching serde's serialize_bytes for Vec<u8> / BlindedClientToken.
func encodeByteArrayJSON(b []byte) json.RawMessage {
	arr := make([]uint16, len(b))
	for i, v := range b {
		arr[i] = uint16(v)
	}
	out, err := json.Marshal(arr)
	if err != nil {
		return json.RawMessage("[]")
	}
	return out
}
