package auth

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/goose-network/geph5-go/internal/config"
	"github.com/goose-network/geph5-go/internal/melpow"
)

// ensureCredential makes sure Cfg.Credentials holds a credential the production
// broker accepts. The broker hard-rejects Credential::TestDummy (the zero value
// the zero-config provider starts with), so an unset credential must be turned
// into a registered account secret. An operator-provided secret or legacy
// username+password is used as-is; otherwise the persisted account secret is
// loaded, or a new account is self-registered via the broker's proof-of-work
// puzzle (get_puzzle -> solve_puzzle -> register_user_secret), mirroring the
// Rust GUI manager's start_registration (control_prot.rs). The minted secret is
// persisted under "account_secret" so the PoW is solved only once per database.
//
// Called with authTokenMu held (from GetAuthToken), so the Cfg.Credentials
// mutation is serialized against marshalCredential.
func (m *Manager) ensureCredential(ctx context.Context) error {
	if m.Cfg == nil {
		return errors.New("auth: nil config")
	}
	c := m.Cfg.Credentials
	if c.Kind == "secret" && c.Secret != "" {
		return nil
	}
	if c.Kind == "legacy_username_password" && c.Username != "" {
		return nil
	}
	// No usable operator credential: try the persisted secret first.
	if m.DB != nil {
		if raw, err := m.DB.Read(ctx, "account_secret"); err == nil && len(raw) > 0 {
			m.Cfg.Credentials = config.Credential{Kind: "secret", Secret: string(raw)}
			return nil
		}
	}
	if m.Broker == nil {
		return errors.New("auth: no broker configured to register an account")
	}
	secret, err := m.registerAccount(ctx)
	if err != nil {
		return err
	}
	m.Cfg.Credentials = config.Credential{Kind: "secret", Secret: secret}
	if m.DB != nil {
		if err := m.DB.Write(ctx, "account_secret", []byte(secret)); err != nil {
			log.Printf("auth: warning: could not persist account secret: %v", err)
		}
	}
	return nil
}

// registerAccount solves the broker's registration puzzle and registers a new
// account secret, returning the secret string. Mirrors start_registration in
// geph5-client/src/control_prot.rs.
func (m *Manager) registerAccount(ctx context.Context) (string, error) {
	puzzle, difficulty, err := m.Broker.GetPuzzle(ctx)
	if err != nil {
		return "", fmt.Errorf("auth: get_puzzle: %w", err)
	}
	log.Printf("auth: no account secret configured; registering via proof-of-work (difficulty %d)", difficulty)
	lastLog := -10
	solution := melpow.SolvePuzzle(puzzle, int(difficulty), func(progress float64) {
		pct := int(progress * 100)
		if pct >= lastLog+10 {
			lastLog = pct
			log.Printf("auth: registration proof-of-work %d%%", pct)
		}
	})
	secret, err := m.Broker.RegisterUserSecret(ctx, puzzle, solution)
	if err != nil {
		return "", fmt.Errorf("auth: register_user_secret: %w", err)
	}
	log.Printf("auth: registered a new account secret")
	return secret, nil
}
