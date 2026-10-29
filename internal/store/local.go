package store

import (
	"context"
	"database/sql"
	"time"
)

// LocalAccount is the built-in admin account.
type LocalAccount struct {
	Username          string
	PasswordHash      string
	MustChange        bool
	FailedAttempts    int
	LockedUntil       *string
	PasswordChangedAt string
	LastLoginAt       *string
}

// EnsureLocalAccount creates the account with hash unless it exists, and
// reports whether it did. An existing account keeps its password.
func (s *Store) EnsureLocalAccount(ctx context.Context, username, hash string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO local_accounts (username, password_hash, must_change, password_changed_at)
		VALUES (?, ?, 1, ?) ON CONFLICT (username) DO NOTHING`, username, hash, formatTime(s.now()))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// GetLocalAccount returns an account, or sql.ErrNoRows.
func (s *Store) GetLocalAccount(ctx context.Context, username string) (LocalAccount, error) {
	var (
		a      LocalAccount
		locked sql.NullString
		last   sql.NullString
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT username, password_hash, must_change, failed_attempts, locked_until, password_changed_at, last_login_at
		FROM local_accounts WHERE username = ?`, username).
		Scan(&a.Username, &a.PasswordHash, &a.MustChange, &a.FailedAttempts, &locked, &a.PasswordChangedAt, &last)
	if err != nil {
		return LocalAccount{}, err
	}
	if locked.Valid {
		a.LockedUntil = &locked.String
	}
	if last.Valid {
		a.LastLoginAt = &last.String
	}
	return a, nil
}

// RecordLoginFailure counts a failed login. After max failures in a row the
// account is locked for lock, and the counter starts over. It reports
// whether this failure locked the account.
func (s *Store) RecordLoginFailure(ctx context.Context, username string, max int, lock time.Duration) (locked bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	var n int
	if err = tx.QueryRowContext(ctx, `
		UPDATE local_accounts SET failed_attempts = failed_attempts + 1 WHERE username = ?
		RETURNING failed_attempts`, username).Scan(&n); err != nil {
		return false, err
	}
	if n >= max {
		if _, err = tx.ExecContext(ctx, `UPDATE local_accounts SET failed_attempts = 0, locked_until = ? WHERE username = ?`,
			formatTime(s.now().Add(lock)), username); err != nil {
			return false, err
		}
		locked = true
	}
	return locked, tx.Commit()
}

// RecordLoginSuccess clears failures and records the login time.
func (s *Store) RecordLoginSuccess(ctx context.Context, username string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE local_accounts SET failed_attempts = 0, locked_until = NULL, last_login_at = ? WHERE username = ?`,
		formatTime(s.now()), username)
	return err
}

// SetLocalPassword replaces the password hash, clears any lock and records
// the change in the audit log. Sessions started before the change stop
// working (the authenticator compares password_changed_at), except the
// one in keepSession, when given.
func (s *Store) SetLocalPassword(ctx context.Context, username, hash string, mustChange bool, by Actor, keepSession string) (err error) {
	now := formatTime(s.now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	res, err := tx.ExecContext(ctx, `
		UPDATE local_accounts SET password_hash = ?, must_change = ?, failed_attempts = 0, locked_until = NULL,
		       password_changed_at = ?
		WHERE username = ?`, hash, mustChange, now, username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err = tx.ExecContext(ctx, `
			INSERT INTO local_accounts (username, password_hash, must_change, password_changed_at) VALUES (?, ?, ?, ?)`,
			username, hash, mustChange, now); err != nil {
			return err
		}
	}
	if keepSession != "" {
		// The session that made the change stays valid.
		if _, err = tx.ExecContext(ctx, `UPDATE sessions SET created_at = ? WHERE id_hash = ?`, now, keepSession); err != nil {
			return err
		}
	}
	action := "account.password"
	if mustChange {
		action = "account.password_reset"
	}
	if err = insertAudit(ctx, tx, by, action, username, map[string]any{}, now); err != nil {
		return err
	}
	return tx.Commit()
}
