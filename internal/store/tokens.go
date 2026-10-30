package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// APIToken is a token tools use instead of a session.
type APIToken struct {
	ID            int64    `json:"id"`
	Name          string   `json:"name"`
	Prefix        string   `json:"prefix"`
	Permissions   []string `json:"permissions"`
	CreatedBy     string   `json:"created_by"`
	CreatedByName string   `json:"created_by_name,omitempty"`
	CreatedAt     string   `json:"created_at"`
	ExpiresAt     *string  `json:"expires_at,omitempty"`
	LastUsedAt    *string  `json:"last_used_at,omitempty"`
	RevokedAt     *string  `json:"revoked_at,omitempty"`
}

// CreateToken stores a token by its hash and records it in the audit log.
func (s *Store) CreateToken(ctx context.Context, t APIToken, hash string, by Actor) (id int64, err error) {
	perms, err := json.Marshal(nonNil(t.Permissions))
	if err != nil {
		return 0, err
	}
	now := formatTime(s.now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = tx.QueryRowContext(ctx, `
		INSERT INTO api_tokens (name, prefix, hash, permissions, created_by, created_by_name, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
		t.Name, t.Prefix, hash, string(perms), by.Subject, by.Name, now, t.ExpiresAt).Scan(&id); err != nil {
		return 0, err
	}
	detail := map[string]any{"name": t.Name, "permissions": t.Permissions}
	if t.ExpiresAt != nil {
		detail["expires_at"] = *t.ExpiresAt
	}
	if err = insertAudit(ctx, tx, by, "token.create", fmt.Sprint(id), detail, now); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

const tokenColumns = `SELECT id, name, prefix, permissions, created_by, created_by_name, created_at,
	expires_at, last_used_at, revoked_at FROM api_tokens`

func scanToken(sc scanner) (APIToken, error) {
	var (
		t                        APIToken
		perms                    string
		expires, used, revokedAt sql.NullString
	)
	if err := sc.Scan(&t.ID, &t.Name, &t.Prefix, &perms, &t.CreatedBy, &t.CreatedByName, &t.CreatedAt,
		&expires, &used, &revokedAt); err != nil {
		return APIToken{}, err
	}
	if err := json.Unmarshal([]byte(perms), &t.Permissions); err != nil {
		return APIToken{}, err
	}
	for _, p := range []struct {
		src *sql.NullString
		dst **string
	}{{&expires, &t.ExpiresAt}, {&used, &t.LastUsedAt}, {&revokedAt, &t.RevokedAt}} {
		if p.src.Valid {
			v := p.src.String
			*p.dst = &v
		}
	}
	return t, nil
}

// TokenByHash returns a usable token (not revoked, not expired) and marks
// it used, at most once a minute. It returns sql.ErrNoRows otherwise.
func (s *Store) TokenByHash(ctx context.Context, hash string) (APIToken, error) {
	now := formatTime(s.now())
	t, err := scanToken(s.db.QueryRowContext(ctx, tokenColumns+`
		WHERE hash = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`, hash, now))
	if err != nil {
		return APIToken{}, err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ?
		WHERE id = ? AND (last_used_at IS NULL OR last_used_at < ?)`,
		now, t.ID, formatTime(s.now().Add(-time.Minute))); err != nil {
		return APIToken{}, err
	}
	return t, nil
}

// ListTokens returns every token, newest first, revoked ones included.
func (s *Store) ListTokens(ctx context.Context) ([]APIToken, error) {
	rows, err := s.db.QueryContext(ctx, tokenColumns+` ORDER BY revoked_at IS NOT NULL, created_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIToken{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ErrTokenRevoked means the token was revoked already (or does not exist).
var ErrTokenRevoked = errors.New("token not found or already revoked")

// RevokeToken stops a token from working and records it in the audit log.
func (s *Store) RevokeToken(ctx context.Context, id int64, by Actor) (err error) {
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
	var name string
	err = tx.QueryRowContext(ctx, `UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL RETURNING name`,
		now, id).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrTokenRevoked
	}
	if err != nil {
		return err
	}
	if err = insertAudit(ctx, tx, by, "token.revoke", fmt.Sprint(id), map[string]any{"name": name}, now); err != nil {
		return err
	}
	return tx.Commit()
}
