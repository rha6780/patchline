package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// InboxItem is a stored webhook delivery awaiting processing.
type InboxItem struct {
	ID        int64
	Source    string
	EventType string
	Payload   []byte
	Attempts  int
}

// InsertInbox stores a delivery. A delivery with the same (source,
// dedupKey) is stored once; later copies return the existing id with
// inserted=false.
func (s *Store) InsertInbox(ctx context.Context, source, eventType, dedupKey string, payload []byte) (id int64, inserted bool, err error) {
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO webhook_inbox (source, event_type, dedup_key, payload, received_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (source, dedup_key) DO NOTHING
		RETURNING id`,
		source, eventType, dedupKey, payload, formatTime(s.now())).Scan(&id)
	if err == nil {
		return id, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, false, err
	}
	err = s.db.QueryRowContext(ctx,
		`SELECT id FROM webhook_inbox WHERE source = ? AND dedup_key = ?`, source, dedupKey).Scan(&id)
	return id, false, err
}

// PendingInbox returns up to limit unprocessed items that are due for an
// attempt and have fewer than maxAttempts failures, oldest first.
func (s *Store) PendingInbox(ctx context.Context, maxAttempts, limit int) ([]InboxItem, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, source, event_type, payload, attempts
		FROM webhook_inbox
		WHERE processed_at IS NULL
		  AND attempts < ?
		  AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
		ORDER BY id
		LIMIT ?`,
		maxAttempts, formatTime(s.now()), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []InboxItem
	for rows.Next() {
		var it InboxItem
		if err := rows.Scan(&it.ID, &it.Source, &it.EventType, &it.Payload, &it.Attempts); err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	return items, rows.Err()
}

// MarkInboxDone records successful processing. note, if non-empty, is kept
// in last_error for visibility (for example "skipped: ...").
func (s *Store) MarkInboxDone(ctx context.Context, id int64, note string) error {
	var n sql.NullString
	if note != "" {
		n = sql.NullString{String: note, Valid: true}
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE webhook_inbox
		SET processed_at = ?, last_error = ?, attempts = attempts + 1, next_attempt_at = NULL
		WHERE id = ?`,
		formatTime(s.now()), n, id)
	return err
}

// MarkInboxFailed records a failed attempt and when to retry.
func (s *Store) MarkInboxFailed(ctx context.Context, id int64, cause error, retryAfter time.Duration) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE webhook_inbox
		SET attempts = attempts + 1, last_error = ?, next_attempt_at = ?
		WHERE id = ?`,
		cause.Error(), formatTime(s.now().Add(retryAfter)), id)
	return err
}
