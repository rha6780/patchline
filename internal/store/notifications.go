package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/rha6780/patchline/internal/finding"
)

// NotificationWork is a finding whose chat message is missing or behind.
type NotificationWork struct {
	Finding Finding
	// Channel and MessageRef identify the existing message; MessageRef is
	// empty when nothing has been posted yet.
	Channel     string
	MessageRef  string
	LastEventID int64
	Attempts    int
	// NewEvents are the events after LastEventID, excluding "notified".
	NewEvents []FindingEvent
}

// PendingNotifications returns findings whose effective severity is at or
// above minSeverity that have events not yet reflected in sink, and are due
// for an attempt. Findings the policy has not evaluated yet wait, so the
// first message already carries the due date.
func (s *Store) PendingNotifications(ctx context.Context, sink string, minSeverity string, limit int) ([]NotificationWork, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT f.id, COALESCE(n.channel, ''), COALESCE(n.message_ref, ''),
		       COALESCE(n.last_event_id, 0), COALESCE(n.attempts, 0)
		FROM findings f
		LEFT JOIN finding_notifications n ON n.finding_id = f.id AND n.sink = ?
		WHERE f.effective_severity != ''
		  AND (CASE f.effective_severity
		         WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
		         WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END) <= ?
		  AND (n.next_attempt_at IS NULL OR n.next_attempt_at <= ?)
		  AND EXISTS (
		        SELECT 1 FROM finding_events e
		        WHERE e.finding_id = f.id AND e.kind != ? AND e.id > COALESCE(n.last_event_id, 0))
		ORDER BY f.id
		LIMIT ?`,
		sink, finding.SeverityRank(minSeverity), formatTime(s.now()), finding.EventNotified, limit)
	if err != nil {
		return nil, err
	}
	var work []NotificationWork
	for rows.Next() {
		var w NotificationWork
		if err := rows.Scan(&w.Finding.ID, &w.Channel, &w.MessageRef, &w.LastEventID, &w.Attempts); err != nil {
			rows.Close()
			return nil, err
		}
		work = append(work, w)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i := range work {
		f, err := s.GetFinding(ctx, work[i].Finding.ID)
		if err != nil {
			return nil, err
		}
		work[i].Finding = f
		events, err := s.FindingEvents(ctx, f.ID)
		if err != nil {
			return nil, err
		}
		for _, e := range events {
			if e.ID > work[i].LastEventID && e.Kind != finding.EventNotified {
				work[i].NewEvents = append(work[i].NewEvents, e)
			}
		}
	}
	return work, nil
}

// NotificationResult records what a sink did for a finding.
type NotificationResult struct {
	FindingID   int64
	Sink        string
	Channel     string
	MessageRef  string // empty when the finding was intentionally not posted
	LastEventID int64
	// Posted is true when MessageRef was created by this attempt; a
	// "notified" event is added to the finding's timeline.
	Posted bool
}

// RecordNotification stores a successful (or intentionally skipped) attempt.
func (s *Store) RecordNotification(ctx context.Context, r NotificationResult) (err error) {
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
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO finding_notifications (finding_id, sink, channel, message_ref, last_event_id, attempts, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 0, ?, ?)
		ON CONFLICT (finding_id, sink) DO UPDATE SET
			channel = excluded.channel, message_ref = excluded.message_ref,
			last_event_id = excluded.last_event_id, attempts = 0,
			last_error = NULL, next_attempt_at = NULL, updated_at = excluded.updated_at`,
		r.FindingID, r.Sink, r.Channel, r.MessageRef, r.LastEventID, now, now); err != nil {
		return err
	}
	if r.Posted {
		ev, mErr := json.Marshal(map[string]any{"sink": r.Sink, "channel": r.Channel, "message_ref": r.MessageRef})
		if mErr != nil {
			err = mErr
			return err
		}
		if _, err = tx.ExecContext(ctx, `
			INSERT INTO finding_events (finding_id, kind, evidence, occurred_at) VALUES (?, ?, ?, ?)`,
			r.FindingID, finding.EventNotified, string(ev), now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// MarkNotificationFailed records a failed attempt and when to retry.
func (s *Store) MarkNotificationFailed(ctx context.Context, findingID int64, sink string, cause error, retryAfter time.Duration) error {
	now := s.now()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO finding_notifications (finding_id, sink, attempts, last_error, next_attempt_at, created_at, updated_at)
		VALUES (?, ?, 1, ?, ?, ?, ?)
		ON CONFLICT (finding_id, sink) DO UPDATE SET
			attempts = finding_notifications.attempts + 1, last_error = excluded.last_error,
			next_attempt_at = excluded.next_attempt_at, updated_at = excluded.updated_at`,
		findingID, sink, cause.Error(), formatTime(now.Add(retryAfter)), formatTime(now), formatTime(now))
	return err
}

// NotificationError returns the last recorded error for a finding and sink.
func (s *Store) NotificationError(ctx context.Context, findingID int64, sink string) (string, error) {
	var msg sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT last_error FROM finding_notifications WHERE finding_id = ? AND sink = ?`, findingID, sink).Scan(&msg)
	return msg.String, err
}
