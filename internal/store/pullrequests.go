package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"github.com/rha6780/patchline/internal/finding"
)

// Pull request link states.
const (
	PRStateOpen   = "open"
	PRStateMerged = "merged"
	PRStateClosed = "closed"
)

// Fix verdicts: whether the pull request's target version leaves the
// vulnerable range.
const (
	VerdictFixes        = "fixes"
	VerdictInsufficient = "insufficient"
	VerdictUnknown      = "unknown"
)

// PullRequestLink connects a finding to a pull request that changes its
// component.
type PullRequestLink struct {
	FindingID     int64  `json:"finding_id"`
	Repository    string `json:"repository"`
	Number        int    `json:"number"`
	URL           string `json:"url"`
	Title         string `json:"title"`
	State         string `json:"state"`
	Package       string `json:"package"`
	FromVersion   string `json:"from_version,omitempty"`
	ToVersion     string `json:"to_version"`
	Verdict       string `json:"verdict"`
	VerdictDetail string `json:"verdict_detail,omitempty"`
	HeadSHA       string `json:"head_sha,omitempty"`
	MergeSHA      string `json:"merge_sha,omitempty"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

func (l PullRequestLink) evidence() map[string]any {
	return map[string]any{
		"repository": l.Repository, "number": l.Number, "url": l.URL, "title": l.Title,
		"package": l.Package, "from_version": l.FromVersion, "to_version": l.ToVersion,
		"verdict": l.Verdict, "verdict_detail": l.VerdictDetail,
		"head_sha": l.HeadSHA, "merge_sha": l.MergeSHA,
	}
}

// OpenFindingsInRepository returns open findings of a repository in the
// given environments.
func (s *Store) OpenFindingsInRepository(ctx context.Context, repository string, environments []string) ([]Finding, error) {
	if len(environments) == 0 {
		return nil, nil
	}
	q := findingColumns + ` FROM findings
		WHERE repository = ? AND state NOT IN ('resolved', 'not_affected', 'risk_accepted')
		  AND environment IN (?` + strings.Repeat(", ?", len(environments)-1) + `)
		ORDER BY id`
	args := []any{repository}
	for _, e := range environments {
		args = append(args, e)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// LinkPullRequest records an open pull request for a finding. A new link
// moves an untriaged finding (new, needs review, reopened) to in progress.
// It returns true when it recorded an event.
func (s *Store) LinkPullRequest(ctx context.Context, l PullRequestLink) (changed bool, err error) {
	now := formatTime(s.now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	var state string
	if err = tx.QueryRowContext(ctx, `SELECT state FROM findings WHERE id = ?`, l.FindingID).Scan(&state); err != nil {
		return false, err
	}

	var prev PullRequestLink
	err = tx.QueryRowContext(ctx, `
		SELECT state, to_version, verdict FROM finding_pull_requests
		WHERE finding_id = ? AND repository = ? AND number = ?`,
		l.FindingID, l.Repository, l.Number).Scan(&prev.State, &prev.ToVersion, &prev.Verdict)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	err = nil

	if _, err = tx.ExecContext(ctx, `
		INSERT INTO finding_pull_requests (finding_id, repository, number, url, title, state, package,
			from_version, to_version, verdict, verdict_detail, head_sha, merge_sha, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, '', ?, ?)
		ON CONFLICT (finding_id, repository, number) DO UPDATE SET
			url = excluded.url, title = excluded.title, state = 'open', package = excluded.package,
			from_version = excluded.from_version, to_version = excluded.to_version,
			verdict = excluded.verdict, verdict_detail = excluded.verdict_detail,
			head_sha = excluded.head_sha, updated_at = excluded.updated_at`,
		l.FindingID, l.Repository, l.Number, l.URL, l.Title, l.Package,
		l.FromVersion, l.ToVersion, l.Verdict, l.VerdictDetail, l.HeadSHA, now, now); err != nil {
		return false, err
	}

	kind := finding.EventPRLinked
	if exists {
		if prev.State == PRStateOpen && prev.ToVersion == l.ToVersion && prev.Verdict == l.Verdict {
			return false, tx.Commit() // nothing worth telling
		}
		kind = finding.EventPRUpdated
	}

	from, to := sql.NullString{}, sql.NullString{}
	switch finding.State(state) {
	case finding.StateNew, finding.StateNeedsReview, finding.StateReopened:
		if finding.CanTransition(finding.State(state), finding.StateInProgress) {
			from = sql.NullString{String: state, Valid: true}
			to = sql.NullString{String: string(finding.StateInProgress), Valid: true}
			if _, err = tx.ExecContext(ctx, `UPDATE findings SET state = ?, updated_at = ? WHERE id = ?`,
				finding.StateInProgress, now, l.FindingID); err != nil {
				return false, err
			}
		}
	}
	l.State = PRStateOpen
	if err = insertEvent(ctx, tx, l.FindingID, kind, from, to, l.evidence(), now); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// ClosePullRequest records that a pull request was merged or closed, for
// every finding linked to it. A merge moves the finding to awaiting
// verification: the next rescan decides whether it is resolved. It returns
// the ids of the findings that got an event.
func (s *Store) ClosePullRequest(ctx context.Context, repository string, number int, merged bool, mergeSHA string) (ids []int64, err error) {
	now := formatTime(s.now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	rows, err := tx.QueryContext(ctx, `
		SELECT l.finding_id, f.state, l.url, l.title, l.package, l.from_version, l.to_version, l.verdict, l.verdict_detail, l.head_sha
		FROM finding_pull_requests l JOIN findings f ON f.id = l.finding_id
		WHERE l.repository = ? AND l.number = ? AND l.state = 'open'`, repository, number)
	if err != nil {
		return nil, err
	}
	type row struct {
		link  PullRequestLink
		state string
	}
	var links []row
	for rows.Next() {
		var r row
		if err = rows.Scan(&r.link.FindingID, &r.state, &r.link.URL, &r.link.Title, &r.link.Package,
			&r.link.FromVersion, &r.link.ToVersion, &r.link.Verdict, &r.link.VerdictDetail, &r.link.HeadSHA); err != nil {
			rows.Close()
			return nil, err
		}
		r.link.Repository, r.link.Number = repository, number
		links = append(links, r)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}

	newState, kind := PRStateClosed, finding.EventPRClosed
	if merged {
		newState, kind = PRStateMerged, finding.EventPRMerged
	}
	for _, r := range links {
		if _, err = tx.ExecContext(ctx, `
			UPDATE finding_pull_requests SET state = ?, merge_sha = ?, updated_at = ?
			WHERE finding_id = ? AND repository = ? AND number = ?`,
			newState, mergeSHA, now, r.link.FindingID, repository, number); err != nil {
			return nil, err
		}
		from, to := sql.NullString{}, sql.NullString{}
		if merged {
			switch finding.State(r.state) {
			case finding.StateNew, finding.StateNeedsReview, finding.StateReopened, finding.StateInProgress:
				from = sql.NullString{String: r.state, Valid: true}
				to = sql.NullString{String: string(finding.StateAwaitingVerification), Valid: true}
				if _, err = tx.ExecContext(ctx, `UPDATE findings SET state = ?, updated_at = ? WHERE id = ?`,
					finding.StateAwaitingVerification, now, r.link.FindingID); err != nil {
					return nil, err
				}
			}
		}
		r.link.State, r.link.MergeSHA = newState, mergeSHA
		if err = insertEvent(ctx, tx, r.link.FindingID, kind, from, to, r.link.evidence(), now); err != nil {
			return nil, err
		}
		ids = append(ids, r.link.FindingID)
	}
	return ids, tx.Commit()
}

// FindingPullRequests returns the pull requests linked to a finding.
func (s *Store) FindingPullRequests(ctx context.Context, findingID int64) ([]PullRequestLink, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT finding_id, repository, number, url, title, state, package, from_version, to_version,
		       verdict, verdict_detail, head_sha, merge_sha, created_at, updated_at
		FROM finding_pull_requests WHERE finding_id = ? ORDER BY created_at, number`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PullRequestLink{}
	for rows.Next() {
		var l PullRequestLink
		if err := rows.Scan(&l.FindingID, &l.Repository, &l.Number, &l.URL, &l.Title, &l.State, &l.Package,
			&l.FromVersion, &l.ToVersion, &l.Verdict, &l.VerdictDetail, &l.HeadSHA, &l.MergeSHA,
			&l.CreatedAt, &l.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func insertEvent(ctx context.Context, tx *sql.Tx, findingID int64, kind string, from, to sql.NullString, evidence map[string]any, now string) error {
	ev, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO finding_events (finding_id, kind, from_state, to_state, evidence, occurred_at)
		VALUES (?, ?, ?, ?, ?, ?)`, findingID, kind, from, to, string(ev), now)
	return err
}
