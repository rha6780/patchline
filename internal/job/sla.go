// Package job runs Patchline's scheduled work.
package job

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/inventory"
	"github.com/rha6780/patchline/internal/policy"
	"github.com/rha6780/patchline/internal/source/kev"
	"github.com/rha6780/patchline/internal/store"
)

// SLAStore is the persistence the SLA job needs.
type SLAStore interface {
	OpenFindingsForSLA(ctx context.Context) ([]store.SLAFinding, error)
	UpdateSLA(ctx context.Context, u store.SLAUpdate, prev store.Finding) error
	RecordReminder(ctx context.Context, findingID int64, kind, due string, at time.Time) error
	KEVSet(ctx context.Context) (map[string]bool, error)
	ReplaceKEV(ctx context.Context, entries []store.KEVEntry, version string) error
	Setting(ctx context.Context, key string) (string, error)
	ClearDueOverride(ctx context.Context, id int64) error
}

// SLA evaluates the policy for open findings, keeps due dates current and
// records reminders. It also refreshes the CISA KEV catalog.
type SLA struct {
	Store     SLAStore
	Policy    policy.Policy
	Inventory *inventory.Inventory
	Logger    *slog.Logger

	// KEVURL is the KEV feed; empty disables KEV.
	KEVURL     string
	KEVRefresh time.Duration // default 24h
	HTTP       *http.Client

	// OnChange is called after events were recorded (to wake the notifier).
	OnChange func()
	Now      func() time.Time
	Interval time.Duration // default 5m

	once sync.Once
	wake chan struct{}
}

func (j *SLA) init() {
	j.once.Do(func() {
		if j.Logger == nil {
			j.Logger = slog.Default()
		}
		if j.Inventory == nil {
			j.Inventory = inventory.Empty()
		}
		if j.KEVRefresh == 0 {
			j.KEVRefresh = 24 * time.Hour
		}
		if j.OnChange == nil {
			j.OnChange = func() {}
		}
		if j.Now == nil {
			j.Now = time.Now
		}
		if j.Interval == 0 {
			j.Interval = 5 * time.Minute
		}
		j.wake = make(chan struct{}, 1)
	})
}

// Wake runs the job soon. It never blocks.
func (j *SLA) Wake() {
	j.init()
	select {
	case j.wake <- struct{}{}:
	default:
	}
}

// Run repeats RunOnce until ctx is cancelled.
func (j *SLA) Run(ctx context.Context) {
	j.init()
	t := time.NewTicker(j.Interval)
	defer t.Stop()
	for {
		if err := j.RunOnce(ctx); err != nil && ctx.Err() == nil {
			j.Logger.Error("sla job failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-j.wake:
		}
	}
}

// RunOnce refreshes KEV when due, re-evaluates open findings and sends
// reminders.
func (j *SLA) RunOnce(ctx context.Context) error {
	j.init()
	if j.KEVURL != "" {
		if err := j.refreshKEV(ctx); err != nil {
			// Keep going with the catalog we have.
			j.Logger.Warn("kev refresh failed", "err", err)
		}
	}
	kevSet, err := j.Store.KEVSet(ctx)
	if err != nil {
		return err
	}
	open, err := j.Store.OpenFindingsForSLA(ctx)
	if err != nil {
		return err
	}

	now := j.Now().UTC()
	changed := false
	for _, f := range open {
		res, inKEV := j.evaluate(f.Finding, kevSet)
		var due *time.Time
		if !res.Due.IsZero() {
			d := res.Due.UTC()
			due = &d
		}
		if f.DueOverride != nil {
			if finding.SeverityRank(res.EffectiveSeverity) < finding.SeverityRank(f.DueOverrideSeverity) {
				// The extension was approved for a lower severity (for
				// example before the CVE entered KEV): the policy's due date
				// applies again.
				if err := j.Store.ClearDueOverride(ctx, f.ID); err != nil {
					return err
				}
				j.Logger.Info("due date extension dropped", "finding", f.ID, "approved_for", f.DueOverrideSeverity, "severity", res.EffectiveSeverity)
			} else if t, err := time.Parse(store.TimeLayout, *f.DueOverride); err == nil {
				t = t.UTC()
				due = &t
			}
		}
		if differs(f.Finding, res, inKEV, due) {
			silent := f.EffectiveSeverity == ""
			if err := j.Store.UpdateSLA(ctx, store.SLAUpdate{
				FindingID: f.ID, KEV: inKEV, EffectiveSeverity: res.EffectiveSeverity,
				Reasons: res.Reasons, Due: due, Silent: silent,
			}, f.Finding); err != nil {
				return err
			}
			if !silent {
				j.Logger.Info("sla changed", "finding", f.ID, "severity", res.EffectiveSeverity, "reasons", res.Reasons, "due", due)
			}
			changed = true
			// Reminders are evaluated against the new due date next run.
			continue
		}
		if due == nil {
			continue
		}
		kind := j.reminderDue(f, *due, now)
		if kind == "" {
			continue
		}
		if err := j.Store.RecordReminder(ctx, f.ID, kind, store.FormatTime(*due), now); err != nil {
			return err
		}
		j.Logger.Info("reminder recorded", "finding", f.ID, "kind", kind, "due", due)
		changed = true
	}
	if changed {
		j.OnChange()
	}
	return nil
}

func (j *SLA) evaluate(f store.Finding, kevSet map[string]bool) (policy.Result, bool) {
	inKEV := kevSet[strings.ToUpper(f.VulnID)]
	for _, a := range f.Aliases {
		inKEV = inKEV || kevSet[strings.ToUpper(a)]
	}
	exposure := ""
	if f.Registered {
		if s, ok := j.Inventory.Service(f.Service); ok {
			exposure = string(s.Exposure)
		}
	}
	var started time.Time
	if f.SLAStartedAt != nil {
		started, _ = time.Parse(store.TimeLayout, *f.SLAStartedAt)
	}
	return j.Policy.Evaluate(policy.Input{
		Severity: f.Severity, KEV: inKEV, EPSS: f.EPSS, Exposure: exposure, StartedAt: started,
	}), inKEV
}

func differs(f store.Finding, res policy.Result, inKEV bool, due *time.Time) bool {
	if f.EffectiveSeverity != res.EffectiveSeverity || f.KEV != inKEV || !slices.Equal(f.SLAReasons, res.Reasons) {
		return true
	}
	switch {
	case f.DueAt == nil && due == nil:
		return false
	case f.DueAt == nil || due == nil:
		return true
	}
	return *f.DueAt != store.FormatTime(*due)
}

// reminderDue returns which reminder to send now, if any.
func (j *SLA) reminderDue(f store.SLAFinding, due, now time.Time) string {
	soon := time.Duration(j.Policy.Reminders.DueSoon)
	every := time.Duration(j.Policy.Reminders.OverdueEvery)
	if !now.Before(due) {
		if f.RemindedOverdueAt == nil {
			return store.ReminderOverdue
		}
		last, err := time.Parse(store.TimeLayout, *f.RemindedOverdueAt)
		if err == nil && every > 0 && now.Sub(last) >= every {
			return store.ReminderOverdue
		}
		return ""
	}
	if soon > 0 && f.RemindedDueSoonAt == nil && !now.Before(due.Add(-soon)) {
		return store.ReminderDueSoon
	}
	return ""
}

func (j *SLA) refreshKEV(ctx context.Context) error {
	last, err := j.Store.Setting(ctx, "kev.refreshed_at")
	if err != nil {
		return err
	}
	if t, err := time.Parse(store.TimeLayout, last); err == nil && j.Now().Sub(t) < j.KEVRefresh {
		return nil
	}
	c, err := kev.Fetch(ctx, j.KEVURL, j.HTTP)
	if err != nil {
		return err
	}
	entries := make([]store.KEVEntry, 0, len(c.Vulnerabilities))
	for _, v := range c.Vulnerabilities {
		entries = append(entries, store.KEVEntry{CVEID: v.CVEID, DateAdded: v.DateAdded, DueDate: v.DueDate, Ransomware: v.Ransomware})
	}
	if err := j.Store.ReplaceKEV(ctx, entries, c.Version); err != nil {
		return err
	}
	j.Logger.Info("kev catalog refreshed", "version", c.Version, "entries", len(entries))
	return nil
}
