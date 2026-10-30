package job

import (
	"context"
	"log/slog"
	"time"

	"github.com/rha6780/patchline/internal/source/osv"
)

// OSV keeps the local OSV mirror current and asks for a re-analysis of the
// stored SBOMs whenever records changed.
type OSV struct {
	Syncer   *osv.Syncer
	Interval time.Duration // default 6h
	Logger   *slog.Logger
	// OnChanged is called after a sync that changed records.
	OnChanged func(ctx context.Context)
}

// Run syncs at once, then every Interval, until ctx is cancelled.
func (j *OSV) Run(ctx context.Context) {
	if j.Interval == 0 {
		j.Interval = 6 * time.Hour
	}
	if j.Logger == nil {
		j.Logger = slog.Default()
	}
	if j.OnChanged == nil {
		j.OnChanged = func(context.Context) {}
	}
	t := time.NewTicker(j.Interval)
	defer t.Stop()
	for {
		changed, err := j.Syncer.Sync(ctx)
		if err != nil && ctx.Err() == nil {
			// Keep the data we have; try again next time.
			j.Logger.Warn("osv sync failed", "err", err)
		}
		if changed > 0 && ctx.Err() == nil {
			j.OnChanged(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
