package osv

import (
	"archive/zip"
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rha6780/patchline/internal/store"
)

// DefaultURL serves the OSV exports: <ecosystem>/all.zip,
// <ecosystem>/modified_id.csv and <ecosystem>/<id>.json.
const DefaultURL = "https://osv-vulnerabilities.storage.googleapis.com"

// SyncStore is the persistence the syncer needs.
type SyncStore interface {
	WriteOSV(ctx context.Context, replaceEcosystem string, produce func(put func(store.OSVRecord) error) error) error
	Setting(ctx context.Context, key string) (string, error)
	SetSystemSetting(ctx context.Context, key, value string) error
}

// Syncer keeps the local OSV mirror current: a full export the first time,
// then only the records modified since the last sync.
type Syncer struct {
	Store      SyncStore
	BaseURL    string // default DefaultURL; an internal mirror of the same layout works
	Ecosystems []string
	HTTP       *http.Client
	// TempDir holds the downloaded export while it is read (default: the
	// system temp directory).
	TempDir string
	// IncrementalLimit: with more changed records than this, the full
	// export is cheaper (default 2000).
	IncrementalLimit int
	Logger           *slog.Logger
	Now              func() time.Time
}

func (s *Syncer) defaults() {
	if s.BaseURL == "" {
		s.BaseURL = DefaultURL
	}
	s.BaseURL = strings.TrimRight(s.BaseURL, "/")
	if s.HTTP == nil {
		s.HTTP = &http.Client{Timeout: 30 * time.Minute}
	}
	if s.IncrementalLimit == 0 {
		s.IncrementalLimit = 2000
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	if s.Now == nil {
		s.Now = time.Now
	}
}

func syncedKey(ecosystem string) string { return "osv." + ecosystem + ".synced_at" }

// Ready reports whether every ecosystem has been synced at least once.
// Until then a missing match does not mean a fix.
func (s *Syncer) Ready(ctx context.Context) (bool, error) {
	for _, eco := range s.Ecosystems {
		v, err := s.Store.Setting(ctx, syncedKey(eco))
		if err != nil {
			return false, err
		}
		if v == "" {
			return false, nil
		}
	}
	return true, nil
}

// Sync updates every ecosystem and reports how many records changed. An
// ecosystem that fails keeps its data; the others still sync.
func (s *Syncer) Sync(ctx context.Context) (changed int, err error) {
	s.defaults()
	var errs []error
	for _, eco := range s.Ecosystems {
		n, err := s.syncEcosystem(ctx, eco)
		if err != nil {
			errs = append(errs, fmt.Errorf("osv %s: %w", eco, err))
			continue
		}
		changed += n
	}
	return changed, errors.Join(errs...)
}

func (s *Syncer) syncEcosystem(ctx context.Context, eco string) (int, error) {
	started := s.Now().UTC()
	last, err := s.Store.Setting(ctx, syncedKey(eco))
	if err != nil {
		return 0, err
	}
	var n int
	full := last == ""
	if !full {
		since, perr := time.Parse(time.RFC3339Nano, last)
		if perr != nil {
			full = true
		} else {
			var ids []string
			ids, err = s.modifiedSince(ctx, eco, since)
			switch {
			case err != nil:
				return 0, err
			case len(ids) > s.IncrementalLimit:
				full = true
			default:
				n, err = s.fetchRecords(ctx, eco, ids)
			}
		}
	}
	if full {
		n, err = s.fullSync(ctx, eco)
	}
	if err != nil {
		return 0, err
	}
	// Overlap a little: records modified while this sync ran are fetched
	// again next time.
	if err := s.Store.SetSystemSetting(ctx, syncedKey(eco), started.Add(-time.Minute).Format(time.RFC3339Nano)); err != nil {
		return 0, err
	}
	s.Logger.Info("osv synced", "ecosystem", eco, "full", full, "records", n)
	return n, nil
}

func (s *Syncer) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.BaseURL+"/"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	return resp, nil
}

// fullSync downloads <eco>/all.zip and replaces the ecosystem's records.
func (s *Syncer) fullSync(ctx context.Context, eco string) (int, error) {
	resp, err := s.get(ctx, url.PathEscape(eco)+"/all.zip")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	f, err := os.CreateTemp(s.TempDir, "osv-*.zip")
	if err != nil {
		return 0, err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	size, err := io.Copy(f, resp.Body)
	if err != nil {
		return 0, fmt.Errorf("download all.zip: %w", err)
	}
	zr, err := zip.NewReader(f, size)
	if err != nil {
		return 0, fmt.Errorf("read all.zip: %w", err)
	}
	n := 0
	err = s.Store.WriteOSV(ctx, eco, func(put func(store.OSVRecord) error) error {
		for _, zf := range zr.File {
			if !strings.HasSuffix(zf.Name, ".json") {
				continue
			}
			rc, err := zf.Open()
			if err != nil {
				return err
			}
			data, err := io.ReadAll(io.LimitReader(rc, 16<<20))
			rc.Close()
			if err != nil {
				return err
			}
			rec, err := Parse(data, eco)
			if err != nil {
				s.Logger.Debug("skip osv record", "file", zf.Name, "err", err)
				continue
			}
			if err := put(rec); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// modifiedSince reads <eco>/modified_id.csv ("<modified>,<id>", newest
// first) up to since.
func (s *Syncer) modifiedSince(ctx context.Context, eco string, since time.Time) ([]string, error) {
	resp, err := s.get(ctx, url.PathEscape(eco)+"/modified_id.csv")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var ids []string
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		ts, id, ok := strings.Cut(strings.TrimSpace(sc.Text()), ",")
		if !ok {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			continue
		}
		if !t.After(since) {
			break
		}
		ids = append(ids, id)
		if len(ids) > s.IncrementalLimit {
			break
		}
	}
	return ids, sc.Err()
}

// fetchRecords downloads single records and stores them.
func (s *Syncer) fetchRecords(ctx context.Context, eco string, ids []string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	var recs []store.OSVRecord
	for _, id := range ids {
		resp, err := s.get(ctx, url.PathEscape(eco)+"/"+url.PathEscape(id)+".json")
		if err != nil {
			return 0, err
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if err != nil {
			return 0, err
		}
		rec, err := Parse(data, eco)
		if err != nil {
			s.Logger.Debug("skip osv record", "id", id, "err", err)
			continue
		}
		recs = append(recs, rec)
	}
	err := s.Store.WriteOSV(ctx, "", func(put func(store.OSVRecord) error) error {
		for _, r := range recs {
			if err := put(r); err != nil {
				return err
			}
		}
		return nil
	})
	return len(recs), err
}
