package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	_ "github.com/ncruces/go-sqlite3/driver" // registers the "sqlite3" driver (pure Go, no cgo)
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var embedded embed.FS

// Open opens (or creates) the SQLite database at path with WAL mode,
// foreign keys and a busy timeout enabled.
func Open(ctx context.Context, path string) (*sql.DB, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
	}

	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_txlock=immediate" // take the write lock at BEGIN to avoid upgrade deadlocks

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return db, nil
}

// Migrate applies all pending embedded migrations and returns how many ran.
func Migrate(ctx context.Context, db *sql.DB) (int, error) {
	fsys, err := fs.Sub(embedded, "migrations")
	if err != nil {
		return 0, err
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, fsys)
	if err != nil {
		return 0, fmt.Errorf("init migrations: %w", err)
	}
	results, err := provider.Up(ctx)
	if err != nil {
		return 0, fmt.Errorf("apply migrations: %w", err)
	}
	return len(results), nil
}

// timeLayout matches the strftime format used in the schema defaults, so
// stored timestamps compare correctly as strings.
const timeLayout = "2006-01-02T15:04:05.000Z"

func formatTime(t time.Time) string { return t.UTC().Format(timeLayout) }

// Store provides typed access to the database.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// New wraps an open, migrated database.
func New(db *sql.DB) *Store {
	return &Store{db: db, now: time.Now}
}

// PingContext lets the store serve as a readiness check.
func (s *Store) PingContext(ctx context.Context) error { return s.db.PingContext(ctx) }
