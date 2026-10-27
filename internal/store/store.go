package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	_ "github.com/ncruces/go-sqlite3/driver" // registers the "sqlite3" driver
	_ "github.com/ncruces/go-sqlite3/embed"  // bundles the SQLite build (pure Go, no cgo)
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
		"&_pragma=synchronous(NORMAL)"

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
