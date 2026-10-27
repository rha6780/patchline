package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestOpenAndMigrate(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "sub", "patchline.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	n, err := Migrate(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("expected at least one migration to run")
	}

	// Running again is a no-op.
	if n, err := Migrate(ctx, db); err != nil || n != 0 {
		t.Fatalf("second migrate: n=%d err=%v, want 0 nil", n, err)
	}

	for _, table := range []string{"webhook_inbox", "findings", "finding_events"} {
		var name string
		err := db.QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name)
		if err != nil {
			t.Errorf("table %s missing: %v", table, err)
		}
	}

	var fk int
	if err := db.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
		t.Errorf("foreign_keys = %d (err %v), want 1", fk, err)
	}
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "patchline.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	return New(db)
}
