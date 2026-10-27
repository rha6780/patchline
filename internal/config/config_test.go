package config

import (
	"log/slog"
	"testing"
	"time"
)

func lookupFrom(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func TestFromLookupDefaults(t *testing.T) {
	cfg, err := FromLookup(lookupFrom(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg != Default() {
		t.Fatalf("got %+v, want defaults %+v", cfg, Default())
	}
}

func TestFromLookupOverrides(t *testing.T) {
	cfg, err := FromLookup(lookupFrom(map[string]string{
		"PATCHLINE_ADDR":             "127.0.0.1:9000",
		"PATCHLINE_DB_PATH":          "/var/lib/patchline/db.sqlite",
		"PATCHLINE_LOG_LEVEL":        "debug",
		"PATCHLINE_LOG_FORMAT":       "JSON",
		"PATCHLINE_SHUTDOWN_TIMEOUT": "3s",
		"PATCHLINE_INVENTORY_PATH":   "/etc/patchline/inventory",
		"PATCHLINE_WEBHOOK_TOKEN":    "tok",
		"PATCHLINE_DT_URL":           "http://dt:8080",
		"PATCHLINE_DT_API_KEY":       "key",
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		Addr:            "127.0.0.1:9000",
		DatabasePath:    "/var/lib/patchline/db.sqlite",
		LogLevel:        slog.LevelDebug,
		LogFormat:       "json",
		ShutdownTimeout: 3 * time.Second,

		InventoryPath:         "/etc/patchline/inventory",
		WebhookToken:          "tok",
		DependencyTrackURL:    "http://dt:8080",
		DependencyTrackAPIKey: "key",
	}
	if cfg != want {
		t.Fatalf("got %+v, want %+v", cfg, want)
	}
}

func TestFromLookupInvalid(t *testing.T) {
	for _, tc := range []map[string]string{
		{"PATCHLINE_LOG_LEVEL": "loud"},
		{"PATCHLINE_LOG_FORMAT": "xml"},
		{"PATCHLINE_SHUTDOWN_TIMEOUT": "soon"},
	} {
		if _, err := FromLookup(lookupFrom(tc)); err == nil {
			t.Errorf("%v: expected error", tc)
		}
	}
}

func TestDependencyTrackEnabled(t *testing.T) {
	for _, tc := range []struct {
		url, key string
		want     bool
	}{{"", "", false}, {"http://dt", "", false}, {"", "k", false}, {"http://dt", "k", true}} {
		c := Config{DependencyTrackURL: tc.url, DependencyTrackAPIKey: tc.key}
		if got := c.DependencyTrackEnabled(); got != tc.want {
			t.Errorf("url=%q key=%q: got %v, want %v", tc.url, tc.key, got, tc.want)
		}
	}
}
