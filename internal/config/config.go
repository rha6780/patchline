package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

// Config holds runtime settings. Values come from PATCHLINE_* environment
// variables; every field has a default so the binary runs with no setup.
type Config struct {
	// Addr is the HTTP listen address (PATCHLINE_ADDR).
	Addr string
	// DatabasePath is the SQLite database file (PATCHLINE_DB_PATH).
	DatabasePath string
	// LogLevel is debug, info, warn or error (PATCHLINE_LOG_LEVEL).
	LogLevel slog.Level
	// LogFormat is text or json (PATCHLINE_LOG_FORMAT).
	LogFormat string
	// ShutdownTimeout bounds graceful shutdown (PATCHLINE_SHUTDOWN_TIMEOUT).
	ShutdownTimeout time.Duration
}

// Default returns the configuration used when no variables are set.
func Default() Config {
	return Config{
		Addr:            ":8080",
		DatabasePath:    "data/patchline.db",
		LogLevel:        slog.LevelInfo,
		LogFormat:       "text",
		ShutdownTimeout: 10 * time.Second,
	}
}

// Load reads configuration from the process environment.
func Load() (Config, error) {
	return FromLookup(os.LookupEnv)
}

// FromLookup reads configuration using the given lookup function, which
// makes it testable without touching the real environment.
func FromLookup(lookup func(string) (string, bool)) (Config, error) {
	cfg := Default()

	if v, ok := lookup("PATCHLINE_ADDR"); ok && v != "" {
		cfg.Addr = v
	}
	if v, ok := lookup("PATCHLINE_DB_PATH"); ok && v != "" {
		cfg.DatabasePath = v
	}
	if v, ok := lookup("PATCHLINE_LOG_LEVEL"); ok && v != "" {
		if err := cfg.LogLevel.UnmarshalText([]byte(v)); err != nil {
			return Config{}, fmt.Errorf("PATCHLINE_LOG_LEVEL: %w", err)
		}
	}
	if v, ok := lookup("PATCHLINE_LOG_FORMAT"); ok && v != "" {
		v = strings.ToLower(v)
		if v != "text" && v != "json" {
			return Config{}, fmt.Errorf("PATCHLINE_LOG_FORMAT: want text or json, got %q", v)
		}
		cfg.LogFormat = v
	}
	if v, ok := lookup("PATCHLINE_SHUTDOWN_TIMEOUT"); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("PATCHLINE_SHUTDOWN_TIMEOUT: %w", err)
		}
		cfg.ShutdownTimeout = d
	}

	return cfg, nil
}
