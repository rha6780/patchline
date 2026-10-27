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

	// InventoryPath is a YAML file or a directory of YAML files
	// (PATCHLINE_INVENTORY_PATH). Empty means no inventory.
	InventoryPath string
	// WebhookToken is the shared secret webhook senders must present
	// (PATCHLINE_WEBHOOK_TOKEN). Empty disables the check.
	WebhookToken string
	// DependencyTrackURL is the Dependency-Track API server base URL
	// (PATCHLINE_DT_URL). Empty disables fetching findings on BOM_PROCESSED.
	DependencyTrackURL string
	// DependencyTrackAPIKey authenticates to Dependency-Track (PATCHLINE_DT_API_KEY).
	DependencyTrackAPIKey string
	// DependencyTrackReconcileDelay is how long to wait after BOM_PROCESSED
	// before reading a project's findings and resolving the ones that
	// disappeared (PATCHLINE_DT_RECONCILE_DELAY).
	DependencyTrackReconcileDelay time.Duration
	// DependencyTrackUIURL is the browser URL of the Dependency-Track
	// frontend, used for links in messages (PATCHLINE_DT_UI_URL).
	DependencyTrackUIURL string

	// GiteaWebhookSecret is the secret set on the Gitea / Forgejo / GitHub
	// webhook; requests must carry its HMAC signature
	// (PATCHLINE_GITEA_WEBHOOK_SECRET). Empty falls back to WebhookToken.
	GiteaWebhookSecret string

	// SlackBotToken enables the Slack sink (PATCHLINE_SLACK_BOT_TOKEN).
	// Without it notifications are printed to stdout.
	SlackBotToken string
	// SlackDefaultChannel receives findings whose service has no
	// slack_channel (PATCHLINE_SLACK_DEFAULT_CHANNEL).
	SlackDefaultChannel string
	// NotifyMinSeverity is the lowest severity that is posted
	// (PATCHLINE_NOTIFY_MIN_SEVERITY): critical, high, medium, low, info.
	NotifyMinSeverity string
}

// DependencyTrackEnabled reports whether findings can be fetched from the
// Dependency-Track API (both URL and API key are set).
func (c Config) DependencyTrackEnabled() bool {
	return c.DependencyTrackURL != "" && c.DependencyTrackAPIKey != ""
}

// Default returns the configuration used when no variables are set.
func Default() Config {
	return Config{
		Addr:            ":8080",
		DatabasePath:    "data/patchline.db",
		LogLevel:        slog.LevelInfo,
		LogFormat:       "text",
		ShutdownTimeout: 10 * time.Second,

		NotifyMinSeverity:             "medium",
		DependencyTrackReconcileDelay: 2 * time.Minute,
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

	cfg.InventoryPath, _ = lookup("PATCHLINE_INVENTORY_PATH")
	cfg.WebhookToken, _ = lookup("PATCHLINE_WEBHOOK_TOKEN")
	cfg.DependencyTrackURL, _ = lookup("PATCHLINE_DT_URL")
	cfg.DependencyTrackAPIKey, _ = lookup("PATCHLINE_DT_API_KEY")
	cfg.DependencyTrackUIURL, _ = lookup("PATCHLINE_DT_UI_URL")
	if v, ok := lookup("PATCHLINE_DT_RECONCILE_DELAY"); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return Config{}, fmt.Errorf("PATCHLINE_DT_RECONCILE_DELAY: want a positive duration such as 2m, got %q", v)
		}
		cfg.DependencyTrackReconcileDelay = d
	}
	cfg.GiteaWebhookSecret, _ = lookup("PATCHLINE_GITEA_WEBHOOK_SECRET")
	cfg.SlackBotToken, _ = lookup("PATCHLINE_SLACK_BOT_TOKEN")
	cfg.SlackDefaultChannel, _ = lookup("PATCHLINE_SLACK_DEFAULT_CHANNEL")
	if v, ok := lookup("PATCHLINE_NOTIFY_MIN_SEVERITY"); ok && v != "" {
		v = strings.ToLower(v)
		switch v {
		case "critical", "high", "medium", "low", "info":
			cfg.NotifyMinSeverity = v
		default:
			return Config{}, fmt.Errorf("PATCHLINE_NOTIFY_MIN_SEVERITY: want critical, high, medium, low or info, got %q", v)
		}
	}
	return cfg, nil
}
