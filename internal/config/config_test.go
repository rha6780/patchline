package config

import (
	"log/slog"
	"reflect"
	"strings"
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
	if !reflect.DeepEqual(cfg, Default()) {
		t.Fatalf("got %+v, want defaults %+v", cfg, Default())
	}
}

func TestFromLookupOverrides(t *testing.T) {
	cfg, err := FromLookup(lookupFrom(map[string]string{
		"PATCHLINE_ADDR":                  "127.0.0.1:9000",
		"PATCHLINE_DB_PATH":               "/var/lib/patchline/db.sqlite",
		"PATCHLINE_LOG_LEVEL":             "debug",
		"PATCHLINE_LOG_FORMAT":            "JSON",
		"PATCHLINE_SHUTDOWN_TIMEOUT":      "3s",
		"PATCHLINE_INVENTORY_PATH":        "/etc/patchline/inventory",
		"PATCHLINE_WEBHOOK_TOKEN":         "tok",
		"PATCHLINE_DT_URL":                "http://dt:8080",
		"PATCHLINE_DT_API_KEY":            "key",
		"PATCHLINE_DT_UI_URL":             "http://localhost:18082",
		"PATCHLINE_DT_RECONCILE_DELAY":    "30s",
		"PATCHLINE_GITEA_WEBHOOK_SECRET":  "gsec",
		"PATCHLINE_POLICY_PATH":           "/etc/patchline/policy.yaml",
		"PATCHLINE_KEV_URL":               "off",
		"PATCHLINE_SLACK_BOT_TOKEN":       "xoxb-1",
		"PATCHLINE_SLACK_DEFAULT_CHANNEL": "#security",
		"PATCHLINE_NOTIFY_MIN_SEVERITY":   "HIGH",
		"PATCHLINE_NOTIFY_LANG":           "KO",
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

		InventoryPath:                 "/etc/patchline/inventory",
		WebhookToken:                  "tok",
		DependencyTrackURL:            "http://dt:8080",
		DependencyTrackAPIKey:         "key",
		DependencyTrackUIURL:          "http://localhost:18082",
		DependencyTrackReconcileDelay: 30 * time.Second,

		GiteaWebhookSecret:  "gsec",
		PolicyPath:          "/etc/patchline/policy.yaml",
		KEVURL:              "",
		SlackBotToken:       "xoxb-1",
		SlackDefaultChannel: "#security",
		NotifyMinSeverity:   "high",
		NotifyLang:          "ko",
	}
	d := Default()
	want.OIDCScopes, want.OIDCGroupsClaims, want.SessionTTL, want.LocalAdmin = d.OIDCScopes, d.OIDCGroupsClaims, d.SessionTTL, d.LocalAdmin
	want.OSVEcosystems, want.OSVURL, want.OSVRefresh = d.OSVEcosystems, d.OSVURL, d.OSVRefresh
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("got %+v, want %+v", cfg, want)
	}
}

func TestFromLookupInvalid(t *testing.T) {
	for _, tc := range []map[string]string{
		{"PATCHLINE_LOG_LEVEL": "loud"},
		{"PATCHLINE_LOG_FORMAT": "xml"},
		{"PATCHLINE_SHUTDOWN_TIMEOUT": "soon"},
		{"PATCHLINE_NOTIFY_MIN_SEVERITY": "urgent"},
		{"PATCHLINE_NOTIFY_LANG": "fr"},
		{"PATCHLINE_DT_RECONCILE_DELAY": "-1m"},
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

func TestOIDC(t *testing.T) {
	cfg, err := FromLookup(lookupFrom(map[string]string{
		"PATCHLINE_OIDC_ISSUER":       "https://id.example.com",
		"PATCHLINE_OIDC_CLIENT_ID":    "patchline",
		"PATCHLINE_PUBLIC_URL":        "https://patchline.example.com",
		"PATCHLINE_OIDC_GROUPS_CLAIM": "groups, roles",
		"PATCHLINE_OIDC_SCOPES":       "profile email groups",
		"PATCHLINE_SESSION_TTL":       "8h",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.OIDCEnabled() || cfg.SessionTTL != 8*time.Hour ||
		!reflect.DeepEqual(cfg.OIDCGroupsClaims, []string{"groups", "roles"}) ||
		!reflect.DeepEqual(cfg.OIDCScopes, []string{"profile", "email", "groups"}) {
		t.Fatalf("got %+v", cfg)
	}

	for name, env := range map[string]map[string]string{
		"client id":  {"PATCHLINE_OIDC_ISSUER": "https://id", "PATCHLINE_PUBLIC_URL": "https://p"},
		"public url": {"PATCHLINE_OIDC_ISSUER": "https://id", "PATCHLINE_OIDC_CLIENT_ID": "c"},
		"ttl":        {"PATCHLINE_SESSION_TTL": "forever"},
		"nobody":     {"PATCHLINE_LOCAL_ADMIN": "false"},
	} {
		if _, err := FromLookup(lookupFrom(env)); err == nil {
			t.Errorf("%s: want an error", name)
		} else if (name == "client id" || name == "public url") && !strings.Contains(err.Error(), "required") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestOSVSettings(t *testing.T) {
	cfg, err := FromLookup(lookupFrom(map[string]string{"PATCHLINE_OSV_ECOSYSTEMS": "maven, PyPI,crates.io", "PATCHLINE_OSV_REFRESH": "12h"}))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.OSVEcosystems, []string{"Maven", "PyPI", "crates.io"}) || cfg.OSVRefresh != 12*time.Hour {
		t.Fatalf("got %v %v", cfg.OSVEcosystems, cfg.OSVRefresh)
	}
	if cfg, _ := FromLookup(lookupFrom(map[string]string{"PATCHLINE_OSV_ECOSYSTEMS": "off"})); len(cfg.OSVEcosystems) != 0 {
		t.Errorf("off = %v", cfg.OSVEcosystems)
	}
	for _, v := range []map[string]string{{"PATCHLINE_OSV_ECOSYSTEMS": "Debian"}, {"PATCHLINE_OSV_REFRESH": "1s"}} {
		if _, err := FromLookup(lookupFrom(v)); err == nil {
			t.Errorf("%v: want an error", v)
		}
	}
}

func TestTrivySettings(t *testing.T) {
	cfg, err := FromLookup(lookupFrom(map[string]string{"PATCHLINE_TRIVY_URL": "http://trivy:8080", "PATCHLINE_TRIVY_TOKEN": "t", "PATCHLINE_TRIVY_SCOPE": "ALL"}))
	if err != nil || cfg.TrivyURL != "http://trivy:8080" || cfg.TrivyToken != "t" || !cfg.TrivyAll {
		t.Fatalf("got %+v, %v", cfg, err)
	}
	if _, err := FromLookup(lookupFrom(map[string]string{"PATCHLINE_TRIVY_SCOPE": "images"})); err == nil {
		t.Error("bad scope accepted")
	}
}
