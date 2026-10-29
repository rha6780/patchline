package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func f(v float64) *float64 { return &v }

func TestEvaluate(t *testing.T) {
	p := Default()
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		in      Input
		sev     string
		reasons []string
		days    int // 0 = no due
	}{
		{"plain high", Input{Severity: "high"}, "high", nil, 30},
		{"internet raises", Input{Severity: "medium", Exposure: "internet"}, "high", []string{"internet exposure"}, 30},
		{"epss raises", Input{Severity: "high", EPSS: f(0.94)}, "critical", []string{"EPSS 0.94"}, 7},
		{"low epss ignored", Input{Severity: "high", EPSS: f(0.01)}, "high", nil, 30},
		{"kev to critical", Input{Severity: "medium", KEV: true}, "critical", []string{"in CISA KEV"}, 7},
		{"kev already critical", Input{Severity: "critical", KEV: true}, "critical", []string{"in CISA KEV"}, 7},
		{"capped at critical", Input{Severity: "critical", EPSS: f(0.9), Exposure: "internet"}, "critical", nil, 7},
		{"info has no sla", Input{Severity: "info"}, "info", nil, 0},
		{"unassigned no sla", Input{Severity: "unassigned"}, "unassigned", nil, 0},
		{"unassigned kev", Input{Severity: "unassigned", KEV: true}, "critical", []string{"in CISA KEV"}, 7},
	}
	for _, tc := range tests {
		tc.in.StartedAt = start
		r := p.Evaluate(tc.in)
		if r.EffectiveSeverity != tc.sev || !reflect.DeepEqual(r.Reasons, tc.reasons) {
			t.Errorf("%s: got %s %v, want %s %v", tc.name, r.EffectiveSeverity, r.Reasons, tc.sev, tc.reasons)
		}
		want := time.Time{}
		if tc.days > 0 {
			want = start.AddDate(0, 0, tc.days)
		}
		if !r.Due.Equal(want) {
			t.Errorf("%s: due %v, want %v", tc.name, r.Due, want)
		}
	}
	// Private exposure can lower.
	p.Escalation.Exposure["private"] = -1
	if r := p.Evaluate(Input{Severity: "medium", Exposure: "private", StartedAt: start}); r.EffectiveSeverity != "low" {
		t.Errorf("private: %s", r.EffectiveSeverity)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	_ = os.WriteFile(path, []byte("sla:\n  critical: 3d\n  high: 36h\nescalation:\n  epss_threshold: 0.7\nreminders:\n  due_soon: 1d\n"), 0o600)
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(p.SLA["critical"]) != 72*time.Hour || time.Duration(p.SLA["high"]) != 36*time.Hour {
		t.Errorf("sla = %v", p.SLA)
	}
	if _, ok := p.SLA["medium"]; ok {
		t.Error("a file's sla map replaces the default one")
	}
	if p.Escalation.EPSSThreshold != 0.7 || p.Escalation.KEV != "critical" {
		t.Errorf("escalation = %+v (kev default should remain)", p.Escalation)
	}
	if time.Duration(p.Reminders.DueSoon) != 24*time.Hour || time.Duration(p.Reminders.OverdueEvery) != 7*24*time.Hour {
		t.Errorf("reminders = %+v", p.Reminders)
	}

	for name, body := range map[string]string{
		"unknown field":    "slas: {}\n",
		"bad severity":     "sla:\n  urgent: 1d\n",
		"bad duration":     "sla:\n  high: soon\n",
		"bad threshold":    "escalation:\n  epss_threshold: 2\n",
		"bad kev severity": "escalation:\n  kev: top\n",
	} {
		_ = os.WriteFile(path, []byte(body), 0o600)
		if _, err := Load(path); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if p, err := Load(""); err != nil || p.Summary() != "low 180d, medium 90d, high 30d, critical 7d" {
		t.Errorf("default: %q %v", p.Summary(), err)
	}
}
