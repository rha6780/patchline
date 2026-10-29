// Package policy turns a finding's risk signals into an effective severity
// and a remediation due date. The rules are configuration (YAML in Git),
// not code: days per severity, and escalations for CISA KEV, EPSS and
// service exposure.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/rha6780/patchline/internal/finding"
)

// Duration is a time.Duration that also accepts "7d" in YAML.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseDuration(n.Value)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// ParseDuration parses Go durations plus a "d" (day) unit, e.g. "3d", "36h".
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "d") {
		var days float64
		if _, err := fmt.Sscanf(strings.TrimSuffix(s, "d"), "%g", &days); err != nil || days < 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(days * float64(24*time.Hour)), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return d, nil
}

// Policy is the remediation policy.
type Policy struct {
	// SLA is the time allowed to remediate, by effective severity. A
	// severity without an entry has no due date.
	SLA map[string]Duration `yaml:"sla"`
	// Escalation raises (or lowers) the severity used for the SLA.
	Escalation Escalation `yaml:"escalation"`
	// Reminders controls follow-up messages.
	Reminders Reminders `yaml:"reminders"`
}

// Escalation rules.
type Escalation struct {
	// KEV is the severity a finding in CISA's Known Exploited
	// Vulnerabilities catalog is raised to ("" disables).
	KEV string `yaml:"kev"`
	// EPSSThreshold raises the severity one level when the EPSS score is at
	// or above it (0 disables).
	EPSSThreshold float64 `yaml:"epss_threshold"`
	// Exposure adjusts the severity by levels per service exposure,
	// e.g. internet: 1, private: -1.
	Exposure map[string]int `yaml:"exposure"`
}

// Reminders controls reminder timing.
type Reminders struct {
	// DueSoon is how long before the due date to remind once (0 disables).
	DueSoon Duration `yaml:"due_soon"`
	// OverdueEvery repeats a reminder while overdue (0 = once).
	OverdueEvery Duration `yaml:"overdue_every"`
}

// Default is used when no policy file is configured.
func Default() Policy {
	day := Duration(24 * time.Hour)
	return Policy{
		SLA: map[string]Duration{
			finding.SeverityCritical: 7 * day,
			finding.SeverityHigh:     30 * day,
			finding.SeverityMedium:   90 * day,
			finding.SeverityLow:      180 * day,
		},
		Escalation: Escalation{
			KEV:           finding.SeverityCritical,
			EPSSThreshold: 0.5,
			Exposure:      map[string]int{"internet": 1},
		},
		Reminders: Reminders{DueSoon: 3 * day, OverdueEvery: 7 * day},
	}
}

// Load reads a policy file. An empty path returns Default. Fields the file
// leaves out keep their defaults; an explicit empty map clears them.
func Load(path string) (Policy, error) {
	p := Default()
	if path == "" {
		return p, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("policy: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil && !errors.Is(err, io.EOF) {
		return Policy{}, fmt.Errorf("policy %s: %w", path, err)
	}
	// Maps are merged by the decoder; the SLA table in a file replaces the
	// default one so a severity can be left without a due date.
	var only struct {
		SLA map[string]Duration `yaml:"sla"`
	}
	if err := yaml.Unmarshal(data, &only); err == nil && only.SLA != nil {
		p.SLA = only.SLA
	}
	return p, p.Validate()
}

// Validate checks severities and thresholds.
func (p Policy) Validate() error {
	var errs []error
	for sev := range p.SLA {
		if !knownSeverity(sev) {
			errs = append(errs, fmt.Errorf("sla: unknown severity %q", sev))
		}
	}
	if p.Escalation.KEV != "" && !knownSeverity(p.Escalation.KEV) {
		errs = append(errs, fmt.Errorf("escalation.kev: unknown severity %q", p.Escalation.KEV))
	}
	if t := p.Escalation.EPSSThreshold; t < 0 || t > 1 {
		errs = append(errs, fmt.Errorf("escalation.epss_threshold: want 0..1, got %g", t))
	}
	return errors.Join(errs...)
}

// order lists severities from least to most severe.
var order = []string{finding.SeverityInfo, finding.SeverityLow, finding.SeverityMedium, finding.SeverityHigh, finding.SeverityCritical}

func knownSeverity(s string) bool {
	for _, o := range order {
		if o == s {
			return true
		}
	}
	return s == finding.SeverityUnassigned
}

func level(s string) int {
	for i, o := range order {
		if o == s {
			return i
		}
	}
	return -1 // unassigned
}

// Input is what the policy looks at.
type Input struct {
	Severity  string
	KEV       bool
	EPSS      *float64
	Exposure  string
	StartedAt time.Time // when the SLA clock started
}

// Result is the policy's verdict.
type Result struct {
	EffectiveSeverity string
	// Reasons explains the escalation, e.g. "in CISA KEV", "EPSS 0.94".
	Reasons []string
	// Due is zero when the effective severity has no SLA.
	Due time.Time
}

// Evaluate computes the effective severity and due date.
func (p Policy) Evaluate(in Input) Result {
	sev := in.Severity
	var reasons []string

	if l := level(sev); l >= 0 {
		shift := 0
		if in.EPSS != nil && p.Escalation.EPSSThreshold > 0 && *in.EPSS >= p.Escalation.EPSSThreshold {
			shift++
			reasons = append(reasons, fmt.Sprintf("EPSS %.2f", *in.EPSS))
		}
		if d := p.Escalation.Exposure[in.Exposure]; d != 0 {
			shift += d
			reasons = append(reasons, in.Exposure+" exposure")
		}
		if shift != 0 {
			sev = order[clamp(l+shift, 0, len(order)-1)]
		}
	}
	if in.KEV && p.Escalation.KEV != "" && level(p.Escalation.KEV) > level(sev) {
		sev = p.Escalation.KEV
		reasons = append([]string{"in CISA KEV"}, reasons...)
	} else if in.KEV {
		reasons = append([]string{"in CISA KEV"}, reasons...)
	}
	if sev == in.Severity {
		// Signals that did not change the result are still informative,
		// but only report them when they mattered.
		reasons = keepKEV(reasons)
	}

	r := Result{EffectiveSeverity: sev, Reasons: reasons}
	if d, ok := p.SLA[sev]; ok && !in.StartedAt.IsZero() {
		r.Due = in.StartedAt.Add(time.Duration(d))
	}
	return r
}

func keepKEV(reasons []string) []string {
	var out []string
	for _, r := range reasons {
		if r == "in CISA KEV" {
			out = append(out, r)
		}
	}
	return out
}

func clamp(v, lo, hi int) int {
	return max(lo, min(v, hi))
}

// Summary describes the SLA table, e.g. "critical 7d, high 30d".
func (p Policy) Summary() string {
	var parts []string
	for _, s := range order {
		if d, ok := p.SLA[s]; ok {
			parts = append(parts, fmt.Sprintf("%s %s", s, FormatDuration(time.Duration(d))))
		}
	}
	return strings.Join(parts, ", ")
}

// FormatDuration renders whole days as "7d", otherwise Go's format.
func FormatDuration(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	return d.String()
}
