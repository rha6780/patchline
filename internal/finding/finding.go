package finding

import (
	"sort"
	"strings"
)

// State is a finding's position in the remediation lifecycle.
type State string

const (
	StateNeedsReview          State = "needs_review"
	StateNew                  State = "new"
	StateInProgress           State = "in_progress"
	StateAwaitingVerification State = "awaiting_verification"
	StateResolved             State = "resolved"
	StateNotAffected          State = "not_affected"
	StateRiskAccepted         State = "risk_accepted"
	StateReopened             State = "reopened"
)

// Event kinds recorded in the append-only finding_events log.
const (
	EventDetected        = "detected"
	EventStateChanged    = "state_changed"
	EventSeverityChanged = "severity_changed"
	EventNotified        = "notified"
)

// Severity levels, normalized to lower case.
const (
	SeverityCritical   = "critical"
	SeverityHigh       = "high"
	SeverityMedium     = "medium"
	SeverityLow        = "low"
	SeverityInfo       = "info"
	SeverityUnassigned = "unassigned"
)

// NormalizeSeverity maps a scanner severity (CRITICAL, High, ...) to one of
// the Severity constants.
func NormalizeSeverity(s string) string {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return v
	default:
		return SeverityUnassigned
	}
}

// Observation is one sighting of a vulnerability in a component of a
// service, as reported by a source. Sources produce observations; the
// store turns them into findings.
type Observation struct {
	Service     string // inventory service, or the source project name when unregistered
	Registered  bool   // false when the source project is not in the inventory
	Repository  string
	Environment string // e.g. main, prod

	ComponentRef     string // purl, else cpe, else a synthetic name@version
	ComponentName    string
	ComponentVersion string

	VulnID   string   // canonical id
	Aliases  []string // other ids for the same vulnerability
	Severity string
	Title    string

	// Dependency-Track identifiers, kept for links and later diffing.
	DTProjectUUID       string
	DTComponentUUID     string
	DTVulnerabilityUUID string
}

// CanonicalID picks a stable identifier from a set of ids that refer to the
// same vulnerability: the lowest CVE id if any, otherwise the primary id.
// It returns the canonical id and the remaining ids, sorted and de-duplicated.
func CanonicalID(primary string, aliases []string) (string, []string) {
	set := map[string]struct{}{}
	add := func(id string) {
		if id = strings.TrimSpace(id); id != "" {
			set[id] = struct{}{}
		}
	}
	add(primary)
	for _, a := range aliases {
		add(a)
	}

	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	canonical := strings.TrimSpace(primary)
	for _, id := range ids {
		if strings.HasPrefix(id, "CVE-") {
			canonical = id
			break
		}
	}
	if canonical == "" && len(ids) > 0 {
		canonical = ids[0]
	}

	rest := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != canonical {
			rest = append(rest, id)
		}
	}
	return canonical, rest
}
