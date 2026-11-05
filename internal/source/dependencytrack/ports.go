package dependencytrack

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/source"
	"github.com/rha6780/patchline/internal/store"
	"github.com/rha6780/patchline/internal/version"
)

// VulnerabilityFetcher reads a vulnerability's affected version ranges.
// *Client implements it.
type VulnerabilityFetcher interface {
	Vulnerability(ctx context.Context, source, vulnID string) (VulnerabilityDetail, error)
}

// AnalysisWriter records analysis decisions. *Client implements it.
type AnalysisWriter interface {
	SetAnalysis(ctx context.Context, a AnalysisUpdate) error
}

// Verdict judges a fix version with the affected components
// Dependency-Track knows for the finding's vulnerability.
func (a *Adapter) Verdict(ctx context.Context, f store.Finding, refs []finding.Ref, to string) (string, string, error) {
	if a.Vulnerabilities == nil {
		return store.VerdictUnknown, "Dependency-Track API not configured", nil
	}
	for _, ref := range refs {
		if ref.Source != Name || ref.VulnSource == "" || ref.VulnName == "" {
			continue
		}
		v, err := a.Vulnerabilities.Vulnerability(ctx, ref.VulnSource, ref.VulnName)
		if err != nil {
			return store.VerdictUnknown, "", err
		}
		verdict, detail := Judge(f.ComponentRef, to, v)
		return verdict, detail, nil
	}
	return store.VerdictUnknown, "Dependency-Track does not report this finding", nil
}

// Judge compares a target version with a vulnerability's affected ranges
// for the component identified by purl.
func Judge(purl, to string, v VulnerabilityDetail) (verdict, detail string) {
	base := purlBase(purl)
	var ranges []version.Range
	for _, ac := range v.AffectedComponents {
		if !strings.EqualFold(ac.IdentityType, "PURL") || purlBase(ac.Identity) != base {
			continue
		}
		r := version.Range{
			StartIncluding: ac.VersionStartIncluding, StartExcluding: ac.VersionStartExcluding,
			EndIncluding: ac.VersionEndIncluding, EndExcluding: ac.VersionEndExcluding,
		}
		if strings.EqualFold(ac.VersionType, "EXACT") {
			r = version.Range{Exact: ac.Version}
		}
		ranges = append(ranges, r)
	}

	if len(ranges) == 0 {
		// Fall back to a single patched version, when that is all we have.
		pv := strings.TrimSpace(v.PatchedVersions)
		if pv != "" && !strings.ContainsAny(pv, "<>=, ") {
			if version.Compare(to, pv) >= 0 {
				return store.VerdictFixes, fmt.Sprintf("%s ≥ patched version %s", to, pv)
			}
			return store.VerdictInsufficient, fmt.Sprintf("%s < patched version %s", to, pv)
		}
		return store.VerdictUnknown, "no affected version range for this package"
	}

	var descs []string
	for _, r := range ranges {
		if r.Contains(to) {
			return store.VerdictInsufficient, fmt.Sprintf("%s is still in the affected range %s", to, r)
		}
		descs = append(descs, r.String())
	}
	return store.VerdictFixes, fmt.Sprintf("%s is outside the affected range %s", to, strings.Join(descs, "; "))
}

// purlBase strips version, qualifiers and subpath, for comparing purls.
func purlBase(purl string) string {
	s := strings.ToLower(purl)
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '@'); i > strings.IndexByte(s, '/') {
		s = s[:i]
	}
	if u, err := url.PathUnescape(s); err == nil {
		s = u
	}
	return s
}

// Keeps reports whether ref names a Dependency-Track analysis (a project,
// component and vulnerability there).
func (a *Adapter) Keeps(ref finding.Ref) bool {
	return ref.Source == Name && ref.Project != "" && ref.Component != "" && ref.Vuln != ""
}

// Ready reports whether the API is configured for writing analyses.
func (a *Adapter) Ready() bool { return a.Analyses != nil }

// WriteDecision records the decision as the analysis of ref, so it lives
// where Dependency-Track users look. The PROJECT_AUDIT_CHANGE that follows
// is a no-op: the finding is already closed.
func (a *Adapter) WriteDecision(ctx context.Context, ref finding.Ref, d source.Decision) error {
	if a.Analyses == nil {
		return errors.New("dependency-track is not configured (PATCHLINE_DT_URL, PATCHLINE_DT_API_KEY)")
	}
	reason := strings.Join(strings.Fields(d.Reason), " ")
	u := AnalysisUpdate{
		ProjectUUID: ref.Project, ComponentUUID: ref.Component, VulnerabilityUUID: ref.Vuln,
		Justification: "NOT_SET", Response: "NOT_SET", Details: reason,
	}
	what := ""
	switch d.Kind {
	case store.RequestRiskAcceptance:
		u.State, u.Response, u.Suppressed, what = "EXPLOITABLE", "WILL_NOT_FIX", true, "Risk accepted"
	case store.RequestNotAffected:
		u.State, u.Justification, what = "NOT_AFFECTED", strings.ToUpper(d.Justification), "Not affected ("+d.Justification+")"
	case store.RequestFalsePositive:
		u.State, what = "FALSE_POSITIVE", "False positive"
	default:
		return fmt.Errorf("not a decision: %s", d.Kind)
	}
	u.Comment = fmt.Sprintf("%s in Patchline (request #%d): requested by %s, approved by %s. %s",
		what, d.RequestID, d.RequestedBy, d.ApprovedBy, reason)
	return a.Analyses.SetAnalysis(ctx, u)
}

// Link is the project's findings in the Dependency-Track frontend.
func (a *Adapter) Link(ref finding.Ref) (string, string) {
	if a.UIURL == "" || ref.Source != Name || ref.Project == "" {
		return "", ""
	}
	return "Dependency-Track", strings.TrimRight(a.UIURL, "/") + "/projects/" + ref.Project + "/findings"
}
