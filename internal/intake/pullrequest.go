package intake

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/rha6780/patchline/internal/source/dependencytrack"
	"github.com/rha6780/patchline/internal/source/gitea"
	"github.com/rha6780/patchline/internal/store"
	"github.com/rha6780/patchline/internal/version"
)

// SourceGitea is the inbox source name for Gitea / Forgejo / GitHub webhooks.
const SourceGitea = "gitea"

// VulnerabilityFetcher reads a vulnerability's affected version ranges.
// The Dependency-Track client implements it.
type VulnerabilityFetcher interface {
	Vulnerability(ctx context.Context, source, vulnID string) (dependencytrack.VulnerabilityDetail, error)
}

func (p *Processor) handleGitea(ctx context.Context, it store.InboxItem) (string, error) {
	if it.EventType != gitea.EventPullRequest {
		return "ignored: event " + it.EventType, nil
	}
	ev, err := gitea.ParsePullRequestEvent(it.Payload)
	if err != nil {
		return "", err
	}
	outcome := ev.Outcome()
	if outcome == gitea.OutcomeIgnore {
		return "ignored: action " + ev.Action, nil
	}
	pr := ev.PullRequest
	repo := ev.Repository.FullName

	changed := 0
	// Link on open, and also on merge in case the opening was never seen.
	if outcome == gitea.OutcomeOpen || outcome == gitea.OutcomeMerged {
		n, err := p.linkPullRequest(ctx, repo, pr)
		if err != nil {
			return "", err
		}
		changed += n
	}
	if outcome == gitea.OutcomeMerged || outcome == gitea.OutcomeClosed {
		ids, err := p.Store.ClosePullRequest(ctx, repo, pr.Number, outcome == gitea.OutcomeMerged, pr.MergeCommitSHA)
		if err != nil {
			return "", err
		}
		changed += len(ids)
	}

	p.Logger.Info("pull request processed", "id", it.ID, "repository", repo, "number", pr.Number,
		"outcome", outcome, "findings_changed", changed)
	if changed == 0 {
		return "no matching findings", nil
	}
	p.OnChange()
	return "", nil
}

// linkPullRequest links the pull request to the open findings whose
// component it updates. Findings are matched in the repository's
// environment named after the base branch (and "default").
func (p *Processor) linkPullRequest(ctx context.Context, repo string, pr gitea.PullRequest) (int, error) {
	updates := gitea.RenovateUpdates(pr)
	if len(updates) == 0 {
		return 0, nil
	}
	envs := []string{DefaultEnvironment}
	if pr.Base.Ref != "" {
		envs = append(envs, pr.Base.Ref)
	}
	findings, err := p.Store.OpenFindingsInRepository(ctx, repo, envs)
	if err != nil {
		return 0, err
	}

	changed := 0
	for _, f := range findings {
		for _, u := range updates {
			if !packageMatches(f, u.Package) {
				continue
			}
			verdict, detail := p.judge(ctx, f, u.To)
			ok, err := p.Store.LinkPullRequest(ctx, store.PullRequestLink{
				FindingID: f.ID, Repository: repo, Number: pr.Number, URL: pr.HTMLURL, Title: pr.Title,
				Package: u.Package, FromVersion: u.From, ToVersion: u.To,
				Verdict: verdict, VerdictDetail: detail, HeadSHA: pr.Head.SHA,
			})
			if err != nil {
				return changed, err
			}
			if ok {
				changed++
				p.Logger.Info("pull request linked", "finding", f.ID, "repository", repo, "number", pr.Number,
					"package", u.Package, "to", u.To, "verdict", verdict)
			}
			break
		}
	}
	return changed, nil
}

// packageMatches compares a Renovate package name with the finding's
// component (group/name or the purl's namespace/name).
func packageMatches(f store.Finding, pkg string) bool {
	want := gitea.NormalizePackage(pkg)
	if want == "" {
		return false
	}
	if gitea.NormalizePackage(f.ComponentName) == want {
		return true
	}
	return purlName(f.ComponentRef) == want
}

// purlName returns "namespace/name" (or "name") of a purl, lowercased.
func purlName(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	s := strings.TrimPrefix(purl, "pkg:")
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 { // drop the type
		s = s[i+1:]
	}
	if u, err := url.PathUnescape(s); err == nil {
		s = u
	}
	return strings.ToLower(s)
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

// judge decides whether version to leaves the finding's vulnerable range,
// using the affected components Dependency-Track knows for it.
func (p *Processor) judge(ctx context.Context, f store.Finding, to string) (verdict, detail string) {
	vf, ok := p.DT.(VulnerabilityFetcher)
	if !ok || p.DT == nil || f.DTVulnSource == "" || f.DTVulnID == "" {
		return store.VerdictUnknown, "vulnerability ranges not available"
	}
	v, err := vf.Vulnerability(ctx, f.DTVulnSource, f.DTVulnID)
	if err != nil {
		p.Logger.Warn("could not read vulnerability ranges", "finding", f.ID, "vuln", f.DTVulnID, "err", err)
		return store.VerdictUnknown, "vulnerability ranges not available"
	}
	return Judge(f.ComponentRef, to, v)
}

// Judge compares a target version with a vulnerability's affected ranges
// for the component identified by purl.
func Judge(purl, to string, v dependencytrack.VulnerabilityDetail) (verdict, detail string) {
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
