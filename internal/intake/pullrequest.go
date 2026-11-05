package intake

import (
	"context"
	"net/url"
	"strings"

	"github.com/rha6780/patchline/internal/source/gitea"
	"github.com/rha6780/patchline/internal/store"
)

// SourceGitea is the inbox source name for Gitea / Forgejo / GitHub webhooks.
const SourceGitea = "gitea"

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

// judge decides whether version to leaves the finding's vulnerable range.
// The sources' advisories are asked in order (the local OSV mirror first);
// the first that knows the ranges decides.
func (p *Processor) judge(ctx context.Context, f store.Finding, to string) (verdict, detail string) {
	refs, err := p.Store.FindingRefs(ctx, f.ID)
	if err != nil {
		p.Logger.Warn("could not read finding refs", "finding", f.ID, "err", err)
	}
	for _, a := range p.Sources.Advisories() {
		v, d, err := a.Verdict(ctx, f, refs, to)
		if err != nil {
			p.Logger.Warn("could not read vulnerability ranges", "finding", f.ID, "vuln", f.VulnID, "source", a.Name(), "err", err)
			continue
		}
		if v != store.VerdictUnknown {
			return v, d
		}
	}
	return store.VerdictUnknown, "vulnerability ranges not available"
}
