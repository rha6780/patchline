package osv

import (
	"context"
	"strings"

	"github.com/rha6780/patchline/internal/purl"
	"github.com/rha6780/patchline/internal/store"
	"github.com/rha6780/patchline/internal/version"
)

// Candidates looks up the OSV records of a package.
type Candidates interface {
	OSVCandidates(ctx context.Context, ecosystem, pkg string) ([]store.OSVCandidate, error)
}

// Match is a vulnerability affecting a component.
type Match struct {
	ID       string
	Aliases  []string
	Summary  string
	Severity string
	// Range is the affected range the version fell into, for evidence:
	// ">= 2.13.0, < 2.15.0" or "= 2.14.1" for an explicit version.
	Range string
	// Fixed is the first fixed version of that range, when known.
	Fixed string
}

// MatchComponent returns the vulnerabilities affecting c.
func MatchComponent(ctx context.Context, db Candidates, c store.Component) ([]Match, error) {
	if c.Ecosystem == "" || c.Package == "" || c.Version == "" {
		return nil, nil
	}
	cands, err := db.OSVCandidates(ctx, c.Ecosystem, c.Package)
	if err != nil {
		return nil, err
	}
	v := normalizeVersion(c.Ecosystem, c.Version)
	var out []Match
	for _, cand := range cands {
		if rng, fixed, ok := affects(c.Ecosystem, v, cand); ok {
			out = append(out, Match{ID: cand.ID, Aliases: cand.Aliases, Summary: cand.Summary,
				Severity: cand.Severity, Range: rng, Fixed: fixed})
		}
	}
	return out, nil
}

// affects reports whether version v is affected: listed explicitly, or
// inside one of the ranges.
func affects(ecosystem, v string, c store.OSVCandidate) (rng, fixed string, ok bool) {
	for _, listed := range c.Versions {
		if normalizeVersion(ecosystem, listed) == v {
			return "= " + listed, fixedFor(ecosystem, v, c.Ranges), true
		}
	}
	for _, r := range c.Ranges {
		vr := version.Range{}
		if r.Introduced != "" && r.Introduced != "0" {
			vr.StartIncluding = normalizeVersion(ecosystem, r.Introduced)
		}
		switch {
		case r.Fixed != "":
			vr.EndExcluding = normalizeVersion(ecosystem, r.Fixed)
		case r.LastAffected != "":
			vr.EndIncluding = normalizeVersion(ecosystem, r.LastAffected)
		}
		if vr.Contains(v) {
			return vr.String(), r.Fixed, true
		}
	}
	return "", "", false
}

func fixedFor(ecosystem, v string, ranges []store.OSVRange) string {
	for _, r := range ranges {
		if r.Fixed != "" && version.Compare(v, normalizeVersion(ecosystem, r.Fixed)) < 0 {
			return r.Fixed
		}
	}
	return ""
}

// normalizeVersion removes the "v" Go module versions carry in purls but
// not in OSV ranges.
func normalizeVersion(ecosystem, v string) string {
	v = strings.TrimSpace(v)
	if ecosystem == purl.Go {
		return strings.TrimPrefix(v, "v")
	}
	return v
}

// Engine matches components against the local OSV mirror.
type Engine struct {
	DB     Candidates
	Syncer *Syncer
}

// Ready reports whether every configured ecosystem has been synced.
func (e Engine) Ready(ctx context.Context) (bool, error) { return e.Syncer.Ready(ctx) }

// Match returns the vulnerabilities affecting c.
func (e Engine) Match(ctx context.Context, c store.Component) ([]Match, error) {
	return MatchComponent(ctx, e.DB, c)
}
