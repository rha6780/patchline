package osv

import (
	"context"
	"strings"

	"github.com/rha6780/patchline/internal/detect"
	"github.com/rha6780/patchline/internal/purl"
	"github.com/rha6780/patchline/internal/store"
	"github.com/rha6780/patchline/internal/version"
)

// Candidates looks up the OSV records of a package.
type Candidates interface {
	OSVCandidates(ctx context.Context, ecosystem, pkg string) ([]store.OSVCandidate, error)
}

// Match is a vulnerability affecting a component.
type Match = detect.Match

// MatchComponent returns the vulnerabilities affecting c.
func MatchComponent(ctx context.Context, db Candidates, c store.Component) ([]Match, error) {
	if c.Ecosystem == "" || c.Package == "" || c.Version == "" {
		return nil, nil
	}
	cands, err := db.OSVCandidates(ctx, c.Ecosystem, c.Package)
	if err != nil {
		return nil, err
	}
	var out []Match
	for _, cand := range cands {
		if rng, fixed, ok := Affects(c.Ecosystem, c.Version, cand); ok {
			out = append(out, Match{ID: cand.ID, Aliases: cand.Aliases, Summary: cand.Summary,
				Severity: cand.Severity, Range: rng, Fixed: fixed, Engine: "osv"})
		}
	}
	return out, nil
}

// Affects reports whether version v of a package is affected by the
// candidate: inside one of its ranges, or listed explicitly. It returns the
// range that matched (the listed version when no range did) and the first
// fixed version after v, when known.
func Affects(ecosystem, v string, c store.OSVCandidate) (rng, fixed string, ok bool) {
	v = normalizeVersion(ecosystem, v)
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
	// Some records list versions their ranges do not express (for example
	// ranges the comparison cannot read); the list counts too.
	for _, listed := range c.Versions {
		if normalizeVersion(ecosystem, listed) == v {
			return "= " + listed, fixedFor(ecosystem, v, c.Ranges), true
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

// MatchAll matches each component with an OSV ecosystem.
func (e Engine) MatchAll(ctx context.Context, comps []store.Component) (map[string][]Match, error) {
	out := map[string][]Match{}
	for _, c := range comps {
		ms, err := MatchComponent(ctx, e.DB, c)
		if err != nil {
			return nil, err
		}
		if len(ms) > 0 {
			out[c.PURL] = ms
		}
	}
	return out, nil
}
