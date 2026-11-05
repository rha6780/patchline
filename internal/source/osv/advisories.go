package osv

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/purl"
	"github.com/rha6780/patchline/internal/store"
)

// Advisories judges fix pull requests with the local OSV mirror, for
// findings of every source: no network, and the ranges OSV records are the
// ones its matches came from.
type Advisories struct {
	DB Candidates
}

func (Advisories) Name() string { return "osv" }

// Verdict looks up the OSV records of the finding's package that name its
// vulnerability (by id or alias). The target version fixes it when no
// record still affects it.
func (a Advisories) Verdict(ctx context.Context, f store.Finding, _ []finding.Ref, to string) (string, string, error) {
	p, err := purl.Parse(f.ComponentRef)
	if err != nil {
		return store.VerdictUnknown, "not a package URL", nil
	}
	eco, pkg := p.OSV()
	if eco == "" {
		return store.VerdictUnknown, "no OSV ecosystem for this package", nil
	}
	cands, err := a.DB.OSVCandidates(ctx, eco, pkg)
	if err != nil {
		return store.VerdictUnknown, "", err
	}
	ids := append([]string{f.VulnID}, f.Aliases...)
	var descs, records []string
	for _, c := range cands {
		if !slices.Contains(ids, c.ID) && !slices.ContainsFunc(c.Aliases, func(a string) bool { return slices.Contains(ids, a) }) {
			continue
		}
		if rng, _, ok := Affects(eco, to, c); ok {
			return store.VerdictInsufficient, fmt.Sprintf("%s is still in the affected range %s (OSV %s)", to, rng, c.ID), nil
		}
		records = append(records, c.ID)
		for _, r := range c.Ranges {
			descs = append(descs, rangeOf(eco, r).String())
		}
	}
	switch {
	case len(records) == 0:
		return store.VerdictUnknown, "no OSV record of this vulnerability for this package", nil
	case len(descs) == 0:
		return store.VerdictFixes, fmt.Sprintf("%s is not among the affected versions (OSV %s)", to, strings.Join(records, ", ")), nil
	}
	return store.VerdictFixes, fmt.Sprintf("%s is outside the affected range %s (OSV %s)", to, strings.Join(descs, "; "), strings.Join(records, ", ")), nil
}
