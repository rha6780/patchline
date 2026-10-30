// Package impact answers two questions over the stored SBOM snapshots and
// findings: where is a package used (component search), and what does a
// vulnerability affect (impact analysis), including places whose findings
// were closed.
package impact

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/source/osv"
	"github.com/rha6780/patchline/internal/store"
	"github.com/rha6780/patchline/internal/version"
)

// Store is what the analysis reads.
type Store interface {
	SearchComponents(ctx context.Context, q store.ComponentQuery) ([]store.ComponentUse, error)
	OSVRecordsFor(ctx context.Context, id string) ([]store.OSVRecord, error)
	FindingsForVuln(ctx context.Context, ids []string) ([]store.Finding, error)
}

// Query is a component search.
type Query struct {
	Text      string // purl, name or package substring
	Ecosystem string
	// Version is a constraint such as "< 2.17.0" or ">= 2.0, < 2.17.0";
	// empty matches every version.
	Version string
	Limit   int
}

// ErrBadConstraint means the version constraint could not be read.
var ErrBadConstraint = errors.New("version constraint: want for example \"< 2.17.0\", \">= 2.0, < 2.17.0\" or \"= 2.14.1\"")

// ParseConstraint reads comma-separated comparisons into a range.
func ParseConstraint(s string) (version.Range, error) {
	var r version.Range
	s = strings.TrimSpace(s)
	if s == "" {
		return r, nil
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		var op string
		for _, o := range []string{">=", "<=", "==", ">", "<", "="} {
			if strings.HasPrefix(part, o) {
				op = o
				break
			}
		}
		v := strings.TrimSpace(strings.TrimPrefix(part, op))
		if v == "" || strings.ContainsAny(v, "<>=") {
			return version.Range{}, ErrBadConstraint
		}
		switch op {
		case ">=":
			r.StartIncluding = v
		case ">":
			r.StartExcluding = v
		case "<=":
			r.EndIncluding = v
		case "<":
			r.EndExcluding = v
		case "=", "==", "":
			r.Exact = v
		}
	}
	return r, nil
}

// Search finds where packages are used. The version constraint is applied
// after the text search.
func Search(ctx context.Context, st Store, q Query) ([]store.ComponentUse, error) {
	rng, err := ParseConstraint(q.Version)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(q.Text) == "" && q.Ecosystem == "" {
		return []store.ComponentUse{}, nil
	}
	uses, err := st.SearchComponents(ctx, store.ComponentQuery{Text: q.Text, Ecosystem: q.Ecosystem})
	if err != nil {
		return nil, err
	}
	if q.Version == "" {
		return limit(uses, q.Limit), nil
	}
	out := []store.ComponentUse{}
	for _, u := range uses {
		if u.Version != "" && rng.Contains(strings.TrimPrefix(u.Version, "v")) {
			out = append(out, u)
		}
	}
	return limit(out, q.Limit), nil
}

func limit(uses []store.ComponentUse, n int) []store.ComponentUse {
	if n > 0 && len(uses) > n {
		return uses[:n]
	}
	return uses
}

// Package is an affected package of the vulnerability, with its ranges.
type Package struct {
	Ecosystem string   `json:"ecosystem"`
	Package   string   `json:"package"`
	Ranges    []string `json:"ranges"`
}

// Use is a snapshot containing an affected version.
type Use struct {
	store.ComponentUse
	Advisory string `json:"advisory"`
	Range    string `json:"affected_range"`
	Fixed    string `json:"fixed_version,omitempty"`
	// Finding is the finding of this component in this service and
	// environment, if one exists (it may be closed).
	Finding *store.Finding `json:"finding,omitempty"`
}

// Report is the impact of a vulnerability.
type Report struct {
	ID         string    `json:"id"`
	Aliases    []string  `json:"aliases"`
	Summary    string    `json:"summary,omitempty"`
	Severity   string    `json:"severity,omitempty"`
	Advisories []string  `json:"advisories"` // OSV records found for the id
	Packages   []Package `json:"packages"`
	// Affected are the stored snapshots with an affected version.
	Affected []Use `json:"affected"`
	// Unaffected counts the snapshots that contain an affected package in
	// a version outside every range.
	Unaffected int `json:"unaffected"`
	// Findings are every finding of the vulnerability, from any source,
	// open or closed (Dependency-Track findings appear only here).
	Findings []store.Finding `json:"findings"`
}

// Analyze reports what the vulnerability id (CVE, GHSA, ...) affects.
func Analyze(ctx context.Context, st Store, id string) (Report, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Report{}, errors.New("vulnerability id is required")
	}
	recs, err := st.OSVRecordsFor(ctx, id)
	if err != nil {
		return Report{}, err
	}
	ids := map[string]bool{id: true}
	rep := Report{Advisories: []string{}, Affected: []Use{}}
	sevRank := finding.SeverityRank(finding.SeverityUnassigned) + 1
	type key struct{ eco, pkg string }
	cands := map[key][]store.OSVCandidate{}
	var keys []key
	for _, r := range recs {
		if r.Withdrawn != "" {
			continue
		}
		rep.Advisories = append(rep.Advisories, r.ID)
		ids[r.ID] = true
		for _, a := range r.Aliases {
			ids[a] = true
		}
		if rep.Summary == "" {
			rep.Summary = r.Summary
		}
		if rk := finding.SeverityRank(r.Severity); r.Severity != "" && rk < sevRank {
			rep.Severity, sevRank = r.Severity, rk
		}
		for _, a := range r.Affected {
			k := key{a.Ecosystem, a.Package}
			if _, seen := cands[k]; !seen {
				keys = append(keys, k)
			}
			cands[k] = append(cands[k], store.OSVCandidate{ID: r.ID, Ranges: a.Ranges, Versions: a.Versions})
		}
	}
	var all []string
	for i := range ids {
		all = append(all, i)
	}
	sort.Strings(all)
	// Show the CVE when there is one, like findings do.
	rep.ID, rep.Aliases = finding.CanonicalID(id, all)

	findings, err := st.FindingsForVuln(ctx, all)
	if err != nil {
		return Report{}, err
	}
	rep.Findings = findings
	byPlace := map[string]*store.Finding{}
	for i := range findings {
		f := &findings[i]
		byPlace[f.Service+"\x00"+f.Environment+"\x00"+f.ComponentRef] = f
	}

	for _, k := range keys {
		pkg := Package{Ecosystem: k.eco, Package: k.pkg, Ranges: []string{}}
		for _, c := range cands[k] {
			pkg.Ranges = append(pkg.Ranges, describeRanges(c)...)
		}
		rep.Packages = append(rep.Packages, pkg)

		uses, err := st.SearchComponents(ctx, store.ComponentQuery{Ecosystem: k.eco, Package: k.pkg})
		if err != nil {
			return Report{}, err
		}
		for _, u := range uses {
			hit := false
			for _, c := range cands[k] {
				if rng, fixed, ok := osv.Affects(k.eco, u.Version, c); ok {
					rep.Affected = append(rep.Affected, Use{ComponentUse: u, Advisory: c.ID, Range: rng, Fixed: fixed,
						Finding: byPlace[u.Service+"\x00"+u.Environment+"\x00"+u.PURL]})
					hit = true
					break
				}
			}
			if !hit {
				rep.Unaffected++
			}
		}
	}
	return rep, nil
}

func describeRanges(c store.OSVCandidate) []string {
	var out []string
	for _, r := range c.Ranges {
		vr := version.Range{}
		if r.Introduced != "" && r.Introduced != "0" {
			vr.StartIncluding = r.Introduced
		}
		switch {
		case r.Fixed != "":
			vr.EndExcluding = r.Fixed
		case r.LastAffected != "":
			vr.EndIncluding = r.LastAffected
		}
		out = append(out, vr.String())
	}
	if len(out) == 0 && len(c.Versions) > 0 {
		out = append(out, fmt.Sprintf("%d listed versions", len(c.Versions)))
	}
	return out
}
