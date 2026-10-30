// Package detect is the interface between Patchline's own detection and
// the engines that match SBOM components against vulnerability data: the
// built-in OSV mirror and, optionally, a Trivy server.
package detect

import (
	"context"
	"errors"

	"github.com/rha6780/patchline/internal/store"
)

// Match is a vulnerability affecting a component.
type Match struct {
	ID       string
	Aliases  []string
	Summary  string
	Severity string
	// Range is the affected range the version fell into, for evidence:
	// ">= 2.13.0, < 2.15.0", "= 2.14.1", or "< 1.1.1w-0+deb11u2".
	Range string
	// Fixed is the first fixed version, when known.
	Fixed string
	// Engine names the engine that found it ("osv", "trivy").
	Engine string
}

// Engine matches the components of one snapshot.
type Engine interface {
	// Ready reports whether the engine's data is complete enough that a
	// component without matches can count as fixed.
	Ready(ctx context.Context) (bool, error)
	// MatchAll returns the matches by component purl.
	MatchAll(ctx context.Context, components []store.Component) (map[string][]Match, error)
}

// Combined runs several engines and merges their matches; a vulnerability
// found by two engines for the same component is reported once (by the
// first engine).
type Combined []Engine

// Ready reports whether every engine is ready.
func (c Combined) Ready(ctx context.Context) (bool, error) {
	for _, e := range c {
		ok, err := e.Ready(ctx)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

// MatchAll asks every engine. One failing engine fails the analysis, so a
// snapshot is never half analyzed (and nothing is resolved by mistake).
func (c Combined) MatchAll(ctx context.Context, components []store.Component) (map[string][]Match, error) {
	out := map[string][]Match{}
	seen := map[string]map[string]bool{}
	var errs []error
	for _, e := range c {
		m, err := e.MatchAll(ctx, components)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for purl, ms := range m {
			if seen[purl] == nil {
				seen[purl] = map[string]bool{}
			}
			for _, x := range ms {
				ids := append([]string{x.ID}, x.Aliases...)
				dup := false
				for _, id := range ids {
					dup = dup || seen[purl][id]
				}
				if dup {
					continue
				}
				for _, id := range ids {
					seen[purl][id] = true
				}
				out[purl] = append(out[purl], x)
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return out, nil
}
