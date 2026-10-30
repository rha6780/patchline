// Package osv mirrors OSV vulnerability data (https://osv.dev) and matches
// SBOM components against it, so Patchline can detect vulnerabilities in
// the SBOMs uploaded to it without Dependency-Track.
package osv

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/purl"
	"github.com/rha6780/patchline/internal/store"
)

// record is the part of the OSV schema Patchline reads.
type record struct {
	ID        string   `json:"id"`
	Modified  string   `json:"modified"`
	Withdrawn string   `json:"withdrawn"`
	Aliases   []string `json:"aliases"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
			} `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
}

// Parse reads one OSV JSON record. Affected packages of other ecosystems
// (and Git ranges, which need a repository) are dropped; ecosystem is the
// export the record came from.
func Parse(data []byte, ecosystem string) (store.OSVRecord, error) {
	var r record
	if err := json.Unmarshal(data, &r); err != nil {
		return store.OSVRecord{}, fmt.Errorf("osv: %w", err)
	}
	if r.ID == "" {
		return store.OSVRecord{}, fmt.Errorf("osv: record without id")
	}
	out := store.OSVRecord{
		ID: r.ID, Ecosystem: ecosystem, Modified: r.Modified, Withdrawn: r.Withdrawn,
		Aliases: r.Aliases, Summary: firstLine(r.Summary, r.Details), Severity: severityOf(r),
	}
	for _, a := range r.Affected {
		// "Debian:11" style ecosystems carry a release; Patchline matches the base.
		eco, _, _ := strings.Cut(a.Package.Ecosystem, ":")
		if eco != ecosystem {
			continue
		}
		aff := store.OSVAffected{Ecosystem: eco, Package: purl.Normalize(eco, a.Package.Name), Versions: a.Versions}
		for _, rg := range a.Ranges {
			if rg.Type != "ECOSYSTEM" && rg.Type != "SEMVER" {
				continue
			}
			// Events are ordered: introduced opens an interval, fixed or
			// last_affected closes it.
			var cur *store.OSVRange
			for _, e := range rg.Events {
				switch {
				case e.Introduced != "":
					if cur != nil {
						aff.Ranges = append(aff.Ranges, *cur)
					}
					cur = &store.OSVRange{Introduced: e.Introduced}
				case e.Fixed != "" || e.LastAffected != "":
					if cur == nil {
						cur = &store.OSVRange{Introduced: "0"}
					}
					cur.Fixed, cur.LastAffected = e.Fixed, e.LastAffected
					aff.Ranges = append(aff.Ranges, *cur)
					cur = nil
				}
			}
			if cur != nil {
				aff.Ranges = append(aff.Ranges, *cur)
			}
		}
		if len(aff.Ranges) > 0 || len(aff.Versions) > 0 {
			out.Affected = append(out.Affected, aff)
		}
	}
	return out, nil
}

// severityOf prefers the curated severity (GitHub advisories: LOW,
// MODERATE, HIGH, CRITICAL), then the CVSS v3 base score.
func severityOf(r record) string {
	switch strings.ToUpper(r.DatabaseSpecific.Severity) {
	case "CRITICAL":
		return finding.SeverityCritical
	case "HIGH":
		return finding.SeverityHigh
	case "MODERATE", "MEDIUM":
		return finding.SeverityMedium
	case "LOW":
		return finding.SeverityLow
	}
	for _, s := range r.Severity {
		if s.Type == "CVSS_V3" {
			if score, err := CVSS3BaseScore(s.Score); err == nil {
				return SeverityForScore(score)
			}
		}
	}
	return finding.SeverityUnassigned
}

// SeverityForScore maps a CVSS score to a severity (CVSS v3 ratings).
func SeverityForScore(score float64) string {
	switch {
	case score >= 9:
		return finding.SeverityCritical
	case score >= 7:
		return finding.SeverityHigh
	case score >= 4:
		return finding.SeverityMedium
	case score > 0:
		return finding.SeverityLow
	}
	return finding.SeverityInfo
}

func firstLine(summary, details string) string {
	s := strings.TrimSpace(summary)
	if s == "" {
		s, _, _ = strings.Cut(strings.TrimSpace(details), "\n")
	}
	if r := []rune(s); len(r) > 300 {
		s = string(r[:299]) + "…"
	}
	return s
}
