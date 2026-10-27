package finding

import (
	"reflect"
	"testing"
)

func TestCanonicalID(t *testing.T) {
	tests := []struct {
		primary  string
		aliases  []string
		want     string
		wantRest []string
	}{
		{"CVE-2021-44228", []string{"GHSA-jfh8-c2jp-5v3q"}, "CVE-2021-44228", []string{"GHSA-jfh8-c2jp-5v3q"}},
		{"GHSA-jfh8-c2jp-5v3q", []string{"CVE-2021-44228"}, "CVE-2021-44228", []string{"GHSA-jfh8-c2jp-5v3q"}},
		{"GHSA-aaaa-bbbb-cccc", nil, "GHSA-aaaa-bbbb-cccc", []string{}},
		{"GHSA-x", []string{"CVE-2024-2", "CVE-2024-1", "CVE-2024-2", " "}, "CVE-2024-1", []string{"CVE-2024-2", "GHSA-x"}},
		{"", []string{"OSV-1"}, "OSV-1", []string{}},
	}
	for _, tc := range tests {
		got, rest := CanonicalID(tc.primary, tc.aliases)
		if got != tc.want || !reflect.DeepEqual(rest, tc.wantRest) {
			t.Errorf("CanonicalID(%q, %v) = %q %v, want %q %v", tc.primary, tc.aliases, got, rest, tc.want, tc.wantRest)
		}
	}
}

func TestNormalizeSeverity(t *testing.T) {
	for in, want := range map[string]string{
		"CRITICAL": SeverityCritical, "High": SeverityHigh, " medium ": SeverityMedium,
		"LOW": SeverityLow, "INFO": SeverityInfo, "UNASSIGNED": SeverityUnassigned, "": SeverityUnassigned,
	} {
		if got := NormalizeSeverity(in); got != want {
			t.Errorf("NormalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}
