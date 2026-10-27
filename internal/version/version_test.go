package version

import "testing"

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.10.0", "1.9.0", 1},
		{"2.17.1", "2.17.1", 0},
		{"v1.2.3", "1.2.3", 0},
		{"1.0", "1.0.0", 0},
		{"1.0.1", "1.0", 1},
		{"6.1.0-RC1", "6.1.0", -1},
		{"6.1.0.RELEASE", "6.1.0", 0},
		{"2.0.0-alpha", "2.0.0-beta", -1},
		{"2.0.0-beta.2", "2.0.0-beta.11", -1},
		{"2.0.0-rc.1", "2.0.0", -1},
		{"1.0-SNAPSHOT", "1.0", -1},
		{"2.0.post1", "2.0", 1},
		{"1.0.0+build.5", "1.0.0", 0},
		{"2.9.10.1", "2.9.10", 1},
		{"2.15.4", "2.9.10.1", 1},
		{"4.17.21", "4.17.15", 1},
		{"1:1.2", "1.2", 0},
	}
	for _, tc := range tests {
		if got := Compare(tc.a, tc.b); got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		if got := Compare(tc.b, tc.a); got != -tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d (antisymmetry)", tc.b, tc.a, got, -tc.want)
		}
	}
}

func TestRange(t *testing.T) {
	log4shell := Range{StartIncluding: "2.0-beta9", EndExcluding: "2.15.0"}
	for v, want := range map[string]bool{"2.14.1": true, "2.0-beta9": true, "2.0-beta8": false, "2.15.0": false, "2.17.1": false} {
		if got := log4shell.Contains(v); got != want {
			t.Errorf("%s in %s = %v, want %v", v, log4shell, got, want)
		}
	}
	if !(Range{Exact: "1.4"}).Contains("1.4") || (Range{Exact: "1.4"}).Contains("1.5") {
		t.Error("exact range")
	}
	if !(Range{}).Contains("anything") || (Range{}).String() != "all versions" {
		t.Error("open range")
	}
	r := Range{StartExcluding: "1.0", EndIncluding: "1.5"}
	if r.Contains("1.0") || !r.Contains("1.5") || r.String() != "> 1.0, <= 1.5" {
		t.Errorf("bounds: %s", r)
	}
}
