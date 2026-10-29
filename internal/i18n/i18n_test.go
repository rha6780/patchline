package i18n

import "testing"

func TestCatalogsMatch(t *testing.T) {
	for k := range en {
		if _, ok := ko[k]; !ok {
			t.Errorf("ko is missing %q", k)
		}
	}
	for k := range ko {
		if _, ok := en[k]; !ok {
			t.Errorf("ko has %q, which en does not", k)
		}
	}
}

func TestT(t *testing.T) {
	if got := KO.T("dur.days", 3); got != "3일" {
		t.Errorf("ko = %q", got)
	}
	if got := EN.T("due.in", "2026-11-05", "6 days"); got != "due 2026-11-05 (in 6 days)" {
		t.Errorf("en = %q", got)
	}
	if got := Lang("fr").T("state.new"); got != "🆕 New" {
		t.Errorf("fallback = %q", got)
	}
	if got := EN.T("no.such.key"); got != "no.such.key" {
		t.Errorf("missing key = %q", got)
	}
}

func TestNegotiate(t *testing.T) {
	for header, want := range map[string]Lang{
		"":                                 EN,
		"ko-KR,ko;q=0.9,en-US;q=0.8":       KO,
		"en-US,en;q=0.9,ko;q=0.8":          EN,
		"fr-FR,fr;q=0.9,ko;q=0.5,en;q=0.4": KO,
		"de":                               EN,
		"ko;q=0":                           EN,
	} {
		if got := Negotiate(header); got != want {
			t.Errorf("Negotiate(%q) = %s, want %s", header, got, want)
		}
	}
	if l, ok := Parse("KO_kr"); !ok || l != KO {
		t.Error("Parse ko_KR")
	}
}
