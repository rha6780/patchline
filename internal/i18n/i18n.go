// Package i18n holds Patchline's user-facing text in English and Korean.
package i18n

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Lang is a supported language.
type Lang string

const (
	EN Lang = "en"
	KO Lang = "ko"
)

// Default is used when nothing else decides.
const Default = EN

// Supported lists the languages in display order.
var Supported = []Lang{EN, KO}

// Name is the language's own name.
func (l Lang) Name() string {
	if l == KO {
		return "한국어"
	}
	return "English"
}

// Parse accepts "en", "ko" and regional forms such as "ko-KR".
func Parse(s string) (Lang, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexAny(s, "-_"); i > 0 {
		s = s[:i]
	}
	for _, l := range Supported {
		if string(l) == s {
			return l, true
		}
	}
	return "", false
}

// Negotiate picks the best supported language from an Accept-Language
// header, or Default.
func Negotiate(header string) Lang {
	type cand struct {
		lang Lang
		q    float64
		pos  int
	}
	var cs []cand
	for i, part := range strings.Split(header, ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		l, ok := Parse(fields[0])
		if !ok {
			continue
		}
		q := 1.0
		for _, f := range fields[1:] {
			if v, found := strings.CutPrefix(strings.TrimSpace(f), "q="); found {
				if p, err := strconv.ParseFloat(v, 64); err == nil {
					q = p
				}
			}
		}
		if q > 0 {
			cs = append(cs, cand{l, q, i})
		}
	}
	if len(cs) == 0 {
		return Default
	}
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].q > cs[j].q })
	return cs[0].lang
}

// T returns the text for key, formatted with args. Missing keys fall back
// to English, then to the key itself.
func (l Lang) T(key string, args ...any) string {
	s, ok := catalog[l][key]
	if !ok {
		s, ok = catalog[EN][key]
	}
	if !ok {
		s = key
	}
	if len(args) > 0 {
		return fmt.Sprintf(s, args...)
	}
	return s
}

// Has reports whether key exists in the English catalog.
func Has(key string) bool {
	_, ok := catalog[EN][key]
	return ok
}
