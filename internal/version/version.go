// Package version compares package versions across ecosystems on a
// best-effort basis.
//
// It understands the common shape of Maven, npm/SemVer, PyPI and Go
// versions: numeric segments compared as numbers, pre-release qualifiers
// (alpha, beta, milestone, rc, snapshot) before the release, and
// post-release qualifiers (sp, post) after it. Build metadata (+...) and a
// leading "v" are ignored. It is used to judge whether a pull request's
// target version leaves a vulnerable range; a rescan remains the proof.
package version

import (
	"strconv"
	"strings"
	"unicode"
)

type token struct {
	num   int64
	text  string
	isNum bool
}

func tokenize(v string) []token {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, ':'); i >= 0 { // Debian epoch: ignored
		v = v[i+1:]
	}
	var out []token
	var cur strings.Builder
	curNum := false
	flush := func() {
		if cur.Len() == 0 {
			return
		}
		s := cur.String()
		if curNum {
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				n = 1<<62 - 1
			}
			out = append(out, token{num: n, isNum: true})
		} else {
			out = append(out, token{text: s})
		}
		cur.Reset()
	}
	for _, r := range v {
		switch {
		case unicode.IsDigit(r):
			if !curNum {
				flush()
				curNum = true
			}
			cur.WriteRune(r)
		case unicode.IsLetter(r):
			if curNum {
				flush()
				curNum = false
			}
			cur.WriteRune(r)
		default: // separators: . - _ ~
			flush()
			curNum = false
		}
	}
	flush()
	return out
}

// qualifierRank orders text qualifiers relative to a release (0).
func qualifierRank(q string) int {
	switch q {
	case "alpha", "a", "dev":
		return -5
	case "beta", "b":
		return -4
	case "milestone", "m", "preview", "pre":
		return -3
	case "rc", "cr", "c":
		return -2
	case "snapshot":
		return -1
	case "final", "ga", "release", "r":
		return 0
	case "sp", "post", "p", "patch":
		return 1
	}
	return -6 // unknown words sort before releases
}

// Compare returns -1, 0 or +1 as a is less than, equal to or greater than b.
func Compare(a, b string) int {
	ta, tb := tokenize(a), tokenize(b)
	for i := 0; i < len(ta) || i < len(tb); i++ {
		var x, y *token
		if i < len(ta) {
			x = &ta[i]
		}
		if i < len(tb) {
			y = &tb[i]
		}
		if c := compareToken(x, y); c != 0 {
			return c
		}
	}
	return 0
}

// compareToken compares two tokens; nil means "absent", which behaves like
// zero against numbers and like a release against qualifiers.
func compareToken(x, y *token) int {
	switch {
	case x == nil && y == nil:
		return 0
	case x == nil:
		return -compareToken(y, nil)
	case y == nil:
		if x.isNum {
			return sign(x.num)
		}
		return sign(int64(qualifierRank(x.text)))
	case x.isNum && y.isNum:
		return sign(x.num - y.num)
	case x.isNum: // 1.0.1 > 1.0-rc
		return 1
	case y.isNum:
		return -1
	}
	rx, ry := qualifierRank(x.text), qualifierRank(y.text)
	if rx != ry {
		return sign(int64(rx - ry))
	}
	return sign(int64(strings.Compare(x.text, y.text)))
}

func sign(n int64) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// Range is an affected version range; empty bounds are open. Exact, when
// set, matches a single version instead.
type Range struct {
	Exact          string
	StartIncluding string
	StartExcluding string
	EndIncluding   string
	EndExcluding   string
}

// Contains reports whether v is inside the range.
func (r Range) Contains(v string) bool {
	if r.Exact != "" {
		return Compare(v, r.Exact) == 0
	}
	if r.StartIncluding != "" && Compare(v, r.StartIncluding) < 0 {
		return false
	}
	if r.StartExcluding != "" && Compare(v, r.StartExcluding) <= 0 {
		return false
	}
	if r.EndIncluding != "" && Compare(v, r.EndIncluding) > 0 {
		return false
	}
	if r.EndExcluding != "" && Compare(v, r.EndExcluding) >= 0 {
		return false
	}
	return true
}

// String renders the range, e.g. ">= 2.0.0, < 2.17.0".
func (r Range) String() string {
	if r.Exact != "" {
		return "= " + r.Exact
	}
	var parts []string
	if r.StartIncluding != "" {
		parts = append(parts, ">= "+r.StartIncluding)
	}
	if r.StartExcluding != "" {
		parts = append(parts, "> "+r.StartExcluding)
	}
	if r.EndIncluding != "" {
		parts = append(parts, "<= "+r.EndIncluding)
	}
	if r.EndExcluding != "" {
		parts = append(parts, "< "+r.EndExcluding)
	}
	if len(parts) == 0 {
		return "all versions"
	}
	return strings.Join(parts, ", ")
}
