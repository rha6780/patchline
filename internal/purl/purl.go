// Package purl parses package URLs and maps them to OSV ecosystems and
// package names, so SBOM components can be looked up in OSV data.
//
//	pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1 -> Maven, org.apache.logging.log4j:log4j-core
//	pkg:npm/%40babel/core@7.0.0                          -> npm, @babel/core
package purl

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// PURL is a parsed package URL.
type PURL struct {
	Type      string
	Namespace string
	Name      string
	Version   string
	// Qualifiers such as arch, distro, epoch, upstream.
	Qualifiers map[string]string
}

// Parse reads "pkg:type/namespace/name@version?qualifiers#subpath".
// The subpath is dropped.
func Parse(s string) (PURL, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), "pkg:")
	if !ok {
		return PURL{}, errors.New("purl: missing pkg: scheme")
	}
	quals := map[string]string{}
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		if rest[i] == '?' {
			q := rest[i+1:]
			if j := strings.IndexByte(q, '#'); j >= 0 {
				q = q[:j]
			}
			for _, kv := range strings.Split(q, "&") {
				if k, v, ok := strings.Cut(kv, "="); ok && k != "" {
					quals[strings.ToLower(k)] = unescape(v)
				}
			}
		}
		rest = rest[:i]
	}
	rest = strings.TrimLeft(rest, "/")
	typ, path, ok := strings.Cut(rest, "/")
	if !ok || typ == "" || path == "" {
		return PURL{}, errors.New("purl: want pkg:type/name")
	}
	p := PURL{Qualifiers: quals}
	p.Type = strings.ToLower(typ)
	// The version follows the last "@" of the last segment (npm scopes
	// start with an encoded "@").
	if i := strings.LastIndex(path, "@"); i > strings.LastIndex(path, "/") {
		p.Version, path = unescape(path[i+1:]), path[:i]
	}
	segs := strings.Split(strings.Trim(path, "/"), "/")
	for i := range segs {
		segs[i] = unescape(segs[i])
	}
	p.Name = segs[len(segs)-1]
	p.Namespace = strings.Join(segs[:len(segs)-1], "/")
	if p.Name == "" {
		return PURL{}, errors.New("purl: empty name")
	}
	return p, nil
}

func unescape(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}

// OSV ecosystem names.
const (
	Maven     = "Maven"
	NPM       = "npm"
	PyPI      = "PyPI"
	Go        = "Go"
	Crates    = "crates.io"
	NuGet     = "NuGet"
	RubyGems  = "RubyGems"
	Packagist = "Packagist"
)

// Ecosystems lists the OSV ecosystems Patchline can match.
var Ecosystems = []string{Maven, NPM, PyPI, Go, Crates, NuGet, RubyGems, Packagist}

// OSV returns the OSV ecosystem and the normalized package name of p, or
// "" when the purl type has no OSV ecosystem.
func (p PURL) OSV() (ecosystem, pkg string) {
	switch p.Type {
	case "maven":
		if p.Namespace == "" {
			return "", ""
		}
		return Maven, p.Namespace + ":" + p.Name
	case "npm":
		if p.Namespace != "" {
			return NPM, Normalize(NPM, p.Namespace+"/"+p.Name)
		}
		return NPM, Normalize(NPM, p.Name)
	case "pypi":
		return PyPI, Normalize(PyPI, p.Name)
	case "golang":
		if p.Namespace != "" {
			return Go, p.Namespace + "/" + p.Name
		}
		return Go, p.Name
	case "cargo":
		return Crates, p.Name
	case "nuget":
		return NuGet, Normalize(NuGet, p.Name)
	case "gem":
		return RubyGems, p.Name
	case "composer":
		if p.Namespace != "" {
			return Packagist, Normalize(Packagist, p.Namespace+"/"+p.Name)
		}
		return Packagist, Normalize(Packagist, p.Name)
	}
	return "", ""
}

var pypiSeparators = regexp.MustCompile(`[-_.]+`)

// Normalize puts a package name in the form used for lookups, following
// each ecosystem's own rules for which names are the same package.
func Normalize(ecosystem, name string) string {
	switch ecosystem {
	case PyPI:
		// PEP 503: case-insensitive, runs of -_. are equivalent.
		return pypiSeparators.ReplaceAllString(strings.ToLower(name), "-")
	case NPM, NuGet, Packagist:
		return strings.ToLower(name)
	}
	return name
}
