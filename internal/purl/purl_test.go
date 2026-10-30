package purl

import "testing"

func TestParseAndOSV(t *testing.T) {
	for in, want := range map[string]struct{ eco, pkg, version string }{
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar": {Maven, "org.apache.logging.log4j:log4j-core", "2.14.1"},
		"pkg:npm/%40babel/core@7.0.0":                                   {NPM, "@babel/core", "7.0.0"},
		"pkg:npm/lodash@4.17.20":                                        {NPM, "lodash", "4.17.20"},
		"pkg:pypi/Django_REST.framework@3.12.0":                         {PyPI, "django-rest-framework", "3.12.0"},
		"pkg:golang/github.com/gin-gonic/gin@v1.6.0":                    {Go, "github.com/gin-gonic/gin", "v1.6.0"},
		"pkg:cargo/serde@1.0.0":                                         {Crates, "serde", "1.0.0"},
		"pkg:nuget/Newtonsoft.Json@12.0.1":                              {NuGet, "newtonsoft.json", "12.0.1"},
		"pkg:gem/rails@6.0.0":                                           {RubyGems, "rails", "6.0.0"},
		"pkg:composer/Laravel/Framework@8.0.0":                          {Packagist, "laravel/framework", "8.0.0"},
		"pkg:deb/debian/openssl@1.1.1n-0+deb11u3?arch=amd64":            {"", "", "1.1.1n-0+deb11u3"},
		"pkg:maven/log4j-core@2.14.1":                                   {"", "", "2.14.1"},
	} {
		p, err := Parse(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		eco, pkg := p.OSV()
		if eco != want.eco || pkg != want.pkg || p.Version != want.version {
			t.Errorf("%s: got %q %q %q, want %+v", in, eco, pkg, p.Version, want)
		}
	}
	for _, bad := range []string{"", "maven/x@1", "pkg:", "pkg:npm/", "pkg:npm/@1.0"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}
