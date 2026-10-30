package sbom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rha6780/patchline/internal/purl"
)

func TestCycloneDX(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "sbom", "storefront-api.cdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Format != "CycloneDX" || doc.Commit != "1f0e2d3c4b5a69788796a5b4c3d2e1f0a9b8c7d6" || doc.Ref != "refs/heads/main" ||
		doc.Serial == "" || len(doc.Components) != 3 {
		t.Fatalf("doc = %+v", doc)
	}
	c := doc.Components[0]
	if c.PURL != "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10.1" || c.Ecosystem != purl.Maven ||
		c.Package != "com.fasterxml.jackson.core:jackson-databind" || c.Version != "2.9.10.1" {
		t.Errorf("first component = %+v", c)
	}
}

func TestCycloneDXNestedAndRoot(t *testing.T) {
	doc, err := Parse([]byte(`{"bomFormat":"CycloneDX","metadata":{"component":{"name":"app","purl":"pkg:npm/app@1.0.0"}},
	  "components":[{"name":"app","purl":"pkg:npm/app@1.0.0"},
	    {"name":"a","version":"1","purl":"pkg:npm/a@1","components":[{"name":"b","purl":"pkg:npm/b@2"},{"name":"a","purl":"pkg:npm/a@1"}]},
	    {"name":"no-purl","version":"3"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range doc.Components {
		got = append(got, c.PURL+"="+c.Version)
	}
	if strings.Join(got, " ") != "pkg:npm/a@1=1 pkg:npm/b@2=2" || doc.WithoutPURL != 1 {
		t.Fatalf("components = %v, without purl %d", got, doc.WithoutPURL)
	}
}

func TestSPDX(t *testing.T) {
	doc, err := Parse([]byte(`{"spdxVersion":"SPDX-2.3","documentNamespace":"https://example.com/sbom/1",
	  "annotations":[{"comment":"patchline:git:commit=ABCDEF1234567"}],
	  "packages":[{"name":"requests","versionInfo":"2.19.0","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:pypi/requests@2.19.0"}]},
	    {"name":"app"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Format != "SPDX" || doc.Serial != "https://example.com/sbom/1" || doc.Commit != "abcdef1234567" ||
		len(doc.Components) != 1 || doc.Components[0].Package != "requests" || doc.WithoutPURL != 1 {
		t.Fatalf("doc = %+v", doc)
	}
}

func TestParseErrors(t *testing.T) {
	for in, want := range map[string]string{
		"":                  "empty",
		"<bom/>":            "XML",
		"not json":          "not JSON",
		`{"hello":"world"}`: "neither",
		`{"bomFormat":"CycloneDX","components":"x"}`: "CycloneDX",
	} {
		if _, err := Parse([]byte(in)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", in, err, want)
		}
	}
}
