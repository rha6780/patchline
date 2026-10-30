package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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
		"<spdx/>":           "not CycloneDX",
		"<bom><x></bom>":    "CycloneDX XML",
		"not json":          "not JSON",
		`{"hello":"world"}`: "neither",
		`{"bomFormat":"CycloneDX","components":"x"}`: "CycloneDX",
	} {
		if _, err := Parse([]byte(in)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", in, err, want)
		}
	}
}

func TestCycloneDXXML(t *testing.T) {
	// Converted from the JSON samples by cyclonedx-cli (with its UTF-8 BOM).
	for _, tc := range []struct{ xml, json string }{
		{"storefront-api.cdx.xml", filepath.Join("..", "..", "examples", "sbom", "storefront-api.cdx.json")},
		{"storefront-api-image.cdx.xml", filepath.Join("..", "..", "examples", "sbom", "storefront-api-image.cdx.json")},
	} {
		x, err := os.ReadFile(filepath.Join("testdata", tc.xml))
		if err != nil {
			t.Fatal(err)
		}
		j, _ := os.ReadFile(tc.json)
		fromXML, err := Parse(x)
		if err != nil {
			t.Fatalf("%s: %v", tc.xml, err)
		}
		fromJSON, _ := Parse(j)
		if !reflect.DeepEqual(fromXML, fromJSON) {
			t.Errorf("%s differs from the JSON:\nxml  %+v\njson %+v", tc.xml, fromXML, fromJSON)
		}
	}
	x, _ := os.ReadFile(filepath.Join("testdata", "storefront-api-image.cdx.xml"))
	doc, _ := Parse(x)
	for _, c := range doc.Components {
		if c.Name == "libssl1.1" && (c.SrcName != "openssl" || c.SrcVersion != "1.1.1n-0+deb11u4" || c.BOMRef == "") {
			t.Errorf("libssl1.1 = %+v", c)
		}
	}
}

func TestRawEnvelope(t *testing.T) {
	for _, body := range []string{`{"bomFormat":"CycloneDX"}`, "\xef\xbb\xbf<?xml version=\"1.0\"?><bom/>"} {
		b, err := json.Marshal(Upload{Project: "p", BOM: Raw(body)})
		if err != nil {
			t.Fatal(err)
		}
		var up Upload
		if err := json.Unmarshal(b, &up); err != nil || string(up.BOM) != body {
			t.Errorf("%q: round trip %q, %v", body, up.BOM, err)
		}
	}
	// JSON stays readable in the inbox.
	b, _ := json.Marshal(Upload{BOM: Raw(`{"a":1}`)})
	if !strings.Contains(string(b), `"bom":{"a":1}`) {
		t.Errorf("json envelope = %s", b)
	}
}
