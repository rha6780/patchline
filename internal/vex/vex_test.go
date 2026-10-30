package vex

import (
	"testing"
	"time"

	"github.com/rha6780/patchline/internal/store"
)

func TestBOMLinks(t *testing.T) {
	const log4j = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	findings := []store.Finding{{ComponentRef: log4j, ComponentName: "log4j-core", VulnID: "CVE-2021-44228", State: "not_affected",
		Analysis: &store.Analysis{State: "not_affected", Justification: "code_not_reachable"}}}
	comps := []store.Component{{PURL: log4j, Name: "log4j-core", BOMRef: log4j}}

	// A CycloneDX upload with a serial and bom-refs: BOM-Links, no copies
	// of the components.
	p := store.SourceProject{Name: "app", Version: "main", BOMSerial: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", BOMVersion: 2}
	d := Build(p, findings, comps, "dev", time.Now())
	want := "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/2#pkg:maven%2Forg.apache.logging.log4j%2Flog4j-core@2.14.1"
	if got := d.Vulnerabilities[0].Affects[0].Ref; got != want || len(d.Components) != 0 {
		t.Fatalf("ref = %s, components %d", got, len(d.Components))
	}
	if a := d.Vulnerabilities[0].Analysis; a.State != "not_affected" || a.Justification != "code_not_reachable" {
		t.Errorf("analysis = %+v", a)
	}

	// No serial (or SPDX, or no bom-refs): the components go into the VEX.
	for _, p := range []store.SourceProject{{Name: "app"}, {Name: "app", BOMSerial: "https://spdx.example/doc"}} {
		d := Build(p, findings, comps, "dev", time.Now())
		if d.Vulnerabilities[0].Affects[0].Ref != log4j || len(d.Components) != 1 || d.Components[0].PURL != log4j {
			t.Errorf("%+v: affects %s, components %+v", p, d.Vulnerabilities[0].Affects[0].Ref, d.Components)
		}
	}
	d = Build(p, findings, []store.Component{{PURL: log4j}}, "dev", time.Now())
	if d.Vulnerabilities[0].Affects[0].Ref != log4j {
		t.Errorf("without bom-ref: %s", d.Vulnerabilities[0].Affects[0].Ref)
	}
}
