package dependencytrack

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func bomNotification(t *testing.T, content string) Notification {
	t.Helper()
	subject, _ := json.Marshal(map[string]any{
		"project": map[string]any{"uuid": "p1", "name": "storefront-api", "version": "main"},
		"bom":     map[string]any{"content": base64.StdEncoding.EncodeToString([]byte(content)), "format": "CycloneDX", "specVersion": "1.5"},
	})
	return Notification{Group: GroupBOMProcessed, Subject: subject}
}

func TestSubjectBOMJSON(t *testing.T) {
	n := bomNotification(t, `{
	  "bomFormat": "CycloneDX", "serialNumber": "urn:uuid:1",
	  "metadata": {"properties": [
	    {"name": "patchline:git:commit", "value": "3F2A9C1E0B7D4A6F8E5C2B1A0D9E8F7C6B5A4D3E"},
	    {"name": "patchline:git:ref", "value": "refs/heads/main"},
	    {"name": "other", "value": "x"}
	  ]}
	}`)
	got := n.SubjectBOM()
	want := BOMInfo{Format: "CycloneDX", SpecVersion: "1.5", Serial: "urn:uuid:1",
		Commit: "3f2a9c1e0b7d4a6f8e5c2b1a0d9e8f7c6b5a4d3e", Ref: "refs/heads/main"}
	if got != want {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestSubjectBOMXML(t *testing.T) {
	n := bomNotification(t, `<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" serialNumber="urn:uuid:2" version="1">
  <metadata><properties>
    <property name="patchline:git:commit">abc1234</property>
  </properties></metadata>
</bom>`)
	got := n.SubjectBOM()
	if got.Serial != "urn:uuid:2" || got.Commit != "abc1234" {
		t.Fatalf("got %+v", got)
	}
}

func TestSubjectBOMTolerant(t *testing.T) {
	for _, content := range []string{"", "not a bom", `{"metadata":{"properties":[{"name":"patchline:git:commit","value":"not-a-sha"}]}}`} {
		if got := bomNotification(t, content).SubjectBOM(); got.Commit != "" {
			t.Errorf("%q: commit = %q, want empty", content, got.Commit)
		}
	}
	// The fixture carries "{}" as its BOM.
	n, _ := ParseNotification(fixture(t, "bom_processed.json"))
	if got := n.SubjectBOM(); got.Format != "CycloneDX" || got.Commit != "" {
		t.Errorf("fixture: %+v", got)
	}
}
