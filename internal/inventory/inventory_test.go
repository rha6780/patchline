package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `
services:
  - name: storefront
    owners: [alice@example.com, bob@example.com]
    slack_channel: "#team-storefront"
    exposure: internet
    repositories:
      - repo: acme/storefront-api
        dependency_track_projects: [storefront-api, storefront-api-image]
      - repo: acme/storefront-web
  - name: billing
    owners: [carol@example.com]
    repositories:
      - repo: acme/billing
`

func TestParseAndLookup(t *testing.T) {
	doc, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	inv, err := build(doc.Services)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		project, service, repo string
	}{
		{"storefront-api", "storefront", "acme/storefront-api"},
		{"storefront-api-image", "storefront", "acme/storefront-api"},
		{"storefront-web", "storefront", "acme/storefront-web"}, // default: repo basename
		{"billing", "billing", "acme/billing"},
	}
	for _, tc := range tests {
		m, ok := inv.LookupProject(tc.project)
		if !ok {
			t.Errorf("%s: not found", tc.project)
			continue
		}
		if m.Service.Name != tc.service || m.Repository != tc.repo {
			t.Errorf("%s: got %s/%s, want %s/%s", tc.project, m.Service.Name, m.Repository, tc.service, tc.repo)
		}
	}
	if _, ok := inv.LookupProject("unknown"); ok {
		t.Error("unknown project should not match")
	}

	billing, _ := inv.Service("billing")
	if billing.Exposure != ExposureInternal {
		t.Errorf("default exposure = %q, want internal", billing.Exposure)
	}
}

func TestValidation(t *testing.T) {
	tests := map[string]string{
		"missing name":    "services:\n  - owners: [a]\n",
		"duplicate name":  "services:\n  - name: a\n  - name: a\n",
		"bad exposure":    "services:\n  - name: a\n    exposure: public\n",
		"missing repo":    "services:\n  - name: a\n    repositories:\n      - dependency_track_projects: [x]\n",
		"project claimed": "services:\n  - name: a\n    repositories: [{repo: x/app}]\n  - name: b\n    repositories: [{repo: y/app}]\n",
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			doc, err := Parse([]byte(input))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := build(doc.Services); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestParseUnknownField(t *testing.T) {
	if _, err := Parse([]byte("services:\n  - name: a\n    owner: typo\n")); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestLoadDirectory(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("a.yaml", "services:\n  - name: one\n    repositories: [{repo: acme/one}]\n")
	write("b.yml", "services:\n  - name: two\n    repositories: [{repo: acme/two}]\n")
	write("notes.txt", "ignored")

	inv, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(inv.Services()); got != 2 {
		t.Fatalf("services = %d, want 2", got)
	}

	write("c.yaml", "services:\n  - name: one\n")
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("expected duplicate error across files, got %v", err)
	}
}

func TestLoadEmptyPath(t *testing.T) {
	inv, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Services()) != 0 {
		t.Fatal("expected empty inventory")
	}
}
