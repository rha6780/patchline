package intake

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/inventory"
	"github.com/rha6780/patchline/internal/source/osv"
	"github.com/rha6780/patchline/internal/store"
)

func loadInventory(t *testing.T, yaml string) *inventory.Inventory {
	t.Helper()
	path := filepath.Join(t.TempDir(), "inv.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := inventory.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

// TestProjectMovedToAnotherService: moving a project to another service in
// the inventory moves its findings, with their assignee, decisions and
// history, instead of resolving them and starting over.
func TestProjectMovedToAnotherService(t *testing.T) {
	ctx := context.Background()
	p, st := setup(t, nil)
	p.Matcher = &fakeMatcher{ready: true, vulns: map[string][]osv.Match{
		lodash: {{ID: "GHSA-p6mc-m468-83gw", Aliases: []string{"CVE-2020-8203"}, Severity: "high"}},
		log4j:  {{ID: "GHSA-jfh8-c2jp-5v3q", Aliases: []string{"CVE-2021-44228"}, Severity: "critical"}},
	}}
	upload(t, st, "u1", bomWith(lodash, log4j))
	drain(t, p)
	accepted, open := findingFor(t, st, lodash), findingFor(t, st, log4j)

	lead := store.Actor{Subject: "lead", Name: "Lead"}
	rid, err := st.CreateRequest(ctx, store.ExceptionRequest{FindingID: accepted.ID, Kind: store.RequestRiskAcceptance, Reason: "legacy"},
		store.Actor{Subject: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DecideRequest(ctx, store.Decision{RequestID: rid, Status: store.RequestApproved, By: lead}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AssignFinding(ctx, open.ID, "bob@example.com", lead); err != nil {
		t.Fatal(err)
	}

	p.Inventory = loadInventory(t, `
services:
  - name: payments
    repositories:
      - repo: acme/storefront-api
`)
	upload(t, st, "u2", bomWith(lodash, log4j))
	drain(t, p)

	list, _ := st.ListFindings(ctx, store.FindingFilter{})
	if len(list) != 2 {
		t.Fatalf("findings = %+v", list)
	}
	for _, f := range list {
		if f.Service != "payments" || (f.ID != accepted.ID && f.ID != open.ID) {
			t.Fatalf("finding %d: service %s", f.ID, f.Service)
		}
	}
	if f, _ := st.GetFinding(ctx, accepted.ID); f.State != string(finding.StateRiskAccepted) {
		t.Errorf("accepted finding is %s after the move", f.State)
	}
	if f, _ := st.GetFinding(ctx, open.ID); f.State != string(finding.StateNew) || f.Assignee != "bob@example.com" {
		t.Errorf("open finding after the move: %s, assignee %q", f.State, f.Assignee)
	}
	events, _ := st.FindingEvents(ctx, open.ID)
	if last := events[len(events)-1]; last.Kind != finding.EventServiceChanged {
		t.Errorf("last event = %s", last.Kind)
	}

	// Unregistered (the project left the inventory) and back: still the
	// same findings.
	p.Inventory = inventory.Empty()
	upload(t, st, "u3", bomWith(lodash, log4j))
	drain(t, p)
	if f, _ := st.GetFinding(ctx, open.ID); f.Service != "storefront-api" || f.Registered {
		t.Errorf("unregistered: %+v", f)
	}
	p.Inventory = loadInventory(t, testInventory)
	upload(t, st, "u4", bomWith(lodash, log4j))
	drain(t, p)
	if list, _ := st.ListFindings(ctx, store.FindingFilter{}); len(list) != 2 || list[0].Service != "storefront" {
		t.Errorf("back in storefront: %+v", list)
	}
}

// TestSharedFindingStaysWithItsService: a finding another project (of
// another name) still reports for the old service is not taken away; the
// moved project gets its own.
func TestSharedFindingStaysWithItsService(t *testing.T) {
	ctx := context.Background()
	p, st := setup(t, nil)
	p.Inventory = loadInventory(t, `
services:
  - name: storefront
    repositories:
      - repo: acme/storefront-api
        projects: [storefront-api, storefront-worker]
`)
	p.Matcher = &fakeMatcher{ready: true, vulns: map[string][]osv.Match{lodash: {{ID: "GHSA-p6mc-m468-83gw", Aliases: []string{"CVE-2020-8203"}, Severity: "high"}}}}
	upload(t, st, "u1", bomWith(lodash))
	uploadAs(t, st, "w1", "storefront-worker", bomWith(lodash))
	drain(t, p)
	shared := findingFor(t, st, lodash)

	p.Inventory = loadInventory(t, `
services:
  - name: storefront
    repositories:
      - repo: acme/storefront-worker
  - name: payments
    repositories:
      - repo: acme/storefront-api
`)
	upload(t, st, "u2", bomWith(lodash))
	drain(t, p)
	if f, _ := st.GetFinding(ctx, shared.ID); f.Service != "storefront" || !finding.State(f.State).Open() {
		t.Fatalf("shared finding = %s %s", f.Service, f.State)
	}
	list, _ := st.ListFindings(ctx, store.FindingFilter{Service: "payments"})
	if len(list) != 1 || list[0].ID == shared.ID {
		t.Fatalf("payments findings = %+v", list)
	}
}
