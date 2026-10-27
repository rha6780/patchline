package gitea

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"reflect"
	"testing"
)

func load(t *testing.T, name string) PullRequestEvent {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := ParsePullRequestEvent(b)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestParseAndOutcome(t *testing.T) {
	for name, want := range map[string]Outcome{
		"renovate_opened.json": OutcomeOpen,
		"renovate_merged.json": OutcomeMerged,
		"renovate_closed.json": OutcomeClosed,
	} {
		ev := load(t, name)
		if got := ev.Outcome(); got != want {
			t.Errorf("%s: outcome %q, want %q", name, got, want)
		}
		if ev.Repository.FullName != "acme/storefront-api" || ev.PullRequest.Number != 12 || ev.PullRequest.Base.Ref != "main" {
			t.Errorf("%s: %+v", name, ev)
		}
	}
	if (PullRequestEvent{Action: "labeled"}).Outcome() != OutcomeIgnore {
		t.Error("labeled should be ignored")
	}
	if _, err := ParsePullRequestEvent([]byte(`{"action":"opened"}`)); err == nil {
		t.Error("expected error for payload without repository")
	}
}

func TestRenovateUpdatesFromTable(t *testing.T) {
	got := RenovateUpdates(load(t, "renovate_opened.json").PullRequest)
	want := []Update{{Package: "org.apache.logging.log4j:log4j-core", From: "2.14.1", To: "2.17.1"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestRenovateUpdatesVariants(t *testing.T) {
	tests := []struct {
		name string
		pr   PullRequest
		want []Update
	}{
		{"arrow and diff link", PullRequest{Body: "| Package | Change |\n|---|---|\n| [lodash](https://lodash.com/) | [`4.17.15` → `4.17.21`](https://renovatebot.com/diffs/npm/lodash/4.17.15/4.17.21) |"},
			[]Update{{Package: "lodash", From: "4.17.15", To: "4.17.21"}}},
		{"several packages", PullRequest{Body: "| Package | Type | Update | Change |\n|---|---|---|---|\n| `@types/node` | devDependencies | patch | `20.1.0` -> `20.1.4` |\n| express | dependencies | minor | `4.17.1` -> `4.21.2` |"},
			[]Update{{Package: "@types/node", From: "20.1.0", To: "20.1.4"}, {Package: "express", From: "4.17.1", To: "4.21.2"}}},
		{"title only", PullRequest{Title: "chore(deps): update dependency express to v4.21.2 [security]"},
			[]Update{{Package: "express", To: "4.21.2"}}},
		{"not renovate", PullRequest{Title: "Fix login bug", Body: "| a | b |\n|---|---|\n| x | y |"}, nil},
	}
	for _, tc := range tests {
		if got := RenovateUpdates(tc.pr); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestVerifySignature(t *testing.T) {
	body := []byte(`{"x":1}`)
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	h := http.Header{}
	h.Set("X-Gitea-Signature", sig)
	if !VerifySignature(h, body, "s3cret") {
		t.Error("gitea signature should verify")
	}
	if VerifySignature(h, body, "other") || VerifySignature(h, []byte(`{"x":2}`), "s3cret") {
		t.Error("wrong secret or body must fail")
	}
	gh := http.Header{}
	gh.Set("X-Hub-Signature-256", "sha256="+sig)
	if !VerifySignature(gh, body, "s3cret") {
		t.Error("github signature should verify")
	}
	if VerifySignature(http.Header{}, body, "s3cret") {
		t.Error("missing signature must fail")
	}
}

func TestHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("X-Forgejo-Event", "pull_request")
	h.Set("X-Forgejo-Delivery", "d-1")
	if EventType(h) != "pull_request" || DeliveryID(h) != "d-1" {
		t.Errorf("event=%q delivery=%q", EventType(h), DeliveryID(h))
	}
	if NormalizePackage("Org.Apache:Log4j-Core") != "org.apache/log4j-core" {
		t.Error("normalize")
	}
}
