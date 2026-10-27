package slack

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rha6780/patchline/internal/inventory"
	"github.com/rha6780/patchline/internal/notify"
	"github.com/rha6780/patchline/internal/store"
)

type call struct {
	method string
	body   map[string]any
	auth   string
}

func fakeSlack(t *testing.T, handler func(method string, body map[string]any) (int, string)) (*httptest.Server, *[]call) {
	t.Helper()
	var calls []call
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		method := strings.TrimPrefix(r.URL.Path, "/")
		calls = append(calls, call{method: method, body: body, auth: r.Header.Get("Authorization")})
		status, resp := handler(method, body)
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "7")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(resp))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func message() notify.Message {
	return notify.Message{
		Finding: store.Finding{
			ID: 7, Service: "storefront", Registered: true, Repository: "acme/storefront-api", Environment: "main",
			ComponentName: "org.apache.logging.log4j/log4j-core", ComponentVersion: "2.14.1",
			VulnID: "CVE-2021-44228", Aliases: []string{"GHSA-jfh8-c2jp-5v3q"}, Severity: "critical", State: "new",
			FirstSeenAt: "2026-10-28T09:00:00.000Z",
		},
		Service: &inventory.Service{Name: "storefront", Owners: []string{"alice@example.com"}},
		Link:    "http://dt.local/projects/p/findings",
	}
}

func TestPostUpdateReply(t *testing.T) {
	srv, calls := fakeSlack(t, func(method string, _ map[string]any) (int, string) {
		return 200, `{"ok":true,"channel":"C123","ts":"1730000000.000100"}`
	})
	s := New("xoxb-test", srv.URL, nil)
	ctx := context.Background()

	ref, err := s.Post(ctx, "#team-storefront", message())
	if err != nil {
		t.Fatal(err)
	}
	if ref.Channel != "C123" || ref.ID != "1730000000.000100" {
		t.Fatalf("ref = %+v (want the channel id Slack returned)", ref)
	}
	if err := s.Update(ctx, ref, message()); err != nil {
		t.Fatal(err)
	}
	if err := s.Reply(ctx, ref, "State: 🆕 New → 🛠️ In progress"); err != nil {
		t.Fatal(err)
	}

	got := *calls
	if len(got) != 3 || got[0].method != "chat.postMessage" || got[1].method != "chat.update" || got[2].method != "chat.postMessage" {
		t.Fatalf("calls = %+v", got)
	}
	if got[0].auth != "Bearer xoxb-test" || got[0].body["channel"] != "#team-storefront" {
		t.Errorf("post = %+v", got[0])
	}
	if got[1].body["channel"] != "C123" || got[1].body["ts"] != "1730000000.000100" {
		t.Errorf("update = %+v", got[1].body)
	}
	if got[2].body["thread_ts"] != "1730000000.000100" {
		t.Errorf("reply = %+v", got[2].body)
	}
	if !strings.Contains(got[0].body["text"].(string), "CVE-2021-44228") {
		t.Errorf("fallback text = %v", got[0].body["text"])
	}
}

func TestErrors(t *testing.T) {
	ctx := context.Background()

	srv, _ := fakeSlack(t, func(string, map[string]any) (int, string) { return 200, `{"ok":false,"error":"channel_not_found"}` })
	if _, err := New("t", srv.URL, nil).Post(ctx, "#nope", message()); err == nil || !strings.Contains(err.Error(), "channel_not_found") {
		t.Fatalf("api error: %v", err)
	}

	srv, _ = fakeSlack(t, func(string, map[string]any) (int, string) { return 429, `` })
	_, err := New("t", srv.URL, nil).Post(ctx, "#c", message())
	var rl *notify.RateLimitError
	if !errors.As(err, &rl) || rl.RetryAfter != 7*time.Second {
		t.Fatalf("rate limit: %v", err)
	}
}

func TestBlocks(t *testing.T) {
	m := message()
	m.Finding.Title = "Log4Shell <script>"
	b, _ := json.Marshal(Blocks(m))
	s := string(b)
	for _, want := range []string{"CRITICAL · CVE-2021-44228", "storefront (main)", "log4j-core@2.14.1", "alice@example.com",
		"GHSA-jfh8-c2jp-5v3q", "Open in Dependency-Track", "Log4Shell \\u0026lt;script\\u0026gt;"} {
		if !strings.Contains(s, want) {
			t.Errorf("blocks missing %q:\n%s", want, s)
		}
	}

	m.PullRequests = []store.PullRequestLink{{Repository: "acme/api", Number: 12, URL: "https://git/pulls/12", State: "open", Verdict: "fixes"}}
	b, _ = json.Marshal(Blocks(m))
	if !strings.Contains(string(b), "Fix PR") || !strings.Contains(string(b), `\u003chttps://git/pulls/12|acme/api#12\u003e open`) {
		t.Errorf("PR field missing: %s", b)
	}

	m.Service, m.Finding.Registered, m.Link, m.PullRequests = nil, false, "", nil
	b, _ = json.Marshal(Blocks(m))
	if !strings.Contains(string(b), "not in inventory") || strings.Contains(string(b), "Open in Dependency-Track") {
		t.Errorf("unregistered blocks: %s", b)
	}
}
