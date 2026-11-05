package webhook_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/inventory"
	"github.com/rha6780/patchline/internal/notify"
	"github.com/rha6780/patchline/internal/sink/webhook"
	"github.com/rha6780/patchline/internal/source"
	"github.com/rha6780/patchline/internal/store"
)

type request struct {
	header http.Header
	body   []byte
}

func server(t *testing.T, status int) (*httptest.Server, *[]request) {
	t.Helper()
	var got []request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, request{r.Header.Clone(), b})
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "7")
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func message() notify.Message {
	due := "2026-11-10T00:00:00Z"
	return notify.Message{
		Finding: store.Finding{ID: 42, Service: "storefront", Registered: true, Environment: "prod",
			ComponentRef: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", ComponentName: "log4j-core",
			ComponentVersion: "2.14.1", VulnID: "CVE-2021-44228", Severity: "high", EffectiveSeverity: "critical",
			SLAReasons: []string{"in CISA KEV"}, KEV: true, State: "new", DueAt: &due},
		Service: &inventory.Service{Name: "storefront", Owners: []string{"alice@example.com"}},
		URL:     "https://patchline.example/findings/42",
		Links:   []source.Link{{Source: "dependencytrack", Label: "Dependency-Track", URL: "http://dt.local/projects/p/findings"}},
		PullRequests: []store.PullRequestLink{{Repository: "acme/api", Number: 12, URL: "https://git/pulls/12",
			State: "open", ToVersion: "2.17.1", Verdict: "fixes"}},
	}
}

func TestPostAndEvent(t *testing.T) {
	srv, got := server(t, http.StatusNoContent)
	s := webhook.New(srv.URL, "s3cret", nil)
	ctx := context.Background()

	ref, err := s.Post(ctx, "", message())
	if err != nil {
		t.Fatal(err)
	}
	if ref.ID != "42" {
		t.Fatalf("ref = %+v", ref)
	}
	from, to := "new", "in_progress"
	e := store.FindingEvent{ID: 9, Kind: finding.EventStateChanged, FromState: &from, ToState: &to,
		Evidence: json.RawMessage(`{"by_name":"Bob"}`), OccurredAt: "2026-11-03T01:02:03Z"}
	if err := s.ReplyEvent(ctx, ref, message(), e, "State: New → In progress"); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 2 {
		t.Fatalf("requests = %d", len(*got))
	}

	r := (*got)[0]
	if sig := r.header.Get("X-Patchline-Signature-256"); sig != webhook.Sign([]byte("s3cret"), r.body) {
		t.Fatalf("signature = %q", sig)
	}
	if r.header.Get("X-Patchline-Event") != webhook.TypeOpened || r.header.Get("X-Patchline-Delivery") != "42.opened" {
		t.Fatalf("headers = %v", r.header)
	}
	var p webhook.Payload
	if err := json.Unmarshal(r.body, &p); err != nil {
		t.Fatal(err)
	}
	f := p.Finding
	if p.Schema != webhook.Schema || f.Severity != "critical" || f.ScannerSev != "high" || f.Component.Name != "log4j-core" ||
		f.URL != "https://patchline.example/findings/42" || len(f.Owners) != 1 || len(p.PullRequests) != 1 || p.Event != nil ||
		f.DTURL != "http://dt.local/projects/p/findings" || len(f.Links) != 1 || f.Links[0].Label != "Dependency-Track" {
		t.Fatalf("opened payload = %s", r.body)
	}

	if err := json.Unmarshal((*got)[1].body, &p); err != nil {
		t.Fatal(err)
	}
	if p.Type != webhook.TypeEvent || p.Delivery != "42.9" || p.Event == nil || p.Event.Kind != finding.EventStateChanged ||
		*p.Event.ToState != "in_progress" || string(p.Event.Evidence) != `{"by_name":"Bob"}` || p.Text != "State: New → In progress" {
		t.Fatalf("event payload = %s", (*got)[1].body)
	}
}

func TestUnsignedAndErrors(t *testing.T) {
	srv, got := server(t, http.StatusTooManyRequests)
	s := webhook.New(srv.URL, "", nil)
	_, err := s.Post(context.Background(), "", message())
	var rl *notify.RateLimitError
	if !errors.As(err, &rl) || rl.RetryAfter != 7*time.Second {
		t.Fatalf("err = %v", err)
	}
	if (*got)[0].header.Get("X-Patchline-Signature-256") != "" {
		t.Fatal("unsigned sink sent a signature")
	}

	srv, _ = server(t, http.StatusBadRequest)
	if _, err := webhook.New(srv.URL, "", nil).Post(context.Background(), "", message()); err == nil {
		t.Fatal("HTTP 400 accepted")
	}
}
