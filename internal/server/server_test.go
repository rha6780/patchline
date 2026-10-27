package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rha6780/patchline/internal/inventory"
	"github.com/rha6780/patchline/internal/store"
)

type pingFunc func(context.Context) error

func (f pingFunc) PingContext(ctx context.Context) error { return f(ctx) }

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestHealthEndpoints(t *testing.T) {
	ok := pingFunc(func(context.Context) error { return nil })
	down := pingFunc(func(context.Context) error { return errors.New("db down") })

	tests := []struct {
		name   string
		db     Pinger
		method string
		path   string
		want   int
	}{
		{"healthz", down, http.MethodGet, "/healthz", http.StatusOK},
		{"readyz ok", ok, http.MethodGet, "/readyz", http.StatusOK},
		{"readyz db down", down, http.MethodGet, "/readyz", http.StatusServiceUnavailable},
		{"wrong method", ok, http.MethodPost, "/healthz", http.StatusMethodNotAllowed},
		{"unknown path", ok, http.MethodGet, "/nope", http.StatusNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			New(Options{DB: tc.db, Logger: quiet}).ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	return store.New(db)
}

func fixture(t *testing.T) string {
	b, err := os.ReadFile(filepath.Join("..", "source", "dependencytrack", "testdata", "new_vulnerability.json"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDependencyTrackWebhook(t *testing.T) {
	st := newStore(t)
	woken := 0
	h := New(Options{DB: st, Inbox: st, Findings: st, WebhookToken: "s3cret", OnInbox: func() { woken++ }, Logger: quiet})
	body := fixture(t)

	post := func(target, auth, payload string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(payload))
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := post("/webhooks/dependency-track", "", body); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec := post("/webhooks/dependency-track?token=wrong", "", body); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", rec.Code)
	}
	if rec := post("/webhooks/dependency-track?token=s3cret", "", `{"nope":1}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid payload: %d", rec.Code)
	}

	rec := post("/webhooks/dependency-track?token=s3cret", "", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("query token: %d %s", rec.Code, rec.Body)
	}
	var resp struct {
		InboxID   int64 `json:"inbox_id"`
		Duplicate bool  `json:"duplicate"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.InboxID == 0 || resp.Duplicate || woken != 1 {
		t.Fatalf("first delivery: %+v woken=%d", resp, woken)
	}

	rec = post("/webhooks/dependency-track", "Bearer s3cret", body)
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != http.StatusAccepted || !resp.Duplicate || woken != 1 {
		t.Fatalf("redelivery: %d %+v woken=%d", rec.Code, resp, woken)
	}
}

func TestListFindingsAddsOwners(t *testing.T) {
	st := newStore(t)
	doc := "services:\n  - name: storefront\n    owners: [alice@example.com]\n    slack_channel: '#sf'\n    repositories: [{repo: acme/storefront-api}]\n"
	path := filepath.Join(t.TempDir(), "inv.yaml")
	_ = os.WriteFile(path, []byte(doc), 0o600)
	inv, err := inventory.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	_, _, err = st.UpsertFinding(ctx, observation("storefront", true), map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _ = st.UpsertFinding(ctx, observation("unknown-app", false), map[string]any{})

	h := New(Options{DB: st, Findings: st, Inventory: inv, Logger: quiet})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/findings?service=storefront", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var resp struct {
		Findings []findingView `json:"findings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Findings) != 1 || len(resp.Findings[0].Owners) != 1 || resp.Findings[0].SlackChannel != "#sf" {
		t.Fatalf("findings = %+v", resp.Findings)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/findings/1/events", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"detected"`) {
		t.Fatalf("events: %d %s", rec.Code, rec.Body)
	}
}

func TestGiteaWebhook(t *testing.T) {
	st := newStore(t)
	h := New(Options{DB: st, Inbox: st, Findings: st, GiteaSecret: "hook-secret", Logger: quiet})
	body, err := os.ReadFile(filepath.Join("..", "source", "gitea", "testdata", "renovate_opened.json"))
	if err != nil {
		t.Fatal(err)
	}
	sign := func(b []byte) string {
		mac := hmac.New(sha256.New, []byte("hook-secret"))
		mac.Write(b)
		return hex.EncodeToString(mac.Sum(nil))
	}
	post := func(event, sig string, payload []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/webhooks/gitea", strings.NewReader(string(payload)))
		req.Header.Set("X-Gitea-Event", event)
		req.Header.Set("X-Gitea-Delivery", "delivery-1")
		if sig != "" {
			req.Header.Set("X-Gitea-Signature", sig)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := post("pull_request", "", body); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned: %d", rec.Code)
	}
	if rec := post("pull_request", sign([]byte("other")), body); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad signature: %d", rec.Code)
	}
	if rec := post("push", sign(body), body); rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"ignored":true`) {
		t.Fatalf("push event: %d %s", rec.Code, rec.Body)
	}
	rec := post("pull_request", sign(body), body)
	if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"duplicate":false`) {
		t.Fatalf("pull_request: %d %s", rec.Code, rec.Body)
	}
	if rec := post("pull_request", sign(body), body); !strings.Contains(rec.Body.String(), `"duplicate":true`) {
		t.Fatalf("redelivery should be a duplicate: %s", rec.Body)
	}
}
