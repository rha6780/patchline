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
	"mime/multipart"
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

func TestRotatedWebhookToken(t *testing.T) {
	st := newStore(t)
	secrets := store.WebhookSecrets{Store: st, EnvToken: "from-env"}
	h := New(Options{DB: st, Inbox: st, Findings: st, WebhookToken: "from-env", Secrets: secrets.Current, Logger: quiet})
	send := func(token string) int {
		req := httptest.NewRequest(http.MethodPost, "/webhooks/dependency-track?token="+token,
			strings.NewReader(`{"notification":{"group":"BOM_CONSUMED","subject":{}}}`))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := send("from-env"); code == http.StatusUnauthorized {
		t.Fatalf("env token rejected: %d", code)
	}
	if err := st.SetSetting(context.Background(), store.SettingWebhookToken, "rotated-in-the-ui", store.Actor{Subject: "ops"}); err != nil {
		t.Fatal(err)
	}
	if code := send("from-env"); code != http.StatusUnauthorized {
		t.Fatalf("old token after rotation: %d", code)
	}
	if code := send("rotated-in-the-ui"); code == http.StatusUnauthorized {
		t.Fatalf("new token rejected: %d", code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	New(Options{DB: pingFunc(func(context.Context) error { return nil }), Logger: quiet}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") || rec.Header().Get("X-Frame-Options") != "DENY" ||
		rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers = %v", rec.Header())
	}
}

func TestIngestSBOM(t *testing.T) {
	st := newStore(t)
	woken := 0
	h := New(Options{DB: st, Inbox: st, Findings: st, WebhookToken: "s3cret", OnInbox: func() { woken++ }, Logger: quiet})
	bom, err := os.ReadFile(filepath.Join("..", "..", "examples", "sbom", "storefront-api.cdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	send := func(req *http.Request) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	jsonReq := func(query, token string, body []byte) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/ingest/sbom?"+query, strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		return r
	}

	if rec := send(jsonReq("project=storefront-api&version=main", "", bom)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec := send(jsonReq("version=main", "s3cret", bom)); rec.Code != http.StatusBadRequest {
		t.Fatalf("no project: %d", rec.Code)
	}
	if rec := send(jsonReq("project=x", "s3cret", []byte(`<bom/>`))); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "XML") {
		t.Fatalf("xml: %d %s", rec.Code, rec.Body)
	}
	rec := send(jsonReq("project=storefront-api&version=main", "s3cret", bom))
	if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"components":3`) || woken != 1 {
		t.Fatalf("json upload: %d %s (woken %d)", rec.Code, rec.Body, woken)
	}

	// Multipart, the way Dependency-Track's upload is usually scripted.
	var buf strings.Builder
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("project", "storefront-api")
	_ = mw.WriteField("version", "prod")
	fw, _ := mw.CreateFormFile("bom", "bom.json")
	_, _ = fw.Write(bom)
	_ = mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/ingest/sbom?token=s3cret", strings.NewReader(buf.String()))
	r.Header.Set("Content-Type", mw.FormDataContentType())
	if rec := send(r); rec.Code != http.StatusAccepted {
		t.Fatalf("multipart upload: %d %s", rec.Code, rec.Body)
	}

	items, _ := st.PendingInbox(context.Background(), 5, 10)
	if len(items) != 2 || items[0].Source != "patchline" || items[0].EventType != "sbom" {
		t.Fatalf("inbox = %+v", items)
	}
	var up struct{ Project, Version string }
	_ = json.Unmarshal(items[1].Payload, &up)
	if up.Project != "storefront-api" || up.Version != "prod" {
		t.Errorf("multipart payload = %+v", up)
	}
}

func TestComponentsAndImpactAPI(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	_ = st.TouchSourceProject(ctx, store.SourceProject{Source: "patchline", ProjectID: "app@main", Name: "app", Version: "main", Service: "app"}, true)
	_ = st.ReplaceComponents(ctx, "patchline", "app@main", []store.Component{{PURL: "pkg:npm/lodash@4.17.15", Name: "lodash",
		Version: "4.17.15", Ecosystem: "npm", Package: "lodash"}})
	_ = st.UpsertOSV(ctx, []store.OSVRecord{{ID: "GHSA-p6mc-m468-83gw", Ecosystem: "npm", Modified: "2025-01-01T00:00:00Z",
		Aliases: []string{"CVE-2020-8203"}, Severity: "high",
		Affected: []store.OSVAffected{{Ecosystem: "npm", Package: "lodash", Ranges: []store.OSVRange{{Introduced: "0", Fixed: "4.17.19"}}}}}})
	h := New(Options{DB: st, Findings: st, Impact: st, Logger: quiet})
	get := func(path string) (int, map[string]any) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return rec.Code, m
	}
	code, m := get("/api/v1/components?q=lodash&version=%3C4.17.19")
	if comps, _ := m["components"].([]any); code != 200 || len(comps) != 1 {
		t.Fatalf("components: %d %v", code, m)
	}
	if code, _ := get("/api/v1/components?q=lodash&version=%3C%3C"); code != http.StatusBadRequest {
		t.Fatalf("bad constraint: %d", code)
	}
	code, m = get("/api/v1/vulnerabilities/CVE-2020-8203")
	if affected, _ := m["affected"].([]any); code != 200 || m["id"] != "CVE-2020-8203" || len(affected) != 1 {
		t.Fatalf("impact: %d %v", code, m)
	}
}
