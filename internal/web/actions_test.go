package web

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rha6780/patchline/internal/auth"
	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/source/dependencytrack"
	"github.com/rha6780/patchline/internal/store"
)

type fakeDT struct {
	calls []dependencytrack.AnalysisUpdate
	err   error
}

func (f *fakeDT) SetAnalysis(_ context.Context, a dependencytrack.AnalysisUpdate) error {
	f.calls = append(f.calls, a)
	return f.err
}

func person(subject string, perms ...auth.Permission) *auth.Principal {
	set := auth.Set{auth.FindingsRead: true}
	for _, p := range perms {
		set[p] = true
	}
	return &auth.Principal{Authenticated: true, Subject: subject, Email: subject + "@example.com", Name: strings.ToUpper(subject[:1]) + subject[1:],
		Perms: set, CSRF: "t"}
}

// as serves h for p, the way the auth middleware would.
func as(p *auth.Principal, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), p)))
	})
}

func post(t *testing.T, h http.Handler, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func writableUI(t *testing.T, dt AnalysisWriter) (*UI, *store.Store, int64) {
	t.Helper()
	_, st := setup(t)
	ctx := context.Background()
	id, _, err := st.UpsertFinding(ctx, finding.Observation{Service: "storefront", Registered: true, Repository: "acme/storefront-api",
		Environment: "main", ComponentRef: "pkg:npm/lodash@4.17.20", ComponentName: "lodash", ComponentVersion: "4.17.20",
		VulnID: "CVE-2021-23337", Severity: finding.SeverityHigh,
		DTProjectUUID: "11111111-1111-1111-1111-111111111111", DTComponentUUID: "22222222-2222-2222-2222-222222222222",
		DTVulnerabilityUUID: "33333333-3333-3333-3333-333333333333"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	u, err := New(Options{Store: st, Actions: st, DT: dt, AuthEnabled: true, PublicURL: "https://patchline.example.com",
		EnvWebhookToken: "env-token-abcdefgh", Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	return u, st, id
}

func location(rec *httptest.ResponseRecorder) string { return rec.Header().Get("Location") }

func TestAssignPermission(t *testing.T) {
	u, st, id := writableUI(t, &fakeDT{})
	path := findingPath(id) + "/assign"

	if rec := post(t, as(person("viewer"), u), path, url.Values{"me": {"1"}}); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer: %d", rec.Code)
	}
	rec := post(t, as(person("dev", auth.FindingsAssign), u), path, url.Values{"me": {"1"}})
	if rec.Code != http.StatusSeeOther || !strings.Contains(location(rec), "notice=assigned") {
		t.Fatalf("dev: %d %s", rec.Code, location(rec))
	}
	f, _ := st.GetFinding(context.Background(), id)
	if f.Assignee != "dev@example.com" {
		t.Fatalf("assignee = %q", f.Assignee)
	}
	// The page shows it, and the viewer sees no forms.
	_, body := get(t, as(person("viewer"), u), findingPath(id))
	if !strings.Contains(body, "dev@example.com") || strings.Contains(body, `action="`+path+`"`) {
		t.Errorf("viewer page: assignee shown %v, form hidden %v", strings.Contains(body, "dev@example.com"), !strings.Contains(body, path))
	}
	_, body = get(t, as(person("dev", auth.FindingsAssign), u), findingPath(id))
	if !strings.Contains(body, `action="`+path+`"`) {
		t.Error("assign form missing for dev")
	}
}

func TestRiskAcceptanceFlow(t *testing.T) {
	dt := &fakeDT{}
	u, st, id := writableUI(t, dt)
	ctx := context.Background()
	dev := person("dev", auth.ExceptionsRequest)
	lead := person("lead", auth.ExceptionsApprove, auth.ExceptionsRequest)

	if rec := post(t, as(person("viewer"), u), findingPath(id)+"/requests", url.Values{"kind": {"risk_acceptance"}, "reason": {"x"}}); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer request: %d", rec.Code)
	}
	if rec := post(t, as(dev, u), findingPath(id)+"/requests", url.Values{"kind": {"risk_acceptance"}, "reason": {" "}}); !strings.Contains(location(rec), "error=reason") {
		t.Fatalf("empty reason: %s", location(rec))
	}
	rec := post(t, as(dev, u), findingPath(id)+"/requests", url.Values{"kind": {"risk_acceptance"}, "reason": {"Only reachable from the VPN;\nWAF blocks the payload."}})
	if !strings.Contains(location(rec), "notice=requested") {
		t.Fatalf("request: %d %s", rec.Code, location(rec))
	}
	reqs, _ := st.ListRequests(ctx, store.RequestFilter{Status: store.RequestPending})
	if len(reqs) != 1 {
		t.Fatalf("pending = %+v", reqs)
	}
	decide := "/requests/" + itoa(reqs[0].ID)

	// The approvals page lists it; the requester cannot approve it.
	if code, body := get(t, as(lead, u), "/approvals"); code != 200 || !strings.Contains(body, "CVE-2021-23337") || !strings.Contains(body, `value="approve"`) {
		t.Fatalf("approvals page: %d", code)
	}
	selfApprover := person("dev", auth.ExceptionsApprove, auth.ExceptionsRequest)
	if rec := post(t, as(selfApprover, u), decide, url.Values{"action": {"approve"}}); !strings.Contains(location(rec), "error=own_request") {
		t.Fatalf("self approval: %s", location(rec))
	}
	if rec := post(t, as(dev, u), decide, url.Values{"action": {"approve"}}); rec.Code != http.StatusForbidden {
		t.Fatalf("approve without permission: %d", rec.Code)
	}

	// Dependency-Track refuses: nothing is approved.
	dt.err = errors.New("403 Forbidden")
	if rec := post(t, as(lead, u), decide, url.Values{"action": {"approve"}}); !strings.Contains(location(rec), "error=dt_write") {
		t.Fatalf("dt failure: %s", location(rec))
	}
	if r, _ := st.GetRequest(ctx, reqs[0].ID); r.Status != store.RequestPending {
		t.Fatalf("status after dt failure = %s", r.Status)
	}

	dt.err = nil
	rec = post(t, as(lead, u), decide, url.Values{"action": {"approve"}, "note": {"until the Q1 upgrade"}})
	if !strings.Contains(location(rec), "notice=approved") {
		t.Fatalf("approve: %s", location(rec))
	}
	last := dt.calls[len(dt.calls)-1]
	if !last.Suppressed || last.State != "EXPLOITABLE" || last.Response != "WILL_NOT_FIX" ||
		last.ComponentUUID != "22222222-2222-2222-2222-222222222222" || strings.Contains(last.Comment, "\n") ||
		!strings.Contains(last.Comment, "approved by Lead") {
		t.Fatalf("analysis = %+v", last)
	}
	f, _ := st.GetFinding(ctx, id)
	if f.State != string(finding.StateRiskAccepted) {
		t.Fatalf("state = %s", f.State)
	}
	_, body := get(t, as(lead, u), findingPath(id))
	for _, want := range []string{"Risk acceptance", "until the Q1 upgrade", "approved by Lead"} {
		if !strings.Contains(body, want) {
			t.Errorf("finding page lacks %q", want)
		}
	}
}

func TestDueExtensionAndWithdraw(t *testing.T) {
	u, st, id := writableUI(t, nil)
	ctx := context.Background()
	dev := person("dev", auth.ExceptionsRequest)
	path := findingPath(id) + "/requests"

	if rec := post(t, as(dev, u), path, url.Values{"kind": {"due_extension"}, "reason": {"r"}, "due": {"2020-01-01"}}); !strings.Contains(location(rec), "error=due_earlier") {
		t.Fatalf("past date: %s", location(rec))
	}
	day := time.Now().AddDate(0, 4, 0).Format("2006-01-02")
	if rec := post(t, as(dev, u), path, url.Values{"kind": {"due_extension"}, "reason": {"vendor patch"}, "due": {day}}); !strings.Contains(location(rec), "notice=requested") {
		t.Fatalf("request: %s", location(rec))
	}
	if rec := post(t, as(dev, u), path, url.Values{"kind": {"due_extension"}, "reason": {"again"}, "due": {day}}); !strings.Contains(location(rec), "error=pending") {
		t.Fatalf("duplicate: %s", location(rec))
	}
	reqs, _ := st.ListRequests(ctx, store.RequestFilter{FindingID: id})
	decide := "/requests/" + itoa(reqs[0].ID)
	if rec := post(t, as(person("other", auth.ExceptionsRequest), u), decide, url.Values{"action": {"cancel"}}); rec.Code != http.StatusForbidden {
		t.Fatalf("withdraw someone else's: %d", rec.Code)
	}
	if rec := post(t, as(dev, u), decide, url.Values{"action": {"cancel"}}); !strings.Contains(location(rec), "notice=cancelled") {
		t.Fatalf("withdraw: %s", location(rec))
	}

	// Approved: the due date moves to the end of the chosen day.
	_ = post(t, as(dev, u), path, url.Values{"kind": {"due_extension"}, "reason": {"vendor patch"}, "due": {day}})
	reqs, _ = st.ListRequests(ctx, store.RequestFilter{Status: store.RequestPending})
	rec := post(t, as(person("lead", auth.ExceptionsApprove), u), "/requests/"+itoa(reqs[0].ID), url.Values{"action": {"approve"}, "from": {"approvals"}})
	if location(rec) != "/approvals?notice=approved" {
		t.Fatalf("approve: %s", location(rec))
	}
	f, _ := st.GetFinding(ctx, id)
	if f.DueAt == nil || *f.DueAt != day+"T23:59:59.999Z" {
		t.Fatalf("due = %v", f.DueAt)
	}
}

func TestRiskAcceptanceWithoutDT(t *testing.T) {
	// Dependency-Track reports the finding but Patchline cannot write to it:
	// the request is refused up front instead of failing at approval.
	u, st, id := writableUI(t, nil)
	rec := post(t, as(person("dev", auth.ExceptionsRequest), u), findingPath(id)+"/requests", url.Values{"kind": {"risk_acceptance"}, "reason": {"r"}})
	if !strings.Contains(location(rec), "error=no_dt") {
		t.Fatalf("request: %s", location(rec))
	}
	if reqs, _ := st.ListRequests(context.Background(), store.RequestFilter{Status: store.RequestPending}); len(reqs) != 0 {
		t.Fatalf("pending = %d", len(reqs))
	}
}

func TestDecisionsOnPatchlineFindings(t *testing.T) {
	ctx := context.Background()
	dt := &fakeDT{}
	u, st, _ := writableUI(t, dt)
	// A finding only Patchline reports (no Dependency-Track ids).
	id, _, err := st.UpsertFinding(ctx, finding.Observation{Service: "storefront", Registered: true, Environment: "main",
		ComponentRef: "pkg:npm/lodash@4.17.15", ComponentName: "lodash", ComponentVersion: "4.17.15", VulnID: "CVE-2020-8203",
		Severity: finding.SeverityHigh, Source: finding.SourcePatchline, SourceProject: "storefront-api@main"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	dev, lead := person("dev", auth.ExceptionsRequest), person("lead", auth.ExceptionsApprove)
	path := findingPath(id) + "/requests"

	_, body := get(t, as(dev, u), findingPath(id))
	for _, want := range []string{"Not affected", "False positive", "Code not reachable", "Only Patchline reports this finding"} {
		if !strings.Contains(body, want) {
			t.Errorf("finding page lacks %q", want)
		}
	}
	if rec := post(t, as(dev, u), path, url.Values{"kind": {"not_affected"}, "reason": {"r"}, "justification": {"because"}}); !strings.Contains(location(rec), "error=justification") {
		t.Fatalf("bad justification: %s", location(rec))
	}
	if rec := post(t, as(dev, u), path, url.Values{"kind": {"not_affected"}, "reason": {"lodash.merge is never called"},
		"justification": {"code_not_reachable"}}); !strings.Contains(location(rec), "notice=requested") {
		t.Fatalf("request: %s", location(rec))
	}
	reqs, _ := st.ListRequests(ctx, store.RequestFilter{FindingID: id, Status: store.RequestPending})
	if len(reqs) != 1 || reqs[0].Justification != "code_not_reachable" {
		t.Fatalf("pending = %+v", reqs)
	}
	calls := len(dt.calls)
	if rec := post(t, as(lead, u), "/requests/"+itoa(reqs[0].ID), url.Values{"action": {"approve"}}); !strings.Contains(location(rec), "notice=approved") {
		t.Fatalf("approve: %s", location(rec))
	}
	if len(dt.calls) != calls {
		t.Error("a Patchline-only decision was written to Dependency-Track")
	}
	f, _ := st.GetFinding(ctx, id)
	if f.State != string(finding.StateNotAffected) || f.Analysis == nil || f.Analysis.State != "not_affected" ||
		f.Analysis.Justification != "code_not_reachable" || f.Analysis.Detail != "lodash.merge is never called" || f.Analysis.By != "Lead" {
		t.Fatalf("finding = %+v analysis %+v", f, f.Analysis)
	}
	_, body = get(t, as(dev, u), findingPath(id))
	if !strings.Contains(body, "Decision") || !strings.Contains(body, "Code not reachable") {
		t.Error("decision not shown")
	}
}

func TestNotAffectedWrittenToDT(t *testing.T) {
	dt := &fakeDT{}
	u, st, id := writableUI(t, dt)
	_ = post(t, as(person("dev", auth.ExceptionsRequest), u), findingPath(id)+"/requests",
		url.Values{"kind": {"not_affected"}, "reason": {"behind the WAF"}, "justification": {"protected_at_perimeter"}})
	reqs, _ := st.ListRequests(context.Background(), store.RequestFilter{Status: store.RequestPending})
	if len(reqs) != 1 {
		t.Fatalf("pending = %d", len(reqs))
	}
	_ = post(t, as(person("lead", auth.ExceptionsApprove), u), "/requests/"+itoa(reqs[0].ID), url.Values{"action": {"approve"}})
	last := dt.calls[len(dt.calls)-1]
	if last.State != "NOT_AFFECTED" || last.Justification != "PROTECTED_AT_PERIMETER" || last.Suppressed || last.Response != "NOT_SET" {
		t.Fatalf("analysis = %+v", last)
	}
}

func TestWebhookSettings(t *testing.T) {
	u, st, _ := writableUI(t, nil)
	ctx := context.Background()
	admin := person("ops", auth.SettingsWebhooks, auth.AuditRead)

	if code, _ := get(t, as(person("viewer"), u), "/settings"); code != http.StatusForbidden {
		t.Fatalf("viewer: %d", code)
	}
	code, body := get(t, as(admin, u), "/settings")
	if code != 200 || !strings.Contains(body, "••••efgh") || strings.Contains(body, "env-token-abcdefgh") {
		t.Fatalf("settings page: %d, hint shown %v, value hidden %v", code, strings.Contains(body, "••••efgh"), !strings.Contains(body, "env-token-abcdefgh"))
	}

	rec := post(t, as(admin, u), "/settings/webhooks", url.Values{"field": {"token"}, "action": {"generate"}})
	loc := location(rec)
	if !strings.HasPrefix(loc, "/settings?notice=generated&generated=") {
		t.Fatalf("generate: %s", loc)
	}
	value, _ := st.Setting(ctx, store.SettingWebhookToken)
	if len(value) < 32 || strings.Contains(loc, value) {
		t.Fatalf("generated %q, redirect %s", value, loc)
	}
	_, body = get(t, as(admin, u), loc)
	if !strings.Contains(body, value) {
		t.Fatal("generated value not shown")
	}
	if _, body = get(t, as(admin, u), loc); strings.Contains(body, value) {
		t.Fatal("generated value shown twice")
	}
	if !regexp.MustCompile(`setting\.set`).MatchString(body) {
		t.Error("audit log lacks the change")
	}

	if rec := post(t, as(admin, u), "/settings/webhooks", url.Values{"field": {"gitea"}, "action": {"set"}, "value": {"short"}}); !strings.Contains(location(rec), "error=secret_length") {
		t.Fatalf("short value: %s", location(rec))
	}
	_ = post(t, as(admin, u), "/settings/webhooks", url.Values{"field": {"token"}, "action": {"reset"}})
	if v, _ := st.Setting(ctx, store.SettingWebhookToken); v != "" {
		t.Fatalf("after reset: %q", v)
	}
	if rec := post(t, as(person("dev", auth.FindingsAssign), u), "/settings/webhooks", url.Values{"field": {"token"}, "action": {"generate"}}); rec.Code != http.StatusForbidden {
		t.Fatalf("dev: %d", rec.Code)
	}
}

func TestReadOnlyWithoutActions(t *testing.T) {
	u, _ := setup(t)
	for _, path := range []string{"/findings/1/assign", "/requests/1", "/settings/webhooks"} {
		if rec := post(t, as(person("x", auth.All), u), path, url.Values{}); rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
			t.Errorf("POST %s = %d", path, rec.Code)
		}
	}
	if _, body := get(t, as(person("x", auth.All), u), "/"); strings.Contains(body, `href="/settings"`) {
		t.Error("settings link shown without actions")
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestLoginPages(t *testing.T) {
	_, st := setup(t)
	u, err := New(Options{Store: st, Actions: st, AuthEnabled: true, SSO: true, LocalAdmin: true,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	code, body := get(t, u, "/login?next=%2Ffindings%3Fopen%3D1")
	if code != 200 || !strings.Contains(body, `href="/auth/login?next=%2ffindings%3fopen%3d1"`) ||
		!strings.Contains(body, `action="/auth/local"`) || !strings.Contains(body, `value="/findings?open=1"`) {
		t.Fatalf("login page: %d", code)
	}
	if strings.Contains(body, `href="/findings?open=1"`) {
		t.Error("navigation shown before sign-in")
	}
	if _, body := get(t, u, "/login?next=https://evil.example"); !strings.Contains(body, `name="next" value="/"`) {
		t.Error("external next kept")
	}
	if code, _ := get(t, as(person("dev"), u), "/account/password"); code != http.StatusNotFound {
		t.Errorf("password page for an SSO user: %d", code)
	}
	admin := &auth.Principal{Authenticated: true, Subject: "local:admin", Name: "admin", Local: true, MustChangePassword: true,
		Perms: auth.Set{auth.All: true}, CSRF: "t"}
	code, body = get(t, as(admin, u), "/account/password")
	if code != 200 || !strings.Contains(body, "default password") || !strings.Contains(body, `action="/account/password"`) {
		t.Fatalf("password page: %d", code)
	}
}
