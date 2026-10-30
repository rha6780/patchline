package web

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rha6780/patchline/internal/auth"
	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/i18n"
	"github.com/rha6780/patchline/internal/source/dependencytrack"
	"github.com/rha6780/patchline/internal/store"
)

// Actions is what the UI changes. Every change is recorded on the
// finding's timeline and in the audit log by the store.
type Actions interface {
	AssignFinding(ctx context.Context, id int64, assignee string, by store.Actor) (bool, error)
	CreateRequest(ctx context.Context, r store.ExceptionRequest, by store.Actor) (int64, error)
	GetRequest(ctx context.Context, id int64) (store.ExceptionRequest, error)
	ListRequests(ctx context.Context, f store.RequestFilter) ([]store.ExceptionRequest, error)
	DecideRequest(ctx context.Context, d store.Decision) error
	Setting(ctx context.Context, key string) (string, error)
	SettingUpdatedAt(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, value string, by store.Actor) error
	ListAudit(ctx context.Context, limit int) ([]store.AuditEntry, error)
	CreateToken(ctx context.Context, t store.APIToken, hash string, by store.Actor) (int64, error)
	ListTokens(ctx context.Context) ([]store.APIToken, error)
	RevokeToken(ctx context.Context, id int64, by store.Actor) error
}

// AnalysisWriter records analysis decisions in Dependency-Track.
type AnalysisWriter interface {
	SetAnalysis(ctx context.Context, a dependencytrack.AnalysisUpdate) error
}

// maxReason bounds request reasons and decision notes.
const maxReason = 2000

// back redirects to path with a notice or an error key (shown by the page
// through the i18n catalog).
func back(w http.ResponseWriter, r *http.Request, path, param, key string) {
	http.Redirect(w, r, path+"?"+param+"="+url.QueryEscape(key), http.StatusSeeOther)
}

func (u *UI) forbid(w http.ResponseWriter, r *http.Request) {
	http.Error(w, langOf(r).T("ui.err.forbidden"), http.StatusForbidden)
}

func (u *UI) findingFor(w http.ResponseWriter, r *http.Request) (store.Finding, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return store.Finding{}, false
	}
	f, err := u.o.Store.GetFinding(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return store.Finding{}, false
	}
	if err != nil {
		u.fail(w, err)
		return store.Finding{}, false
	}
	return f, true
}

// ---- assignment -------------------------------------------------------

func (u *UI) assign(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	if !p.Can(auth.FindingsAssign) {
		u.forbid(w, r)
		return
	}
	f, ok := u.findingFor(w, r)
	if !ok {
		return
	}
	assignee := strings.TrimSpace(r.PostFormValue("assignee"))
	if r.PostFormValue("me") == "1" {
		assignee = p.Identity()
	}
	if len(assignee) > 254 {
		back(w, r, findingPath(f.ID), "error", "assignee")
		return
	}
	changed, err := u.o.Actions.AssignFinding(r.Context(), f.ID, assignee, p.Actor())
	if err != nil {
		u.fail(w, err)
		return
	}
	if changed {
		u.o.OnChange()
	}
	back(w, r, findingPath(f.ID), "notice", "assigned")
}

// ---- requests ---------------------------------------------------------

func (u *UI) request(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	if !p.Can(auth.ExceptionsRequest) {
		u.forbid(w, r)
		return
	}
	f, ok := u.findingFor(w, r)
	if !ok {
		return
	}
	path := findingPath(f.ID)
	if !finding.State(f.State).Open() {
		back(w, r, path, "error", "closed")
		return
	}
	reason := strings.TrimSpace(r.PostFormValue("reason"))
	if reason == "" || len(reason) > maxReason {
		back(w, r, path, "error", "reason")
		return
	}
	req := store.ExceptionRequest{FindingID: f.ID, Kind: r.PostFormValue("kind"), Reason: reason}
	switch req.Kind {
	case store.RequestRiskAcceptance, store.RequestFalsePositive, store.RequestNotAffected:
		if req.Kind == store.RequestNotAffected {
			req.Justification = r.PostFormValue("justification")
			if !slices.Contains(store.Justifications, req.Justification) {
				back(w, r, path, "error", "justification")
				return
			}
		}
		// A decision on a Dependency-Track finding is written there; one on
		// a finding only Patchline reports stays in Patchline.
		if inDT(f) && u.o.DT == nil {
			back(w, r, path, "error", "no_dt")
			return
		}
	case store.RequestDueExtension:
		day, err := time.Parse("2006-01-02", r.PostFormValue("due"))
		if err != nil {
			back(w, r, path, "error", "due")
			return
		}
		// The end of the chosen day, so "due 2026-12-01" means all of it.
		due := day.Add(24*time.Hour - time.Millisecond).UTC()
		floor := u.o.Now()
		if f.DueAt != nil {
			if t, err := parseTime(*f.DueAt); err == nil && t.After(floor) {
				floor = t
			}
		}
		if !due.After(floor) {
			back(w, r, path, "error", "due_earlier")
			return
		}
		s := store.FormatTime(due)
		req.RequestedDue = &s
	default:
		http.Error(w, "unknown request kind", http.StatusBadRequest)
		return
	}
	if _, err := u.o.Actions.CreateRequest(r.Context(), req, p.Actor()); errors.Is(err, store.ErrPendingRequest) {
		back(w, r, path, "error", "pending")
		return
	} else if err != nil {
		u.fail(w, err)
		return
	}
	u.o.OnChange()
	back(w, r, path, "notice", "requested")
}

// decide approves, rejects or withdraws a request. Approvers cannot decide
// their own requests; only the requester can withdraw one.
func (u *UI) decide(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	req, err := u.o.Actions.GetRequest(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		u.fail(w, err)
		return
	}
	path := findingPath(req.FindingID)
	if r.PostFormValue("from") == "approvals" {
		path = "/approvals"
	}
	note := strings.TrimSpace(r.PostFormValue("note"))
	if len(note) > maxReason {
		back(w, r, path, "error", "reason")
		return
	}

	d := store.Decision{RequestID: id, Note: note, By: p.Actor()}
	switch r.PostFormValue("action") {
	case "approve", "reject":
		if !p.Can(auth.ExceptionsApprove) {
			u.forbid(w, r)
			return
		}
		if req.RequestedBy == p.Subject {
			back(w, r, path, "error", "own_request")
			return
		}
		d.Status = store.RequestRejected
		if r.PostFormValue("action") == "approve" {
			d.Status = store.RequestApproved
		}
	case "cancel":
		if req.RequestedBy != p.Subject || !p.Authenticated {
			u.forbid(w, r)
			return
		}
		d.Status = store.RequestCancelled
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	if req.Status != store.RequestPending {
		back(w, r, path, "error", "not_pending")
		return
	}

	if d.Status == store.RequestApproved && isDecision(req.Kind) {
		f, err := u.o.Store.GetFinding(r.Context(), req.FindingID)
		if err != nil {
			u.fail(w, err)
			return
		}
		if inDT(f) {
			if err := u.writeToDT(r.Context(), f, req, p); err != nil {
				u.o.Logger.Warn("write decision to dependency-track", "request", id, "kind", req.Kind, "err", err)
				back(w, r, path, "error", "dt_write")
				return
			}
			d.Evidence = map[string]any{"recorded_in": "dependency-track"}
		} else {
			d.Evidence = map[string]any{"recorded_in": "patchline"}
		}
	}
	if err := u.o.Actions.DecideRequest(r.Context(), d); errors.Is(err, store.ErrNotPending) {
		back(w, r, path, "error", "not_pending")
		return
	} else if err != nil {
		u.fail(w, err)
		return
	}
	u.o.OnChange()
	back(w, r, path, "notice", d.Status)
}

// isDecision reports whether a request kind closes the finding with an
// analysis decision.
func isDecision(kind string) bool {
	switch kind {
	case store.RequestRiskAcceptance, store.RequestNotAffected, store.RequestFalsePositive:
		return true
	}
	return false
}

// inDT reports whether Dependency-Track knows the finding, so decisions
// about it belong there.
func inDT(f store.Finding) bool {
	return f.DTProjectUUID != "" && f.DTComponentUUID != "" && f.DTVulnerabilityUUID != ""
}

// writeToDT records the decision in Dependency-Track, so it lives where
// the analysis lives. The PROJECT_AUDIT_CHANGE that follows is a no-op:
// the finding is already closed.
func (u *UI) writeToDT(ctx context.Context, f store.Finding, req store.ExceptionRequest, p *auth.Principal) error {
	if u.o.DT == nil {
		return errors.New("dependency-track is not configured (PATCHLINE_DT_URL, PATCHLINE_DT_API_KEY)")
	}
	reason := oneLine(req.Reason)
	a := dependencytrack.AnalysisUpdate{
		ProjectUUID: f.DTProjectUUID, ComponentUUID: f.DTComponentUUID, VulnerabilityUUID: f.DTVulnerabilityUUID,
		Justification: "NOT_SET", Response: "NOT_SET", Details: reason,
	}
	what := ""
	switch req.Kind {
	case store.RequestRiskAcceptance:
		a.State, a.Response, a.Suppressed, what = "EXPLOITABLE", "WILL_NOT_FIX", true, "Risk accepted"
	case store.RequestNotAffected:
		a.State, a.Justification, what = "NOT_AFFECTED", strings.ToUpper(req.Justification), "Not affected ("+req.Justification+")"
	case store.RequestFalsePositive:
		a.State, what = "FALSE_POSITIVE", "False positive"
	}
	a.Comment = fmt.Sprintf("%s in Patchline (request #%d): requested by %s, approved by %s. %s",
		what, req.ID, labelOr(req.RequestedByName, req.RequestedBy), p.Label(), reason)
	return u.o.DT.SetAnalysis(ctx, a)
}

func (u *UI) approvals(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	if !p.Can(auth.ExceptionsApprove) && !p.Can(auth.ExceptionsRequest) {
		u.forbid(w, r)
		return
	}
	pending, err := u.o.Actions.ListRequests(r.Context(), store.RequestFilter{Status: store.RequestPending})
	if err != nil {
		u.fail(w, err)
		return
	}
	recent, err := u.o.Actions.ListRequests(r.Context(), store.RequestFilter{Limit: 50})
	if err != nil {
		u.fail(w, err)
		return
	}
	var decided []store.ExceptionRequest
	for _, rq := range recent {
		if rq.Status != store.RequestPending {
			decided = append(decided, rq)
		}
	}
	u.render(w, r, "approvals", "ui.approvals", map[string]any{"Pending": pending, "Decided": decided})
}

// ---- settings ---------------------------------------------------------

type secretRow struct {
	Key       string // store setting key
	Field     string // form value
	Env       string // environment variable
	Source    string // "ui", "env" or ""
	Hint      string // last characters, never the whole value
	UpdatedAt string
}

func (u *UI) settings(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	if !p.Can(auth.SettingsWebhooks) && !p.Can(auth.AuditRead) && !p.Can(auth.TokensManage) {
		u.forbid(w, r)
		return
	}
	data := map[string]any{}
	if p.Can(auth.TokensManage) {
		tokens, err := u.o.Actions.ListTokens(r.Context())
		if err != nil {
			u.fail(w, err)
			return
		}
		data["Tokens"], data["TokenPermissions"] = tokens, auth.TokenPermissions
		data["Now"] = store.FormatTime(u.o.Now())
		if kind, value, ok := generatedSecrets.take(r.URL.Query().Get("token")); ok && kind == "api-token" {
			data["NewToken"] = value
		}
	}
	if p.Can(auth.SettingsWebhooks) {
		var rows []secretRow
		for _, s := range []struct{ key, field, env, envValue string }{
			{store.SettingWebhookToken, "token", "PATCHLINE_WEBHOOK_TOKEN", u.o.EnvWebhookToken},
			{store.SettingGiteaSecret, "gitea", "PATCHLINE_GITEA_WEBHOOK_SECRET", u.o.EnvGiteaSecret},
		} {
			row := secretRow{Key: s.key, Field: s.field, Env: s.env}
			v, err := u.o.Actions.Setting(r.Context(), s.key)
			if err != nil {
				u.fail(w, err)
				return
			}
			switch {
			case v != "":
				row.Source, row.Hint = "ui", hint(v)
				if row.UpdatedAt, err = u.o.Actions.SettingUpdatedAt(r.Context(), s.key); err != nil {
					u.fail(w, err)
					return
				}
			case s.envValue != "":
				row.Source, row.Hint = "env", hint(s.envValue)
			}
			rows = append(rows, row)
		}
		data["Secrets"] = rows
		if key, value, ok := generatedSecrets.take(r.URL.Query().Get("generated")); ok {
			data["GeneratedKey"], data["GeneratedValue"] = key, value
		}
	}
	if p.Can(auth.AuditRead) {
		entries, err := u.o.Actions.ListAudit(r.Context(), 100)
		if err != nil {
			u.fail(w, err)
			return
		}
		data["Audit"] = entries
	}
	data["PublicURL"] = strings.TrimRight(u.o.PublicURL, "/")
	u.render(w, r, "settings", "ui.settings", data)
}

// generatedSecrets hands a freshly generated value to the next page view
// once, so it can be copied into Dependency-Track or the Git host. It is
// keyed by a random nonce in the redirect, never by the value itself.
var generatedSecrets = newOnceStore()

func (u *UI) saveSecret(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	if !p.Can(auth.SettingsWebhooks) {
		u.forbid(w, r)
		return
	}
	var key string
	switch r.PostFormValue("field") {
	case "token":
		key = store.SettingWebhookToken
	case "gitea":
		key = store.SettingGiteaSecret
	default:
		http.Error(w, "unknown setting", http.StatusBadRequest)
		return
	}
	value := ""
	nonce := ""
	switch r.PostFormValue("action") {
	case "generate":
		value = randomSecret()
		nonce = generatedSecrets.put(key, value)
	case "set":
		value = strings.TrimSpace(r.PostFormValue("value"))
		if len(value) < 16 || len(value) > 256 {
			back(w, r, "/settings", "error", "secret_length")
			return
		}
	case "reset":
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	if err := u.o.Actions.SetSetting(r.Context(), key, value, p.Actor()); err != nil {
		u.fail(w, err)
		return
	}
	u.o.Logger.Info("webhook setting changed", "setting", key, "by", p.Subject, "action", r.PostFormValue("action"))
	if nonce != "" {
		http.Redirect(w, r, "/settings?notice=generated&generated="+nonce, http.StatusSeeOther)
		return
	}
	back(w, r, "/settings", "notice", "saved")
}

// ---- API tokens -------------------------------------------------------

// createToken issues an API token. Its value is shown once.
func (u *UI) createToken(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	if !p.Can(auth.TokensManage) {
		u.forbid(w, r)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" || len(name) > 100 {
		back(w, r, "/settings", "error", "token_name")
		return
	}
	var perms []string
	for _, perm := range auth.TokenPermissions {
		if r.PostFormValue("perm."+string(perm)) == "1" {
			perms = append(perms, string(perm))
		}
	}
	if len(perms) == 0 {
		back(w, r, "/settings", "error", "token_perms")
		return
	}
	t := store.APIToken{Name: name, Permissions: perms}
	if days, err := strconv.Atoi(r.PostFormValue("days")); err == nil && days > 0 {
		exp := store.FormatTime(u.o.Now().Add(time.Duration(days) * 24 * time.Hour))
		t.ExpiresAt = &exp
	}
	raw, prefix, hash := auth.NewToken()
	t.Prefix = prefix
	if _, err := u.o.Actions.CreateToken(r.Context(), t, hash, p.Actor()); err != nil {
		u.fail(w, err)
		return
	}
	u.o.Logger.Info("api token created", "name", name, "permissions", perms, "by", p.Subject)
	http.Redirect(w, r, "/settings?notice=token_created&token="+generatedSecrets.put("api-token", raw)+"#tokens", http.StatusSeeOther)
}

func (u *UI) revokeToken(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	if !p.Can(auth.TokensManage) {
		u.forbid(w, r)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := u.o.Actions.RevokeToken(r.Context(), id, p.Actor()); errors.Is(err, store.ErrTokenRevoked) {
		back(w, r, "/settings", "error", "token_revoked")
		return
	} else if err != nil {
		u.fail(w, err)
		return
	}
	u.o.Logger.Info("api token revoked", "id", id, "by", p.Subject)
	back(w, r, "/settings", "notice", "token_revoked")
}

// ---- helpers ----------------------------------------------------------

func findingPath(id int64) string { return "/findings/" + strconv.FormatInt(id, 10) }

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func labelOr(name, subject string) string {
	if name != "" {
		return name
	}
	return subject
}

func hint(secret string) string {
	if len(secret) <= 8 {
		return "••••"
	}
	return "••••" + secret[len(secret)-4:]
}

func randomSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// notice returns the translated flash message for the page, if any.
func notice(l i18n.Lang, r *http.Request) (ok, bad string) {
	q := r.URL.Query()
	if k := q.Get("notice"); k != "" && i18n.Has("ui.notice."+k) {
		ok = l.T("ui.notice." + k)
	}
	if k := q.Get("error"); k != "" && i18n.Has("ui.err."+k) {
		bad = l.T("ui.err." + k)
	}
	return ok, bad
}

// onceStore keeps values for one read within a few minutes.
type onceStore struct {
	mu    sync.Mutex
	items map[string]onceItem
}

type onceItem struct {
	key, value string
	expires    time.Time
}

func newOnceStore() *onceStore { return &onceStore{items: map[string]onceItem{}} }

func (s *onceStore) put(key, value string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for n, it := range s.items {
		if now.After(it.expires) {
			delete(s.items, n)
		}
	}
	nonce := randomSecret()
	s.items[nonce] = onceItem{key: key, value: value, expires: now.Add(5 * time.Minute)}
	return nonce
}

// take returns the value once.
func (s *onceStore) take(nonce string) (key, value string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.items[nonce]
	if !ok || time.Now().After(it.expires) {
		return "", "", false
	}
	delete(s.items, nonce)
	return it.key, it.value, true
}
