package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rha6780/patchline/internal/app"
	"github.com/rha6780/patchline/internal/auth"
	"github.com/rha6780/patchline/internal/i18n"
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

// back redirects to path with a notice or an error key (shown by the page
// through the i18n catalog).
func back(w http.ResponseWriter, r *http.Request, path, param, key string) {
	http.Redirect(w, r, path+"?"+param+"="+url.QueryEscape(key), http.StatusSeeOther)
}

func (u *UI) forbid(w http.ResponseWriter, r *http.Request) {
	http.Error(w, langOf(r).T("ui.err.forbidden"), http.StatusForbidden)
}

// ---- assignment -------------------------------------------------------

func (u *UI) assign(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	assignee := r.PostFormValue("assignee")
	if r.PostFormValue("me") == "1" {
		assignee = p.Identity()
	}
	if err := u.app.Assign(r.Context(), p, id, assignee); err != nil {
		u.refused(w, r, findingPath(id), err)
		return
	}
	back(w, r, findingPath(id), "notice", "assigned")
}

// ---- requests ---------------------------------------------------------

func (u *UI) request(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	in := app.RequestInput{FindingID: id, Kind: r.PostFormValue("kind"), Reason: r.PostFormValue("reason"),
		Justification: r.PostFormValue("justification"), Due: r.PostFormValue("due")}
	if _, err := u.app.Request(r.Context(), p, in); err != nil {
		u.refused(w, r, findingPath(id), err)
		return
	}
	back(w, r, findingPath(id), "notice", "requested")
}

// decide approves, rejects or withdraws a request.
func (u *UI) decide(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	action := r.PostFormValue("action")
	req, err := u.app.Decide(r.Context(), p, id, action, r.PostFormValue("note"))
	path := findingPath(req.FindingID)
	if r.PostFormValue("from") == "approvals" {
		path = "/approvals"
	}
	if err != nil {
		u.refused(w, r, path, err)
		return
	}
	status := map[string]string{app.Approve: store.RequestApproved, app.Reject: store.RequestRejected,
		app.Cancel: store.RequestCancelled}[action]
	back(w, r, path, "notice", status)
}

// refused answers a change the service did not make: a message on the
// page for a refusal, 403 and 404 for permissions and missing records.
func (u *UI) refused(w http.ResponseWriter, r *http.Request, path string, err error) {
	var e *app.Error
	switch {
	case errors.Is(err, app.ErrForbidden):
		u.forbid(w, r)
	case errors.Is(err, app.ErrNotFound):
		http.NotFound(w, r)
	case errors.As(err, &e) && (e.Code == "kind" || e.Code == "action"):
		http.Error(w, "unknown "+e.Code, http.StatusBadRequest)
	case errors.As(err, &e):
		if e.Err != nil {
			u.o.Logger.Warn("change refused", "path", r.URL.Path, "code", e.Code, "err", e.Err)
		}
		back(w, r, path, "error", e.Code)
	default:
		u.fail(w, err)
	}
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
	// The API needs findings.read for every call, so write permissions
	// bring it along.
	if !slices.Contains(perms, string(auth.FindingsRead)) &&
		(slices.Contains(perms, string(auth.FindingsAssign)) || slices.Contains(perms, string(auth.ExceptionsRequest))) {
		perms = append([]string{string(auth.FindingsRead)}, perms...)
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
