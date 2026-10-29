package auth

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/rha6780/patchline/internal/store"
)

// localApp serves the authenticator with the local admin in front of a
// handler that reports the principal.
func localApp(t *testing.T, opts Options) (*httptest.Server, *store.Store) {
	t.Helper()
	st := newStore(t)
	hash, err := HashPassword(DefaultPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnsureLocalAccount(context.Background(), AdminUser, hash); err != nil {
		t.Fatal(err)
	}
	a, err := New(context.Background(), opts, DefaultPolicy(), st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := FromContext(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]any{"subject": p.Subject, "local": p.Local, "all": p.Can(All),
			"read": p.Can(FindingsRead), "csrf": p.CSRF, "path": r.URL.Path})
	})
	a.Routes(mux)
	srv := httptest.NewServer(a.Middleware(mux))
	t.Cleanup(srv.Close)
	return srv, st
}

type browser struct {
	t      *testing.T
	base   string
	client *http.Client
}

func newBrowser(t *testing.T, base string) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, base: base, client: &http.Client{Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// do returns the status, the Location header and the JSON body (if any).
func (b *browser) do(method, path string, form url.Values, header ...string) (int, string, map[string]any) {
	b.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, b.base+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, resp.Header.Get("Location"), m
}

func (b *browser) login(password string) (int, string) {
	code, loc, _ := b.do(http.MethodPost, "/auth/local", url.Values{"username": {AdminUser}, "password": {password}, "next": {"/findings"}})
	return code, loc
}

func TestLocalAdminFirstSignIn(t *testing.T) {
	srv, _ := localApp(t, Options{LocalAdmin: true})
	b := newBrowser(t, srv.URL)

	// Without a session: the sign-in page; the API answers 401.
	if code, loc, _ := b.do(http.MethodGet, "/findings?open=1", nil); code != http.StatusSeeOther || loc != "/login?next=%2Ffindings%3Fopen%3D1" {
		t.Fatalf("no session: %d %s", code, loc)
	}
	if code, _, _ := b.do(http.MethodGet, "/api/v1/findings", nil); code != http.StatusUnauthorized {
		t.Fatalf("api: %d", code)
	}
	if code, loc := b.login("wrong"); code != http.StatusSeeOther || !strings.Contains(loc, "error=login_invalid") {
		t.Fatalf("wrong password: %d %s", code, loc)
	}

	// admin/admin works once, and only to change the password.
	if _, loc := b.login(DefaultPassword); loc != "/account/password" {
		t.Fatalf("default password: %s", loc)
	}
	if code, loc, _ := b.do(http.MethodGet, "/findings", nil); code != http.StatusSeeOther || loc != "/account/password" {
		t.Fatalf("before change: %d %s", code, loc)
	}
	if code, _, _ := b.do(http.MethodGet, "/api/v1/findings", nil); code != http.StatusForbidden {
		t.Fatalf("api before change: %d", code)
	}
	_, _, me := b.do(http.MethodGet, "/account/password", nil)
	csrf, _ := me["csrf"].(string)

	for _, tc := range []struct{ current, password, confirm, want string }{
		{"nope", "a-long-new-password", "a-long-new-password", "password_current"},
		{"admin", "short", "short", "password_short"},
		{"admin", "a-long-new-password", "different-password", "password_mismatch"},
		{"admin", "ADMIN", "ADMIN", "password_short"},
	} {
		_, loc, _ := b.do(http.MethodPost, "/account/password", url.Values{"csrf": {csrf}, "current": {tc.current},
			"password": {tc.password}, "confirm": {tc.confirm}})
		if !strings.Contains(loc, "error="+tc.want) {
			t.Errorf("%+v: %s", tc, loc)
		}
	}
	if code, _, _ := b.do(http.MethodPost, "/account/password", url.Values{"current": {"admin"}, "password": {"a-long-new-password"}, "confirm": {"a-long-new-password"}}); code != http.StatusForbidden {
		t.Fatalf("change without csrf: %d", code)
	}
	if _, loc, _ := b.do(http.MethodPost, "/account/password", url.Values{"csrf": {csrf}, "current": {"admin"},
		"password": {"a-long-new-password"}, "confirm": {"a-long-new-password"}}); loc != "/?notice=password_changed" {
		t.Fatalf("change: %s", loc)
	}

	// The same session now has every permission.
	code, _, got := b.do(http.MethodGet, "/findings", nil)
	if code != http.StatusOK || got["local"] != true || got["all"] != true || got["subject"] != "local:admin" {
		t.Fatalf("after change: %d %v", code, got)
	}
	// admin/admin no longer works; the new password does.
	other := newBrowser(t, srv.URL)
	if _, loc := other.login(DefaultPassword); !strings.Contains(loc, "error=login_invalid") {
		t.Fatalf("old password: %s", loc)
	}
	if _, loc := other.login("a-long-new-password"); loc != "/findings" {
		t.Fatalf("new password: %s", loc)
	}
}

func TestLocalAdminLockout(t *testing.T) {
	srv, _ := localApp(t, Options{LocalAdmin: true})
	b := newBrowser(t, srv.URL)
	var loc string
	for i := 0; i < maxFailures; i++ {
		_, loc = b.login("guess")
	}
	if !strings.Contains(loc, "error=login_locked") {
		t.Fatalf("after %d failures: %s", maxFailures, loc)
	}
	if _, loc = b.login(DefaultPassword); !strings.Contains(loc, "error=login_locked") {
		t.Fatalf("right password while locked: %s", loc)
	}
	if _, loc = newBrowser(t, srv.URL).login(DefaultPassword); !strings.Contains(loc, "login_locked") {
		t.Fatalf("other client while locked: %s", loc)
	}
}

func TestLocalAdminCrossSite(t *testing.T) {
	srv, _ := localApp(t, Options{LocalAdmin: true})
	b := newBrowser(t, srv.URL)
	code, _, _ := b.do(http.MethodPost, "/auth/local", url.Values{"username": {AdminUser}, "password": {DefaultPassword}},
		"Origin", "https://evil.example")
	if code != http.StatusForbidden {
		t.Fatalf("cross-site login: %d", code)
	}
}

func TestPasswordResetEndsSessions(t *testing.T) {
	srv, st := localApp(t, Options{LocalAdmin: true})
	ctx := context.Background()
	hash, _ := HashPassword("a-long-new-password")
	_ = st.SetLocalPassword(ctx, AdminUser, hash, false, store.Actor{Subject: "test"}, "")
	b := newBrowser(t, srv.URL)
	if _, loc := b.login("a-long-new-password"); loc != "/findings" {
		t.Fatalf("login: %s", loc)
	}
	if code, _, _ := b.do(http.MethodGet, "/findings", nil); code != http.StatusOK {
		t.Fatalf("signed in: %d", code)
	}
	// reset-admin-password: back to admin/admin, existing sessions end.
	reset, _ := HashPassword(DefaultPassword)
	if err := st.SetLocalPassword(ctx, AdminUser, reset, true, store.Actor{Subject: "cli"}, ""); err != nil {
		t.Fatal(err)
	}
	if code, loc, _ := b.do(http.MethodGet, "/findings", nil); code != http.StatusSeeOther || !strings.HasPrefix(loc, "/login") {
		t.Fatalf("after reset: %d %s", code, loc)
	}
	if _, loc := b.login(DefaultPassword); loc != "/account/password" {
		t.Fatalf("login after reset: %s", loc)
	}
}

func TestAllowAnonymous(t *testing.T) {
	srv, _ := localApp(t, Options{LocalAdmin: true, AllowAnonymous: true})
	b := newBrowser(t, srv.URL)
	code, _, got := b.do(http.MethodGet, "/findings", nil)
	if code != http.StatusOK || got["read"] != true || got["all"] == true {
		t.Fatalf("anonymous read: %d %v", code, got)
	}
	if code, _, _ := b.do(http.MethodPost, "/findings/1/assign", url.Values{"me": {"1"}}); code != http.StatusUnauthorized {
		t.Fatalf("anonymous post: %d", code)
	}
}

func TestLocalAdminDisabled(t *testing.T) {
	st := newStore(t)
	if _, err := New(context.Background(), Options{}, DefaultPolicy(), st, nil); err == nil {
		t.Fatal("no sign-in method accepted")
	}
	// Turning the local admin off ends its sessions and the login form.
	srv, st := localApp(t, Options{LocalAdmin: true})
	b := newBrowser(t, srv.URL)
	b.login(DefaultPassword)
	a, _ := New(context.Background(), Options{AllowAnonymous: true}, DefaultPolicy(), st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"local": FromContext(r.Context()).Local})
	})
	a.Routes(mux)
	srv.Config.Handler = a.Middleware(mux)
	if _, _, got := b.do(http.MethodGet, "/findings", nil); got["local"] == true {
		t.Fatal("local session still valid with the local admin off")
	}
	b.login(DefaultPassword) // not routed any more: no session is created
	if _, _, got := b.do(http.MethodGet, "/findings", nil); got["local"] == true {
		t.Fatal("local login worked with the admin off")
	}
}

func TestCheckNewPassword(t *testing.T) {
	for pw, want := range map[string]string{
		"correct horse battery": "", "short": "password_short", "Admin": "password_short",
		strings.Repeat("x", 73): "password_long",
	} {
		if got := CheckNewPassword(pw, pw, "old"); got != want {
			t.Errorf("%q: %q, want %q", pw, got, want)
		}
	}
	if got := CheckNewPassword("admin", "admin", "x"); got != "password_short" {
		t.Errorf("admin: %q", got)
	}
}
