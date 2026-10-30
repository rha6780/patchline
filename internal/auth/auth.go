package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/rha6780/patchline/internal/store"
)

// Config configures OpenID Connect sign-in.
type Config struct {
	// Issuer is the provider's issuer URL; its discovery document is read
	// from Issuer + "/.well-known/openid-configuration".
	Issuer       string
	ClientID     string
	ClientSecret string
	// Scopes requested in addition to "openid".
	Scopes []string
	// GroupsClaims are the ID token claims read as groups, for example
	// "groups" or "roles". Dotted names read nested claims
	// ("realm_access.roles").
	GroupsClaims []string
}

// Options configures how people sign in.
type Options struct {
	// OIDC enables single sign-on; nil leaves only the local admin.
	OIDC *Config
	// LocalAdmin enables the built-in "admin" account (password login).
	LocalAdmin bool
	// AllowAnonymous lets requests without a session read (findings.read
	// only), for deployments behind an authenticating proxy.
	AllowAnonymous bool
	// PublicURL is where users reach Patchline. It is required with OIDC
	// (the redirect URI is PublicURL + "/auth/callback") and makes the
	// session cookie Secure when it is https.
	PublicURL string
	// SessionTTL is how long a sign-in lasts.
	SessionTTL time.Duration
}

// Store keeps sessions, logins in flight and the local admin account.
type Store interface {
	CreateSession(ctx context.Context, s store.Session) error
	GetSession(ctx context.Context, idHash string) (store.Session, error)
	DeleteSession(ctx context.Context, idHash string) error
	SaveAuthState(ctx context.Context, a store.AuthState) error
	TakeAuthState(ctx context.Context, state string) (store.AuthState, error)
	TimeFromNow(d time.Duration) string
	LocalStore
}

// Authenticator signs people in and attaches a Principal to each request.
// Every page and API call needs a session, unless AllowAnonymous is set.
// A nil *Authenticator lets everyone read (used by tests).
type Authenticator struct {
	opts     Options
	oidcCfg  Config
	policy   Policy
	store    Store
	logger   *slog.Logger
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier // nil without OIDC
	secure   bool
}

const (
	cookieSession = "patchline_session"
	loginTTL      = 10 * time.Minute
)

// New returns an Authenticator; with OIDC it reads the provider's
// discovery document first.
func New(ctx context.Context, opts Options, policy Policy, st Store, logger *slog.Logger) (*Authenticator, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if opts.SessionTTL <= 0 {
		opts.SessionTTL = 12 * time.Hour
	}
	if opts.OIDC == nil && !opts.LocalAdmin && !opts.AllowAnonymous {
		return nil, errors.New("no way to sign in: enable the local admin, configure OIDC, or allow anonymous access")
	}
	a := &Authenticator{opts: opts, policy: policy, store: st, logger: logger}
	if opts.PublicURL != "" {
		pub, err := url.Parse(strings.TrimRight(opts.PublicURL, "/"))
		if err != nil || pub.Scheme == "" || pub.Host == "" {
			return nil, fmt.Errorf("PATCHLINE_PUBLIC_URL: want an absolute URL such as https://patchline.example.com, got %q", opts.PublicURL)
		}
		a.secure = pub.Scheme == "https"
	}
	if opts.OIDC == nil {
		return a, nil
	}

	cfg := *opts.OIDC
	if len(cfg.GroupsClaims) == 0 {
		cfg.GroupsClaims = []string{"groups"}
	}
	if opts.PublicURL == "" {
		return nil, errors.New("PATCHLINE_PUBLIC_URL is required with OIDC (the redirect URI is PATCHLINE_PUBLIC_URL/auth/callback)")
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %s: %w", cfg.Issuer, err)
	}
	scopes := []string{oidc.ScopeOpenID}
	for _, s := range cfg.Scopes {
		if s != oidc.ScopeOpenID && s != "" {
			scopes = append(scopes, s)
		}
	}
	a.oidcCfg = cfg
	a.oauth = oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  strings.TrimRight(opts.PublicURL, "/") + "/auth/callback",
		Scopes:       scopes,
	}
	a.verifier = provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	return a, nil
}

// SSO reports whether OIDC sign-in is configured.
func (a *Authenticator) SSO() bool { return a != nil && a.verifier != nil }

// Local reports whether the local admin can sign in.
func (a *Authenticator) Local() bool { return a != nil && a.opts.LocalAdmin }

// Routes registers the sign-in endpoints.
func (a *Authenticator) Routes(mux *http.ServeMux) {
	if a == nil {
		return
	}
	mux.HandleFunc("POST /auth/logout", a.logout)
	if a.SSO() {
		mux.HandleFunc("GET /auth/login", a.login)
		mux.HandleFunc("GET /auth/callback", a.callback)
	}
	if a.Local() {
		mux.HandleFunc("POST /auth/local", a.localLogin)
		mux.HandleFunc("POST /account/password", a.changePassword)
	}
}

// public paths are served without a session.
func public(path string) bool {
	// /webhooks/ and /ingest/ authenticate with their own secrets.
	for _, p := range []string{"/healthz", "/readyz", "/webhooks/", "/ingest/", "/static/", "/auth/", "/prefs", "/login", "/signed-out"} {
		if path == p || (strings.HasSuffix(p, "/") && strings.HasPrefix(path, p)) {
			return true
		}
	}
	return false
}

// passwordPaths stay reachable while the local admin must change the
// default password.
func passwordPaths(path string) bool {
	return path == "/account/password" || path == "/auth/logout"
}

// Middleware attaches the principal and enforces sign-in, findings.read,
// the password change of a fresh local admin and the CSRF token on forms.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a == nil {
			p := &Principal{Perms: Set{FindingsRead: true}}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
			return
		}
		if public(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		p, err := a.principal(r)
		if err != nil {
			a.logger.Error("load session", "err", err)
			http.Error(w, "could not load session", http.StatusInternalServerError)
			return
		}
		if p == nil {
			if a.opts.AllowAnonymous && !unsafe(r.Method) {
				p = &Principal{Perms: Set{FindingsRead: true}}
				next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
				return
			}
			a.unauthenticated(w, r)
			return
		}
		if p.MustChangePassword && !passwordPaths(r.URL.Path) {
			if r.Method == http.MethodGet && !strings.HasPrefix(r.URL.Path, "/api/") {
				http.Redirect(w, r, "/account/password", http.StatusSeeOther)
				return
			}
			http.Error(w, "change the default admin password first", http.StatusForbidden)
			return
		}
		if !p.Can(FindingsRead) {
			http.Error(w, "You are signed in as "+p.Identity()+", but have no access to Patchline. Ask an administrator to add one of your groups to the access policy.", http.StatusForbidden)
			return
		}
		if unsafe(r.Method) && !validCSRF(r, p.CSRF) {
			http.Error(w, "invalid or missing CSRF token: reload the page and try again", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

func (a *Authenticator) principal(r *http.Request) (*Principal, error) {
	c, err := r.Cookie(cookieSession)
	if err != nil || c.Value == "" {
		return nil, nil
	}
	sess, err := a.store.GetSession(r.Context(), hashID(c.Value))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p := &Principal{
		Authenticated: true,
		Subject:       sess.Subject,
		Email:         sess.Email,
		Name:          sess.Name,
		Groups:        sess.Groups,
		CSRF:          sess.CSRF,
		sessionHash:   sess.IDHash,
	}
	if user, ok := strings.CutPrefix(sess.Subject, localPrefix); ok {
		// The local admin holds every permission; a disabled or reset
		// account ends its sessions.
		acct, err := a.store.GetLocalAccount(r.Context(), user)
		if errors.Is(err, sql.ErrNoRows) || !a.opts.LocalAdmin {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if acct.PasswordChangedAt > sess.CreatedAt {
			return nil, nil
		}
		p.Local, p.MustChangePassword, p.Perms = true, acct.MustChange, Set{All: true}
		return p, nil
	}
	p.Perms = a.policy.For(sess.Subject, sess.Email, sess.Groups)
	return p, nil
}

func (a *Authenticator) unauthenticated(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") || r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"sign in required"}` + "\n"))
		return
	}
	next := url.QueryEscape(r.URL.RequestURI())
	if !a.Local() {
		// Only SSO: go straight to the provider.
		http.Redirect(w, r, "/auth/login?next="+next, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login?next="+next, http.StatusSeeOther)
}

// startSession creates a session and sets its cookie.
func (a *Authenticator) startSession(w http.ResponseWriter, r *http.Request, sess store.Session) error {
	id := randomToken()
	sess.IDHash, sess.CSRF = hashID(id), randomToken()
	sess.CreatedAt, sess.ExpiresAt = a.store.TimeFromNow(0), a.store.TimeFromNow(a.opts.SessionTTL)
	if err := a.store.CreateSession(r.Context(), sess); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieSession, Value: id, Path: "/", HttpOnly: true, Secure: a.secure || r.TLS != nil,
		SameSite: http.SameSiteLaxMode, MaxAge: int(a.opts.SessionTTL.Seconds()),
	})
	return nil
}

func unsafe(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// validCSRF checks the form's csrf field against the session's token.
func validCSRF(r *http.Request, want string) bool {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		return false
	}
	got := r.PostForm.Get("csrf")
	return want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (a *Authenticator) login(w http.ResponseWriter, r *http.Request) {
	state, nonce, verifier := randomToken(), randomToken(), oauth2.GenerateVerifier()
	if err := a.store.SaveAuthState(r.Context(), store.AuthState{
		State: state, Nonce: nonce, Verifier: verifier, Next: SafeNext(r.URL.Query().Get("next")),
		ExpiresAt: a.store.TimeFromNow(loginTTL),
	}); err != nil {
		a.logger.Error("save login state", "err", err)
		http.Error(w, "could not start sign-in", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, a.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func (a *Authenticator) callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		a.logger.Warn("sign-in refused by the provider", "error", e, "description", q.Get("error_description"))
		http.Error(w, "sign-in failed: "+e, http.StatusUnauthorized)
		return
	}
	st, err := a.store.TakeAuthState(ctx, q.Get("state"))
	if err != nil {
		http.Error(w, "sign-in expired or was already used: start again", http.StatusBadRequest)
		return
	}
	tok, err := a.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(st.Verifier))
	if err != nil {
		a.logger.Warn("oidc code exchange", "err", err)
		http.Error(w, "sign-in failed: could not exchange the code", http.StatusBadGateway)
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		http.Error(w, "sign-in failed: no ID token", http.StatusBadGateway)
		return
	}
	idt, err := a.verifier.Verify(ctx, raw)
	if err != nil {
		a.logger.Warn("oidc id token", "err", err)
		http.Error(w, "sign-in failed: invalid ID token", http.StatusUnauthorized)
		return
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(st.Nonce)) != 1 {
		http.Error(w, "sign-in failed: nonce mismatch", http.StatusUnauthorized)
		return
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		http.Error(w, "sign-in failed: unreadable claims", http.StatusBadGateway)
		return
	}
	if strings.HasPrefix(idt.Subject, localPrefix) {
		// Reserved for the local admin's sessions.
		http.Error(w, "sign-in failed: unsupported subject", http.StatusUnauthorized)
		return
	}
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	if name == "" {
		name, _ = claims["preferred_username"].(string)
	}
	groups := groupsFrom(claims, a.oidcCfg.GroupsClaims)
	if err := a.startSession(w, r, store.Session{Subject: idt.Subject, Email: email, Name: name, Groups: groups}); err != nil {
		a.logger.Error("create session", "err", err)
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	a.logger.Info("signed in", "subject", idt.Subject, "email", email, "groups", groups,
		"permissions", a.policy.For(idt.Subject, email, groups).List())
	http.Redirect(w, r, st.Next, http.StatusSeeOther)
}

func (a *Authenticator) logout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(cookieSession)
	if err == nil && c.Value != "" {
		sess, err := a.store.GetSession(r.Context(), hashID(c.Value))
		if err == nil {
			// Logout changes state, so it needs the session's CSRF token too.
			if !validCSRF(r, sess.CSRF) {
				http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
				return
			}
			if err := a.store.DeleteSession(r.Context(), sess.IDHash); err != nil {
				a.logger.Error("delete session", "err", err)
			}
		}
	}
	http.SetCookie(w, &http.Cookie{Name: cookieSession, Value: "", Path: "/", HttpOnly: true, Secure: a.secure,
		SameSite: http.SameSiteLaxMode, MaxAge: -1})
	http.Redirect(w, r, "/signed-out", http.StatusSeeOther)
}

// groupsFrom reads groups from the named claims. A claim may be a list of
// strings or a single string; dotted names walk nested objects.
func groupsFrom(claims map[string]any, names []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(g string) {
		if g = strings.TrimSpace(g); g != "" && !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	for _, name := range names {
		var v any = claims
		for _, part := range strings.Split(name, ".") {
			m, ok := v.(map[string]any)
			if !ok {
				v = nil
				break
			}
			v = m[part]
		}
		switch t := v.(type) {
		case string:
			add(t)
		case []any:
			for _, item := range t {
				if s, ok := item.(string); ok {
					add(s)
				}
			}
		}
	}
	return out
}

// SafeNext returns next when it is a path on this site, else "/". Browsers
// drop tabs and newlines and read "\\" as "/", so "/\t/evil.example" and
// "/\\evil.example" would leave the site: any control character or
// backslash is refused, as is "//".
func SafeNext(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	for _, c := range next {
		if c < 0x20 || c == 0x7f || c == '\\' {
			return "/"
		}
	}
	if u, err := url.Parse(next); err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return next
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// MarshalJSON keeps the set readable in logs and the API.
func (s Set) MarshalJSON() ([]byte, error) { return json.Marshal(s.List()) }
