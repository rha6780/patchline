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
	// PublicURL is where users reach Patchline; the redirect URI is
	// PublicURL + "/auth/callback".
	PublicURL string
	// Scopes requested in addition to "openid".
	Scopes []string
	// GroupsClaims are the ID token claims read as groups, for example
	// "groups" or "roles". Dotted names read nested claims
	// ("realm_access.roles").
	GroupsClaims []string
	// SessionTTL is how long a sign-in lasts.
	SessionTTL time.Duration
}

// Store keeps sessions and logins in flight.
type Store interface {
	CreateSession(ctx context.Context, s store.Session) error
	GetSession(ctx context.Context, idHash string) (store.Session, error)
	DeleteSession(ctx context.Context, idHash string) error
	SaveAuthState(ctx context.Context, a store.AuthState) error
	TakeAuthState(ctx context.Context, state string) (store.AuthState, error)
	SessionExpiry(d time.Duration) string
}

// Authenticator signs people in and attaches a Principal to each request.
// A nil *Authenticator, or one without a provider, means sign-in is off:
// everyone is an anonymous reader and nothing can be changed.
type Authenticator struct {
	cfg      Config
	policy   Policy
	store    Store
	logger   *slog.Logger
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	secure   bool
}

const (
	cookieSession = "patchline_session"
	loginTTL      = 10 * time.Minute
)

// New discovers the provider and returns an Authenticator.
func New(ctx context.Context, cfg Config, policy Policy, st Store, logger *slog.Logger) (*Authenticator, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	if len(cfg.GroupsClaims) == 0 {
		cfg.GroupsClaims = []string{"groups"}
	}
	pub, err := url.Parse(strings.TrimRight(cfg.PublicURL, "/"))
	if err != nil || pub.Scheme == "" || pub.Host == "" {
		return nil, fmt.Errorf("PATCHLINE_PUBLIC_URL: want an absolute URL such as https://patchline.example.com, got %q", cfg.PublicURL)
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
	return &Authenticator{
		cfg:    cfg,
		policy: policy,
		store:  st,
		logger: logger,
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  pub.String() + "/auth/callback",
			Scopes:       scopes,
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		secure:   pub.Scheme == "https",
	}, nil
}

// Enabled reports whether sign-in is configured.
func (a *Authenticator) Enabled() bool { return a != nil && a.verifier != nil }

// Routes registers /auth/login, /auth/callback and /auth/logout.
func (a *Authenticator) Routes(mux *http.ServeMux) {
	if !a.Enabled() {
		return
	}
	mux.HandleFunc("GET /auth/login", a.login)
	mux.HandleFunc("GET /auth/callback", a.callback)
	mux.HandleFunc("POST /auth/logout", a.logout)
}

// public paths are served without a session.
func public(path string) bool {
	for _, p := range []string{"/healthz", "/readyz", "/webhooks/", "/static/", "/auth/", "/prefs", "/signed-out"} {
		if path == p || (strings.HasSuffix(p, "/") && strings.HasPrefix(path, p)) {
			return true
		}
	}
	return false
}

// Middleware attaches the principal and enforces sign-in, findings.read
// and the CSRF token on forms.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.Enabled() {
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
			a.unauthenticated(w, r)
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
	return &Principal{
		Authenticated: true,
		Subject:       sess.Subject,
		Email:         sess.Email,
		Name:          sess.Name,
		Groups:        sess.Groups,
		Perms:         a.policy.For(sess.Subject, sess.Email, sess.Groups),
		CSRF:          sess.CSRF,
	}, nil
}

func (a *Authenticator) unauthenticated(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") || r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"sign in required"}` + "\n"))
		return
	}
	http.Redirect(w, r, "/auth/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
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
		State: state, Nonce: nonce, Verifier: verifier, Next: safeNext(r.URL.Query().Get("next")),
		ExpiresAt: a.store.SessionExpiry(loginTTL),
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
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	if name == "" {
		name, _ = claims["preferred_username"].(string)
	}
	groups := groupsFrom(claims, a.cfg.GroupsClaims)

	id := randomToken()
	if err := a.store.CreateSession(ctx, store.Session{
		IDHash: hashID(id), Subject: idt.Subject, Email: email, Name: name, Groups: groups,
		CSRF: randomToken(), CreatedAt: a.store.SessionExpiry(0), ExpiresAt: a.store.SessionExpiry(a.cfg.SessionTTL),
	}); err != nil {
		a.logger.Error("create session", "err", err)
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	a.logger.Info("signed in", "subject", idt.Subject, "email", email, "groups", groups,
		"permissions", a.policy.For(idt.Subject, email, groups).List())
	http.SetCookie(w, &http.Cookie{
		Name: cookieSession, Value: id, Path: "/", HttpOnly: true, Secure: a.secure,
		SameSite: http.SameSiteLaxMode, MaxAge: int(a.cfg.SessionTTL.Seconds()),
	})
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

// safeNext keeps redirects on this site.
func safeNext(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
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
