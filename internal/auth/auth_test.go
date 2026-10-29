package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/rha6780/patchline/internal/store"
)

// fakeIdP is a minimal OpenID provider: discovery, JWKS, authorize and token.
type fakeIdP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	claims map[string]any // extra ID token claims

	mu       sync.Mutex
	nonces   map[string]string // code -> nonce
	verifier map[string]string // code -> code_challenge
}

func newIdP(t *testing.T, claims map[string]any) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeIdP{key: key, claims: claims, nonces: map[string]string{}, verifier: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.srv.URL, "authorization_endpoint": p.srv.URL + "/authorize",
			"token_endpoint": p.srv.URL + "/token", "jwks_uri": p.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	// The browser leg: approve at once and send the code back.
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			http.Error(w, "PKCE required", http.StatusBadRequest)
			return
		}
		code := "code-" + q.Get("state")[:8]
		p.mu.Lock()
		p.nonces[code] = q.Get("nonce")
		p.verifier[code] = q.Get("code_challenge")
		p.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		code := r.PostForm.Get("code")
		p.mu.Lock()
		nonce, ok := p.nonces[code]
		delete(p.nonces, code)
		p.mu.Unlock()
		if !ok || r.PostForm.Get("code_verifier") == "" {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		claims := map[string]any{
			"iss": p.srv.URL, "aud": "patchline", "sub": "user-1", "nonce": nonce,
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		}
		for k, v := range p.claims {
			claims[k] = v
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": p.sign(t, claims)})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeIdP) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
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

// app is Patchline's side: the authenticator in front of a handler that
// reports the principal.
func app(t *testing.T, idp *fakeIdP, policy Policy) (*httptest.Server, *http.Client) {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := FromContext(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]any{"subject": p.Subject, "email": p.Email, "groups": p.Groups,
			"perms": p.Perms, "csrf": p.CSRF, "method": r.Method})
	})
	srv = httptest.NewUnstartedServer(nil)
	srv.Start()
	t.Cleanup(srv.Close)
	a, err := New(context.Background(), Options{PublicURL: srv.URL, OIDC: &Config{Issuer: idp.srv.URL, ClientID: "patchline",
		ClientSecret: "s", GroupsClaims: []string{"groups", "realm_access.roles"}}}, policy, newStore(t),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	a.Routes(mux)
	srv.Config.Handler = a.Middleware(mux)
	jar, _ := cookiejar.New(nil)
	return srv, &http.Client{Jar: jar}
}

func readJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode %s: %v", resp.Request.URL, err)
	}
	return m
}

func TestSignInFlow(t *testing.T) {
	idp := newIdP(t, map[string]any{"email": "alice@example.com", "name": "Alice",
		"groups": []string{"sec-team"}, "realm_access": map[string]any{"roles": []string{"developers"}}})
	policy, err := ParsePolicy([]byte(`
default: [findings.read]
groups:
  sec-team: [exceptions.approve]
  developers: [findings.assign]
`))
	if err != nil {
		t.Fatal(err)
	}
	srv, client := app(t, idp, policy)

	// Without a session: pages redirect to sign-in, the API answers 401.
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Get(srv.URL + "/findings?open=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/auth/login?next=%2Ffindings%3Fopen%3D1" {
		t.Fatalf("page: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, _ = noRedirect.Get(srv.URL + "/api/v1/findings")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("api: %d", resp.StatusCode)
	}
	// Webhooks and health checks never need a session.
	resp, _ = noRedirect.Post(srv.URL+"/webhooks/dependency-track", "application/json", strings.NewReader("{}"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("webhook: %d", resp.StatusCode)
	}

	// Sign in: login -> IdP -> callback -> back to the page.
	resp, err = client.Get(srv.URL + "/findings?open=1")
	if err != nil {
		t.Fatal(err)
	}
	got := readJSON(t, resp)
	if resp.Request.URL.Path != "/findings" || got["subject"] != "user-1" || got["email"] != "alice@example.com" {
		t.Fatalf("after sign-in: %s %v", resp.Request.URL, got)
	}
	if !reflect.DeepEqual(got["groups"], []any{"sec-team", "developers"}) {
		t.Errorf("groups = %v", got["groups"])
	}
	if !reflect.DeepEqual(got["perms"], []any{"findings.read", "findings.assign", "exceptions.approve"}) {
		t.Errorf("perms = %v", got["perms"])
	}
	csrf, _ := got["csrf"].(string)

	// Forms need the session's CSRF token.
	resp, _ = client.PostForm(srv.URL+"/findings/1/assign", url.Values{"assignee": {"x"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("post without csrf: %d", resp.StatusCode)
	}
	resp, _ = client.PostForm(srv.URL+"/findings/1/assign", url.Values{"assignee": {"x"}, "csrf": {csrf}})
	if got := readJSON(t, resp); got["method"] != "POST" {
		t.Fatalf("post with csrf: %v", got)
	}

	// A callback state is used once.
	resp, _ = noRedirect.Get(srv.URL + "/auth/callback?code=x&state=unknown")
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown state: %d", resp.StatusCode)
	}

	// Sign out ends the session.
	resp, _ = client.PostForm(srv.URL+"/auth/logout", url.Values{"csrf": {csrf}})
	resp.Body.Close()
	resp, _ = (&http.Client{Jar: client.Jar, CheckRedirect: noRedirect.CheckRedirect}).Get(srv.URL + "/findings")
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("after sign-out: %d", resp.StatusCode)
	}
}

func TestSignInWithoutAccess(t *testing.T) {
	idp := newIdP(t, map[string]any{"email": "eve@example.com", "groups": []string{"contractors"}})
	srv, client := app(t, idp, Policy{Groups: map[string][]Permission{"staff": {FindingsRead}}})
	resp, err := client.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "eve@example.com") {
		t.Fatalf("got %d %s", resp.StatusCode, body)
	}
}

func TestSignInRejectsForgedToken(t *testing.T) {
	idp := newIdP(t, nil)
	other := newIdP(t, nil)
	a, err := New(context.Background(), Options{PublicURL: "https://p.example.com", OIDC: &Config{Issuer: idp.srv.URL, ClientID: "patchline"}},
		DefaultPolicy(), newStore(t), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	// Signed by another key, and for another audience.
	forged := other.sign(t, map[string]any{"iss": idp.srv.URL, "aud": "patchline", "sub": "x",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()})
	if _, err := a.verifier.Verify(context.Background(), forged); err == nil {
		t.Error("token signed by another key was accepted")
	}
	wrongAud := idp.sign(t, map[string]any{"iss": idp.srv.URL, "aud": "someone-else", "sub": "x",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()})
	if _, err := a.verifier.Verify(context.Background(), wrongAud); err == nil {
		t.Error("token for another audience was accepted")
	}
}

func TestDisabled(t *testing.T) {
	var a *Authenticator
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := FromContext(r.Context())
		if !p.Can(FindingsRead) || p.Can(FindingsAssign) || p.Authenticated {
			t.Errorf("anonymous principal = %+v", p)
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}

func TestPolicy(t *testing.T) {
	if _, err := ParsePolicy([]byte("groups:\n  ops: [settings.webhook]\n")); err == nil || !strings.Contains(err.Error(), "settings.webhook") {
		t.Errorf("unknown permission: %v", err)
	}
	if _, err := ParsePolicy([]byte("roles: {}\n")); err == nil {
		t.Error("unknown field accepted")
	}
	p, err := ParsePolicy([]byte(`
groups:
  sec-team: [findings.read, exceptions.approve]
users:
  alice@example.com: ["*"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if s := p.For("u2", "bob@example.com", []string{"sec-team", "other"}); !s.Has(ExceptionsApprove) || s.Has(SettingsWebhooks) {
		t.Errorf("bob = %v", s.List())
	}
	if s := p.For("u1", "Alice@Example.com", nil); !s.Has(SettingsWebhooks) || len(s.List()) != len(Permissions) {
		t.Errorf("alice = %v", s.List())
	}
	if s := p.For("u3", "", nil); s.Has(FindingsRead) {
		t.Errorf("nobody = %v", s.List())
	}
	if got := p.Summary(); got != "exceptions.approve: alice@example.com, sec-team; settings.webhooks: alice@example.com" {
		t.Errorf("summary = %q", got)
	}
}

func TestGroupsFrom(t *testing.T) {
	claims := map[string]any{
		"groups": []any{"a", "b", 3}, "roles": "admin",
		"realm_access": map[string]any{"roles": []any{"b", "c"}},
	}
	got := groupsFrom(claims, []string{"groups", "roles", "realm_access.roles", "missing.claim"})
	if !reflect.DeepEqual(got, []string{"a", "b", "admin", "c"}) {
		t.Errorf("got %v", got)
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"/findings?x=1": "/findings?x=1", "": "/", "https://evil": "/", "//evil": "/", "/\\evil": "/",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q", in, got)
		}
	}
}

func TestExamplePolicy(t *testing.T) {
	p, err := LoadPolicy(filepath.Join("..", "..", "examples", "access", "access-policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if s := p.For("x", "", []string{"developers"}); !s.Has(ExceptionsRequest) || s.Has(ExceptionsApprove) {
		t.Errorf("developers = %v", s.List())
	}
}
