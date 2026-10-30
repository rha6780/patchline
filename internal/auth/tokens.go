package auth

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

// TokenPrefix starts every API token, so it is recognizable in logs and
// secret scanners.
const TokenPrefix = "plt_"

// NewToken returns a fresh API token, the prefix shown in lists and the
// hash to store.
func NewToken() (raw, prefix, hash string) {
	raw = TokenPrefix + randomToken()
	return raw, raw[:len(TokenPrefix)+6], hashID(raw)
}

// bearerToken returns an API token from the Authorization header.
func bearerToken(r *http.Request) (string, bool) {
	v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !strings.HasPrefix(v, TokenPrefix) {
		return "", false
	}
	return v, true
}

// TokenPrincipal returns the principal of a valid API token, or nil when
// the token is unknown, expired or revoked.
func (a *Authenticator) TokenPrincipal(ctx context.Context, raw string) (*Principal, error) {
	if a == nil || !strings.HasPrefix(raw, TokenPrefix) {
		return nil, nil
	}
	t, err := a.store.TokenByHash(ctx, hashID(raw))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	perms := Set{}
	for _, p := range t.Permissions {
		perms[Permission(p)] = true
	}
	return &Principal{Authenticated: true, Token: true, Subject: "token:" + strconv.FormatInt(t.ID, 10), Name: t.Name, Perms: perms}, nil
}

// RequestAllows reports whether the request carries an API token with perm
// (for endpoints outside /api that tools call, such as /ingest/sbom).
func (a *Authenticator) RequestAllows(r *http.Request, perm Permission) (bool, error) {
	raw, ok := bearerToken(r)
	if !ok {
		return false, nil
	}
	p, err := a.TokenPrincipal(r.Context(), raw)
	if err != nil || p == nil {
		return false, err
	}
	return p.Can(perm), nil
}
