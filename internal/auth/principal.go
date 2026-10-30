package auth

import (
	"context"

	"github.com/rha6780/patchline/internal/store"
)

// Principal is the person behind a request.
type Principal struct {
	// Authenticated is false when sign-in is not configured: everyone is
	// an anonymous reader.
	Authenticated bool
	Subject       string
	Email         string
	Name          string
	Groups        []string
	Perms         Set
	// CSRF must be sent back with every form that changes something.
	CSRF string
	// Token is set for requests authenticated with an API token.
	Token bool
	// Local is the built-in admin account; MustChangePassword is set
	// until its default password has been replaced.
	Local              bool
	MustChangePassword bool

	sessionHash string
}

// Can reports whether the principal holds p.
func (p *Principal) Can(perm Permission) bool { return p != nil && p.Perms.Has(perm) }

// Identity is how the person is shown and assigned: email when known.
func (p *Principal) Identity() string {
	if p.Email != "" {
		return p.Email
	}
	return p.Subject
}

// Label is the name to show.
func (p *Principal) Label() string {
	if p.Name != "" {
		return p.Name
	}
	return p.Identity()
}

// Actor is the principal as recorded on changes.
func (p *Principal) Actor() store.Actor {
	return store.Actor{Subject: p.Subject, Name: p.Label()}
}

type ctxKey struct{}

// WithPrincipal returns a context carrying p.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext returns the request's principal. It never returns nil: a
// request that did not pass the middleware gets an anonymous principal
// without permissions.
func FromContext(ctx context.Context) *Principal {
	if p, ok := ctx.Value(ctxKey{}).(*Principal); ok && p != nil {
		return p
	}
	return &Principal{Perms: Set{}}
}
