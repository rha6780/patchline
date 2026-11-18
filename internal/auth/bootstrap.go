package auth

import (
	"context"
	"crypto/rand"

	"golang.org/x/crypto/bcrypt"

	"github.com/rha6780/patchline/internal/store"
)

// AdminStore creates and resets the local admin.
type AdminStore interface {
	EnsureLocalAccount(ctx context.Context, username, hash string) (bool, error)
	GetLocalAccount(ctx context.Context, username string) (store.LocalAccount, error)
	SetLocalPassword(ctx context.Context, username, hash string, mustChange bool, by store.Actor, keepSession string) error
}

// Bootstrap says what EnsureAdmin did.
type Bootstrap struct {
	// Password is the one-time password set now; empty when the account
	// was left as it was.
	Password string
	// Generated is true when Password is random (not configured).
	Generated bool
	// Rotated is true when an account still on LegacyPassword was given
	// a new one.
	Rotated bool
}

// EnsureAdmin creates the local admin with a one-time password, to be
// changed at the first sign-in: configured when it is set, otherwise a
// random one the caller must show the operator. An existing account that
// still has the fixed password older versions started with gets a new
// one, so a fresh install exposed before anyone signed in cannot be taken
// with admin / admin.
func EnsureAdmin(ctx context.Context, st AdminStore, configured string) (Bootstrap, error) {
	b := Bootstrap{Password: configured}
	if b.Password == "" {
		b.Password, b.Generated = GeneratePassword(), true
	}
	hash, err := HashPassword(b.Password)
	if err != nil {
		return Bootstrap{}, err
	}
	created, err := st.EnsureLocalAccount(ctx, AdminUser, hash)
	if err != nil {
		return Bootstrap{}, err
	}
	if created {
		return b, nil
	}
	acct, err := st.GetLocalAccount(ctx, AdminUser)
	if err != nil {
		return Bootstrap{}, err
	}
	legacy := acct.MustChange && configured != LegacyPassword &&
		bcrypt.CompareHashAndPassword([]byte(acct.PasswordHash), []byte(LegacyPassword)) == nil
	if !legacy {
		return Bootstrap{}, nil
	}
	if err := st.SetLocalPassword(ctx, AdminUser, hash, true, store.Actor{Subject: "system", Name: "patchline"}, ""); err != nil {
		return Bootstrap{}, err
	}
	b.Rotated = true
	return b, nil
}

// passwordAlphabet leaves out characters that are easy to misread
// (0/O, 1/l/I).
const passwordAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// GeneratePassword returns a random 20-character password (about 116 bits).
func GeneratePassword() string {
	return randomFrom(passwordAlphabet, 20)
}

func randomFrom(alphabet string, n int) string {
	out := make([]byte, n)
	limit := 256 - 256%len(alphabet) // reject bytes that would bias the choice
	buf := make([]byte, 1)
	for i := 0; i < n; {
		if _, err := rand.Read(buf); err != nil {
			panic(err) // crypto/rand does not fail on supported platforms
		}
		if int(buf[0]) < limit {
			out[i] = alphabet[int(buf[0])%len(alphabet)]
			i++
		}
	}
	return string(out)
}
