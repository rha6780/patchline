package auth

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/rha6780/patchline/internal/store"
)

func works(t *testing.T, st *store.Store, password string) bool {
	t.Helper()
	acct, err := st.GetLocalAccount(context.Background(), AdminUser)
	if err != nil {
		t.Fatal(err)
	}
	return bcrypt.CompareHashAndPassword([]byte(acct.PasswordHash), []byte(password)) == nil
}

func TestEnsureAdmin(t *testing.T) {
	ctx := context.Background()

	t.Run("new: random one-time password", func(t *testing.T) {
		st := newStore(t)
		b, err := EnsureAdmin(ctx, st, "")
		if err != nil || !b.Generated || len(b.Password) != 20 || b.Rotated {
			t.Fatalf("%+v %v", b, err)
		}
		if !works(t, st, b.Password) || works(t, st, LegacyPassword) {
			t.Fatal("the account does not have the generated password")
		}
		if acct, _ := st.GetLocalAccount(ctx, AdminUser); !acct.MustChange {
			t.Fatal("the one-time password must be changed")
		}
		// The next start leaves it alone and shows nothing.
		if again, err := EnsureAdmin(ctx, st, ""); err != nil || again.Password != "" || !works(t, st, b.Password) {
			t.Fatalf("second start: %+v %v", again, err)
		}
	})

	t.Run("new: configured", func(t *testing.T) {
		st := newStore(t)
		b, err := EnsureAdmin(ctx, st, "from-the-environment")
		if err != nil || b.Generated || b.Password != "from-the-environment" || !works(t, st, "from-the-environment") {
			t.Fatalf("%+v %v", b, err)
		}
	})

	t.Run("still admin/admin: replaced", func(t *testing.T) {
		st := newStore(t)
		hash, _ := HashPassword(LegacyPassword)
		if _, err := st.EnsureLocalAccount(ctx, AdminUser, hash); err != nil {
			t.Fatal(err)
		}
		b, err := EnsureAdmin(ctx, st, "")
		if err != nil || !b.Rotated || !b.Generated || works(t, st, LegacyPassword) || !works(t, st, b.Password) {
			t.Fatalf("%+v %v", b, err)
		}
	})

	t.Run("demo keeps admin/admin on purpose", func(t *testing.T) {
		st := newStore(t)
		hash, _ := HashPassword(LegacyPassword)
		if _, err := st.EnsureLocalAccount(ctx, AdminUser, hash); err != nil {
			t.Fatal(err)
		}
		if b, err := EnsureAdmin(ctx, st, LegacyPassword); err != nil || b.Rotated || !works(t, st, LegacyPassword) {
			t.Fatalf("%+v %v", b, err)
		}
	})

	t.Run("chosen password: untouched", func(t *testing.T) {
		st := newStore(t)
		if _, err := EnsureAdmin(ctx, st, ""); err != nil {
			t.Fatal(err)
		}
		hash, _ := HashPassword("a-chosen-password")
		if err := st.SetLocalPassword(ctx, AdminUser, hash, false, store.Actor{Subject: "local:admin"}, ""); err != nil {
			t.Fatal(err)
		}
		if b, err := EnsureAdmin(ctx, st, "something-else"); err != nil || b.Password != "" || !works(t, st, "a-chosen-password") {
			t.Fatalf("%+v %v", b, err)
		}
	})
}

func TestGeneratePassword(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		p := GeneratePassword()
		if len(p) != 20 || strings.Trim(p, passwordAlphabet) != "" || seen[p] {
			t.Fatalf("password %q", p)
		}
		seen[p] = true
	}
}
