package auth

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/rha6780/patchline/internal/store"
)

// The built-in admin account. It starts with the password "admin", which
// must be changed at the first sign-in.
const (
	AdminUser       = "admin"
	DefaultPassword = "admin"

	localPrefix = "local:"

	// MinPasswordLength is the shortest password accepted for the admin.
	MinPasswordLength = 12
	bcryptCost        = 12
)

// LocalStore keeps the local admin account.
type LocalStore interface {
	GetLocalAccount(ctx context.Context, username string) (store.LocalAccount, error)
	RecordLoginSuccess(ctx context.Context, username string) error
	SetLocalPassword(ctx context.Context, username, hash string, mustChange bool, by store.Actor, keepSession string) error
}

// HashPassword returns a bcrypt hash.
func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	return string(h), err
}

// dummyHash keeps the time of a login for an unknown user close to that of
// a wrong password.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("not-a-password"), bcryptCost)

// CheckNewPassword returns the i18n error key for a password the admin may
// not use, or "".
func CheckNewPassword(password, confirm, current string) string {
	switch {
	case password != confirm:
		return "password_mismatch"
	case len(password) < MinPasswordLength:
		return "password_short"
	case len(password) > 72: // bcrypt ignores the rest
		return "password_long"
	case strings.EqualFold(password, DefaultPassword), strings.EqualFold(password, AdminUser):
		return "password_default"
	case password == current:
		return "password_same"
	}
	return ""
}

// sameOrigin rejects cross-site form posts: browsers send Origin with POST.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	return err == nil && u.Host == r.Host
}

func loginRedirect(w http.ResponseWriter, r *http.Request, key, next string) {
	q := url.Values{"error": {key}}
	if next != "/" {
		q.Set("next", next)
	}
	http.Redirect(w, r, "/login?"+q.Encode(), http.StatusSeeOther)
}

func (a *Authenticator) localLogin(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "cross-site sign-in refused", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	user, password := strings.TrimSpace(r.PostForm.Get("username")), r.PostForm.Get("password")
	next := SafeNext(r.PostForm.Get("next"))
	addr := clientAddr(r, a.opts.TrustedProxies)
	client := clientKey(addr)

	if until, ok := a.throttle.blocked(client); ok {
		a.logger.Warn("local sign-in refused", "username", user, "reason", "too many failures", "client", client, "until", until)
		loginRedirect(w, r, "login_locked", next)
		return
	}
	acct, err := a.store.GetLocalAccount(ctx, user)
	unknown := errors.Is(err, sql.ErrNoRows)
	if err != nil && !unknown {
		a.logger.Error("load local account", "err", err)
		http.Error(w, "could not sign in", http.StatusInternalServerError)
		return
	}
	// An unknown user costs the same check as a wrong password.
	hash := dummyHash
	if !unknown {
		hash = []byte(acct.PasswordHash)
	}
	var match bool
	if !a.throttle.check(ctx, func() { match = bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil }) {
		a.logger.Warn("local sign-in refused", "username", user, "reason", "busy", "client", client)
		loginRedirect(w, r, "login_busy", next)
		return
	}
	if unknown || !match {
		locked := a.throttle.fail(client)
		reason := "wrong password"
		if unknown {
			reason = "unknown user"
		}
		a.logger.Warn("local sign-in failed", "username", user, "reason", reason, "client", client, "blocked", locked)
		if locked {
			loginRedirect(w, r, "login_locked", next)
			return
		}
		loginRedirect(w, r, "login_invalid", next)
		return
	}
	a.throttle.succeed(client)
	if err := a.store.RecordLoginSuccess(ctx, user); err != nil {
		a.logger.Error("record login", "err", err)
	}
	if err := a.startSession(w, r, store.Session{Subject: localPrefix + user, Name: user}); err != nil {
		a.logger.Error("create session", "err", err)
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	a.logger.Info("signed in", "subject", localPrefix+user, "local", true, "must_change_password", acct.MustChange)
	if acct.MustChange {
		http.Redirect(w, r, "/account/password", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// changePassword replaces the local admin's password. The middleware has
// already checked the session and its CSRF token.
func (a *Authenticator) changePassword(w http.ResponseWriter, r *http.Request) {
	p := FromContext(r.Context())
	user, ok := strings.CutPrefix(p.Subject, localPrefix)
	if !p.Local || !ok {
		http.Error(w, "only the local admin has a password here", http.StatusForbidden)
		return
	}
	ctx := r.Context()
	acct, err := a.store.GetLocalAccount(ctx, user)
	if err != nil {
		a.logger.Error("load local account", "err", err)
		http.Error(w, "could not load the account", http.StatusInternalServerError)
		return
	}
	current, password, confirm := r.PostForm.Get("current"), r.PostForm.Get("password"), r.PostForm.Get("confirm")
	back := func(key string) {
		http.Redirect(w, r, "/account/password?error="+key, http.StatusSeeOther)
	}
	if bcrypt.CompareHashAndPassword([]byte(acct.PasswordHash), []byte(current)) != nil {
		back("password_current")
		return
	}
	if key := CheckNewPassword(password, confirm, current); key != "" {
		back(key)
		return
	}
	hash, err := HashPassword(password)
	if err != nil {
		http.Error(w, "could not hash the password", http.StatusInternalServerError)
		return
	}
	if err := a.store.SetLocalPassword(ctx, user, hash, false, p.Actor(), p.sessionHash); err != nil {
		a.logger.Error("set local password", "err", err)
		http.Error(w, "could not save the password", http.StatusInternalServerError)
		return
	}
	a.logger.Info("local admin password changed", "username", user)
	http.Redirect(w, r, "/?notice=password_changed", http.StatusSeeOther)
}
