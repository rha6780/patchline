package auth

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rha6780/patchline/internal/store"
)

func TestAPITokens(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	a, err := New(ctx, Options{LocalAdmin: true}, DefaultPolicy(), st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mint := func(perms []string, expires *string) string {
		raw, prefix, hash := NewToken()
		if _, err := st.CreateToken(ctx, store.APIToken{Name: "ci", Prefix: prefix, Permissions: perms, ExpiresAt: expires}, hash, store.Actor{Subject: "u"}); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	reader := mint([]string{"findings.read"}, nil)
	uploader := mint([]string{"sbom.upload"}, nil)
	past := store.FormatTime(time.Now().Add(-time.Hour))
	expired := mint([]string{"findings.read"}, &past)

	var seen *Principal
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = FromContext(r.Context()) }))
	call := func(path, token string) int {
		seen = nil
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := call("/api/v1/findings", reader); code != 200 || seen == nil || !seen.Token || !seen.Can(FindingsRead) || seen.Can(SBOMUpload) {
		t.Fatalf("reader: %d %+v", code, seen)
	}
	for name, tok := range map[string]string{"unknown": "plt_nope", "expired": expired, "upload only": uploader} {
		if code := call("/api/v1/findings", tok); code != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, code)
		}
	}
	// Tokens are for the API: a page still wants a session.
	if code := call("/findings", reader); code != http.StatusSeeOther || seen != nil {
		t.Errorf("token on a page: %d", code)
	}

	// /ingest/sbom asks for sbom.upload.
	req := httptest.NewRequest(http.MethodPost, "/ingest/sbom", nil)
	req.Header.Set("Authorization", "Bearer "+uploader)
	if ok, err := a.RequestAllows(req, SBOMUpload); !ok || err != nil {
		t.Errorf("uploader: %v %v", ok, err)
	}
	req.Header.Set("Authorization", "Bearer "+reader)
	if ok, _ := a.RequestAllows(req, SBOMUpload); ok {
		t.Error("reader may upload")
	}

	// Revoked: refused from then on.
	list, _ := st.ListTokens(ctx)
	for _, tk := range list {
		if err := st.RevokeToken(ctx, tk.ID, store.Actor{Subject: "u"}); err != nil {
			t.Fatal(err)
		}
	}
	if code := call("/api/v1/findings", reader); code != http.StatusUnauthorized {
		t.Errorf("revoked: %d", code)
	}
	if err := st.RevokeToken(ctx, list[0].ID, store.Actor{Subject: "u"}); err != store.ErrTokenRevoked {
		t.Errorf("second revoke: %v", err)
	}
}
