package source

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rha6780/patchline/internal/store"
)

type both struct{}

func (both) Name() string    { return "tool" }
func (both) Webhook() string { return "the-tool" }
func (both) Accept(*http.Request, []byte, Secrets) (string, string, error) {
	return "", "", nil
}
func (both) Handle(context.Context, store.InboxItem, Env) (Outcome, error) { return Outcome{}, nil }

func TestRegistry(t *testing.T) {
	r := NewRegistry(both{}, "not an adapter")
	if _, ok := r.Receiver("the-tool"); !ok {
		t.Error("receiver not registered under its webhook path")
	}
	if _, ok := r.Reporter("tool"); !ok {
		t.Error("reporter not registered under its name")
	}
	if _, ok := r.Receiver("tool"); ok {
		t.Error("receiver registered under its source name")
	}
	var nilRegistry *Registry
	if _, ok := nilRegistry.Reporter("tool"); ok {
		t.Error("nil registry found a reporter")
	}
}

func TestTokenMatches(t *testing.T) {
	for _, tc := range []struct {
		url, auth, want string
		ok              bool
	}{
		{"/x", "", "", true},
		{"/x?token=s", "", "s", true},
		{"/x", "Bearer s", "s", true},
		{"/x", "Bearer t", "s", false},
		{"/x", "", "s", false},
	} {
		r := httptest.NewRequest("POST", tc.url, nil)
		if tc.auth != "" {
			r.Header.Set("Authorization", tc.auth)
		}
		if got := TokenMatches(r, tc.want); got != tc.ok {
			t.Errorf("%s %q want %q: %v", tc.url, tc.auth, tc.want, got)
		}
	}
}
