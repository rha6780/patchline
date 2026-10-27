package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type pingFunc func(context.Context) error

func (f pingFunc) PingContext(ctx context.Context) error { return f(ctx) }

func TestEndpoints(t *testing.T) {
	ok := pingFunc(func(context.Context) error { return nil })
	down := pingFunc(func(context.Context) error { return errors.New("db down") })

	tests := []struct {
		name   string
		db     Pinger
		method string
		path   string
		want   int
	}{
		{"healthz", down, http.MethodGet, "/healthz", http.StatusOK},
		{"readyz ok", ok, http.MethodGet, "/readyz", http.StatusOK},
		{"readyz db down", down, http.MethodGet, "/readyz", http.StatusServiceUnavailable},
		{"wrong method", ok, http.MethodPost, "/healthz", http.StatusMethodNotAllowed},
		{"unknown path", ok, http.MethodGet, "/nope", http.StatusNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			New(tc.db).ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}
