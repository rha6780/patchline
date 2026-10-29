package kev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestFetch(t *testing.T) {
	body, _ := os.ReadFile("testdata/catalog.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
	defer srv.Close()
	c, err := Fetch(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != "2026.10.28" || len(c.Vulnerabilities) != 2 || c.Vulnerabilities[1].CVEID != "CVE-2017-5638" {
		t.Fatalf("catalog = %+v", c)
	}
}

func TestFetchErrors(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"status": func(w http.ResponseWriter, r *http.Request) { http.Error(w, "nope", http.StatusBadGateway) },
		"empty":  func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"vulnerabilities":[]}`)) },
		"json":   func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`<html>`)) },
	} {
		srv := httptest.NewServer(h)
		if _, err := Fetch(context.Background(), srv.URL, nil); err == nil {
			t.Errorf("%s: expected error", name)
		}
		srv.Close()
	}
}
