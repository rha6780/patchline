package auth

import (
	"context"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestClientAddr(t *testing.T) {
	proxies := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.1.5/32")}
	for _, tc := range []struct {
		remote, xff string
		trusted     []netip.Prefix
		want        string
	}{
		{"203.0.113.7:5000", "", proxies, "203.0.113.7"},
		{"203.0.113.7:5000", "198.51.100.1", proxies, "203.0.113.7"},                     // not from a proxy: header ignored
		{"10.1.2.3:5000", "198.51.100.1", nil, "10.1.2.3"},                               // no trusted proxies
		{"10.1.2.3:5000", "198.51.100.1", proxies, "198.51.100.1"},                       // one proxy
		{"10.1.2.3:5000", "6.6.6.6, 198.51.100.1, 192.168.1.5", proxies, "198.51.100.1"}, // chain; forged left part ignored
		{"10.1.2.3:5000", "nonsense", proxies, "10.1.2.3"},
		{"[::ffff:10.1.2.3]:5000", "198.51.100.1", proxies, "198.51.100.1"}, // IPv4-mapped
	} {
		r := httptest.NewRequest("POST", "/auth/local", nil)
		r.RemoteAddr = tc.remote
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		if got := clientAddr(r, tc.trusted).String(); got != tc.want {
			t.Errorf("%s via %q: got %s, want %s", tc.remote, tc.xff, got, tc.want)
		}
	}
	if got := clientKey(netip.MustParseAddr("2001:db8:1:2:3:4:5:6")); got != "2001:db8:1:2::/64" {
		t.Errorf("IPv6 key = %s", got)
	}
}

func TestThrottle(t *testing.T) {
	now := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	th := newThrottle(1)
	th.now = func() time.Time { return now }

	// Failures spread wider than the window do not add up.
	for i := 0; i < maxFailures-1; i++ {
		th.fail("a")
	}
	now = now.Add(failureWindow + time.Second)
	if th.fail("a") {
		t.Fatal("blocked by failures outside the window")
	}
	for i := 0; i < maxFailures-2; i++ {
		th.fail("a")
	}
	if !th.fail("a") {
		t.Fatal("not blocked after maxFailures")
	}
	if _, ok := th.blocked("a"); !ok {
		t.Fatal("blocked() = false")
	}
	if _, ok := th.blocked("b"); ok {
		t.Fatal("another client is blocked")
	}
	now = now.Add(lockFor + time.Second)
	if _, ok := th.blocked("a"); ok {
		t.Fatal("still blocked after lockFor")
	}

	// A check waits for a free slot and gives up when none comes.
	ctx, cancel := context.WithCancel(context.Background())
	th.checks <- struct{}{} // the only slot is taken
	cancel()
	if th.check(ctx, func() { t.Error("ran without a slot") }) {
		t.Error("check ran without a slot")
	}
	<-th.checks
	ran := false
	if !th.check(context.Background(), func() { ran = true }) || !ran {
		t.Error("check did not run with a free slot")
	}
}

func TestSecureRequest(t *testing.T) {
	proxies := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	for _, tc := range []struct {
		public, remote, proto string
		want                  bool
	}{
		{"https://p.example.com", "203.0.113.7:1", "", true},
		{"", "203.0.113.7:1", "https", false}, // not a proxy: header ignored
		{"", "10.0.0.2:1", "https", true},
		{"", "10.0.0.2:1", "HTTPS, http", true},
		{"", "10.0.0.2:1", "http", false},
		{"", "10.0.0.2:1", "", false},
		{"http://localhost:8080", "10.0.0.2:1", "https", true},
	} {
		a := &Authenticator{opts: Options{TrustedProxies: proxies}, secure: strings.HasPrefix(tc.public, "https://")}
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remote
		if tc.proto != "" {
			r.Header.Set("X-Forwarded-Proto", tc.proto)
		}
		if got := a.secureRequest(r); got != tc.want {
			t.Errorf("%+v: got %v", tc, got)
		}
	}
}
