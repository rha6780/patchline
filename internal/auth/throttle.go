package auth

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Sign-in throttling. Failed passwords are counted per client, not per
// account: the admin's username is known, so locking the account would
// let anyone keep its owner out. And at most a few password checks
// (bcrypt, deliberately slow) run at once, so a flood of attempts cannot
// use up the CPU.
const (
	// maxFailures failed sign-ins from one client within failureWindow
	// block that client for lockFor.
	maxFailures   = 5
	failureWindow = 15 * time.Minute
	lockFor       = 15 * time.Minute
	// maxClients bounds the memory the counts take.
	maxClients = 10000
	// checkWait is how long a sign-in waits for a free password check.
	checkWait = 3 * time.Second
)

type attempts struct {
	failures int
	last     time.Time
	until    time.Time
}

// throttle counts failed sign-ins per client and limits concurrent
// password checks. The counts live in memory: a restart clears them.
type throttle struct {
	mu      sync.Mutex
	clients map[string]*attempts
	checks  chan struct{}
	now     func() time.Time
}

func newThrottle(concurrent int) *throttle {
	return &throttle{clients: map[string]*attempts{}, checks: make(chan struct{}, max(concurrent, 1)), now: time.Now}
}

// blocked returns when the client may try again, if it is blocked now.
func (t *throttle) blocked(client string) (time.Time, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if a, ok := t.clients[client]; ok && t.now().Before(a.until) {
		return a.until, true
	}
	return time.Time{}, false
}

// fail records a failed sign-in and reports whether the client is now
// blocked.
func (t *throttle) fail(client string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	a, ok := t.clients[client]
	if !ok {
		if len(t.clients) >= maxClients {
			t.prune(now)
		}
		a = &attempts{}
		t.clients[client] = a
	}
	if now.Sub(a.last) > failureWindow {
		a.failures = 0
	}
	a.failures++
	a.last = now
	if a.failures >= maxFailures {
		a.failures, a.until = 0, now.Add(lockFor)
		return true
	}
	return false
}

// succeed forgets a client's failures.
func (t *throttle) succeed(client string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.clients, client)
}

// prune drops clients that are neither blocked nor recently failing; if
// that is not enough, it starts over rather than grow without bound.
func (t *throttle) prune(now time.Time) {
	for k, a := range t.clients {
		if now.After(a.until) && now.Sub(a.last) > failureWindow {
			delete(t.clients, k)
		}
	}
	if len(t.clients) >= maxClients {
		clear(t.clients)
	}
}

// check runs fn when a password check slot is free within checkWait, and
// reports whether it ran.
func (t *throttle) check(ctx context.Context, fn func()) bool {
	timer := time.NewTimer(checkWait)
	defer timer.Stop()
	select {
	case t.checks <- struct{}{}:
	case <-timer.C:
		return false
	case <-ctx.Done():
		return false
	}
	defer func() { <-t.checks }()
	fn()
	return true
}

// clientAddr is the address of the client that sent r. A request from a
// trusted proxy is followed back through X-Forwarded-For, right to left,
// to the first address that is not a trusted proxy; anything left of it
// may have been made up by the client.
func clientAddr(r *http.Request, trusted []netip.Prefix) netip.Addr {
	addr := remoteAddr(r.RemoteAddr)
	if !addr.IsValid() || !isTrusted(addr, trusted) {
		return addr
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return addr // malformed: stop at the last address we trust to be real
		}
		addr = hop.Unmap()
		if !isTrusted(addr, trusted) {
			return addr
		}
	}
	return addr
}

// clientKey groups the addresses one client is likely to hold: one IPv4
// address, or an IPv6 /64 (a single network gets a whole /64).
func clientKey(addr netip.Addr) string {
	if !addr.IsValid() {
		return "unknown"
	}
	if addr.Is6() {
		p, _ := addr.WithZone("").Prefix(64)
		return p.String()
	}
	return addr.String()
}

func remoteAddr(hostport string) netip.Addr {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
