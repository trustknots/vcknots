package oid4vp

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
)

// TestMain keeps the package's tests off the network: a client that falls back
// to http.DefaultTransport may reach loopback test servers only. A request to
// any other host fails, and the run fails afterwards even when the test under
// way expected an error anyway.
func TestMain(m *testing.M) {
	guard := &loopbackOnlyTransport{next: http.DefaultTransport}
	http.DefaultTransport = guard
	code := m.Run()
	if len(guard.refused) != 0 {
		fmt.Fprintf(os.Stderr, "tests attempted to reach external hosts: %v\n", guard.refused)
		code = 1
	}
	os.Exit(code)
}

type loopbackOnlyTransport struct {
	next    http.RoundTripper
	mu      sync.Mutex
	refused []string
}

func (t *loopbackOnlyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	host := request.URL.Hostname()
	if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return t.next.RoundTrip(request)
	}
	t.mu.Lock()
	t.refused = append(t.refused, request.Method+" "+request.URL.String())
	t.mu.Unlock()
	return nil, fmt.Errorf("test transport refuses the external host %q", request.URL.Host)
}
