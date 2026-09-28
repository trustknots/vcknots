package httpfetch

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// FAPI 2.0 Security Profile §5.2.1, through HAIP 1.0 §4: every client the
// library creates by default has a TLS 1.2 floor set explicitly, and refuses a
// server that offers only TLS 1.1.
func TestDefaultClientsRequireTLS12(t *testing.T) {
	for name, client := range map[string]*http.Client{
		"NewClient":        NewClient(),
		"NewDefaultClient": NewDefaultClient(time.Second),
		"NoRedirect(nil)":  NoRedirect(nil),
	} {
		transport, ok := client.Transport.(*http.Transport)
		if !ok || transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
			t.Fatalf("%s: transport = %#v, want a TLS 1.2 floor", name, client.Transport)
		}
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}
	server.StartTLS()
	t.Cleanup(server.Close)
	_, err := NewClient().Get(server.URL)
	if err == nil || !strings.Contains(err.Error(), "protocol version") {
		t.Fatalf("a TLS 1.1 server: err = %v, want a protocol version failure", err)
	}
}
