package oid4vci

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
	"github.com/trustknots/vcknots/wallet/internal/observetest"
)

func TestFetchCredentialOffer(t *testing.T) {
	const offer = `{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/offer":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = w.Write([]byte(offer))
		case "/text":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(offer))
		case "/large":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"x":"` + strings.Repeat("a", int(httpfetch.DefaultBodyLimit)) + `"}`))
		case "/redirect":
			http.Redirect(w, r, "/offer", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	recorder := &observetest.Recorder{}
	client := server.Client()
	client.Transport = observe.Transport(client.Transport, recorder)
	receiver := &Oid4vciReceiver{HTTPClient: client, AllowHTTP: true}
	body, err := receiver.FetchCredentialOffer(t.Context(), mustURIField(t, server.URL+"/offer"))
	if err != nil || string(body) != offer {
		t.Fatalf("FetchCredentialOffer() = %q, %v", body, err)
	}
	if got := recorder.Endpoints(); len(got) != 1 || got[0] != observe.EndpointCredentialOffer {
		t.Fatalf("labels = %v, want [%s]", got, observe.EndpointCredentialOffer)
	}

	for path, want := range map[string]error{
		"/text":     nil,
		"/large":    httpfetch.ErrBodyTooLarge,
		"/redirect": ErrHTTPRedirectNotAllowed,
		"/missing":  nil,
	} {
		_, err := receiver.FetchCredentialOffer(t.Context(), mustURIField(t, server.URL+path))
		if err == nil || (want != nil && !errors.Is(err, want)) {
			t.Errorf("%s: err = %v, want %v", path, err, want)
		}
	}

	strict := &Oid4vciReceiver{HTTPClient: server.Client()}
	if _, err := strict.FetchCredentialOffer(t.Context(), mustURIField(t, server.URL+"/offer")); err == nil {
		t.Error("an http credential_offer_uri must be refused without AllowHTTP")
	}
	if strict.HTTPAllowed() || !receiver.HTTPAllowed() {
		t.Error("HTTPAllowed must report AllowHTTP")
	}
}
