package oid4vci

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// Every response body is read within a limit: credential-bearing responses get
// httpfetch.CredentialBodyLimit, everything else httpfetch.DefaultBodyLimit.
func TestResponseBodiesAreBounded(t *testing.T) {
	credentialSized := `{"credential":"` + strings.Repeat("a", int(httpfetch.DefaultBodyLimit)*2) + `"}`
	oversized := strings.Repeat("a", int(httpfetch.CredentialBodyLimit)+1)
	serve := func(body string) *recordingServer {
		return newRecordingServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		})
	}

	t.Run("a credential response above the default limit is read", func(t *testing.T) {
		server := serve(credentialSized)
		receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
		response, err := postCredentialBody(t.Context(), receiver, mustURIField(t, server.URL), "access-1", []byte(`{}`), "application/json", fixedProof("proof"))
		if err != nil || len(response.Body) != len(credentialSized) {
			t.Fatalf("response = %v, err = %v", response, err)
		}
	})
	t.Run("a credential response above the credential limit is refused", func(t *testing.T) {
		server := serve(oversized)
		receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
		_, err := postCredentialBody(t.Context(), receiver, mustURIField(t, server.URL), "access-1", []byte(`{}`), "application/json", fixedProof("proof"))
		if !errors.Is(err, httpfetch.ErrBodyTooLarge) {
			t.Fatalf("err = %v, want ErrBodyTooLarge", err)
		}
	})
	t.Run("a token response above the default limit is refused", func(t *testing.T) {
		server := serve(credentialSized)
		receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
		_, err := receiver.RequestToken(t.Context(), mustURIField(t, server.URL), types.TokenRequest{GrantType: types.PreAuthorizedCode, PreAuthorizedCode: "pre-1"}, types.ClientAuthentication{})
		if !errors.Is(err, httpfetch.ErrBodyTooLarge) {
			t.Fatalf("err = %v, want ErrBodyTooLarge", err)
		}
	})
	t.Run("issuer metadata above the default limit is refused", func(t *testing.T) {
		server := serve(credentialSized)
		receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
		_, err := receiver.FetchIssuerMetadata(mustURIField(t, server.URL), types.Oid4vci)
		if !errors.Is(err, httpfetch.ErrBodyTooLarge) {
			t.Fatalf("err = %v, want ErrBodyTooLarge", err)
		}
	})
}

func TestDPoPChallengeError(t *testing.T) {
	cases := map[string]struct {
		header []string
		want   string
	}{
		"RFC 9449 Section 9 example":  {[]string{`DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof"`}, "use_dpop_nonce"},
		"unquoted parameter":          {[]string{`DPoP error=use_dpop_nonce`}, "use_dpop_nonce"},
		"scheme case":                 {[]string{`dpop algs="ES256 PS256", error="use_dpop_nonce"`}, "use_dpop_nonce"},
		"after a Bearer challenge":    {[]string{`Bearer realm="x", error="invalid_token", DPoP error="use_dpop_nonce"`}, "use_dpop_nonce"},
		"separate header lines":       {[]string{`Bearer error="invalid_token"`, `DPoP error="use_dpop_nonce"`}, "use_dpop_nonce"},
		"Bearer challenge only":       {[]string{`Bearer error="use_dpop_nonce"`}, ""},
		"quoted comma in description": {[]string{`DPoP error_description="a, error=use_dpop_nonce", error="invalid_token"`}, "invalid_token"},
		"no header":                   {nil, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			header := http.Header{}
			for _, value := range tc.header {
				header.Add("WWW-Authenticate", value)
			}
			if got := dpopChallengeError(header); got != tc.want {
				t.Fatalf("dpopChallengeError() = %q, want %q", got, tc.want)
			}
		})
	}
}
