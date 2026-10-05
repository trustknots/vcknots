package oid4vp

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustknots/vcknots/wallet/experimental"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
	"github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/profile"
)

// refusingTransport fails every request, so an entry point that reached the
// network before refusing would show up as a transport error instead.
type refusingTransport struct{ requests int }

func (r *refusingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.requests++
	return nil, http.ErrUseLastResponse
}

// Under ForbidExperimental every entry point refuses any non-zero
// Experimental before the network: Experimental.Transport on the Draft 24
// entry point and Experimental.AcceptClientMetadataJWKsWithoutKeyID on the
// Digital Credentials API entry point included, not only the OpenID4VP 1.0
// URI parse.
func TestHAIPPresenterRefusesExperimentalOnEveryEntryPoint(t *testing.T) {
	f := newRequestObjectFixture(t)
	_, sealed := f.admitSealed(t, f.sealedPresenter(profile.Final(), f.now), f.claims())
	strict, err := profile.Final().With(profile.HAIPOptions())
	require.NoError(t, err)

	draft24URI := finalQueryURI(draft24RedirectURIValues("http://verifier.example/response", "http://verifier.example/response"))
	dcapi := types.DCAPIInvocation{Origin: "https://verifier.example", Request: types.DCAPIRequest{Protocol: DCAPIProtocolUnsigned, Data: []byte(`{"response_type":"vp_token","response_mode":"dc_api.jwt","nonce":"n","dcql_query":{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["x"]}}]}}`)}}
	entries := map[string]func(p *Oid4vpPresenter) error{
		"ParseRequest": func(p *Oid4vpPresenter) error {
			_, err := p.ParseRequest(context.Background(), f.referenceURI(f.clientID(), false))
			return err
		},
		"ParseRequestObject": func(p *Oid4vpPresenter) error {
			_, err := p.ParseRequestObject(context.Background(), f.sign(t, f.claims(), nil), types.RequestObjectSource{ClientID: f.clientID()})
			return err
		},
		"ParseDCAPIRequest": func(p *Oid4vpPresenter) error {
			_, err := p.ParseDCAPIRequest(context.Background(), dcapi)
			return err
		},
		"ParseDraft24Request": func(p *Oid4vpPresenter) error {
			_, err := p.ParseDraft24Request(context.Background(), draft24URI)
			return err
		},
		"ParseDraft24RequestObject": func(p *Oid4vpPresenter) error {
			_, err := p.ParseDraft24RequestObject(context.Background(), f.sign(t, draft24X509Claims(f), nil), types.RequestObjectSource{})
			return err
		},
		"ReadmitRequest": func(p *Oid4vpPresenter) error {
			_, err := p.ReadmitRequest(context.Background(), sealed, sealKey)
			return err
		},
		"ReadmitDraft24Request": func(p *Oid4vpPresenter) error {
			_, err := p.ReadmitDraft24Request(context.Background(), sealed, sealKey)
			return err
		},
	}
	relaxations := map[string]experimental.Presenter{
		"Transport.AllowHTTP":                  {Transport: experimental.Transport{AllowHTTP: true}},
		"InsecureSkipX509Verify":               {InsecureSkipX509Verify: true},
		"AcceptClientMetadataJWKsWithoutKeyID": {AcceptClientMetadataJWKsWithoutKeyID: true},
	}
	for _, p := range []profile.Profile{profile.HAIP(), strict} {
		for entryName, entry := range entries {
			for relaxationName, relaxation := range relaxations {
				t.Run(p.String()+" "+entryName+" "+relaxationName, func(t *testing.T) {
					transport := &refusingTransport{}
					presenter := &Oid4vpPresenter{HTTPClient: &http.Client{Transport: transport}, Profile: p, Experimental: relaxation}
					err := entry(presenter)
					require.Error(t, err)
					require.True(t, strings.Contains(err.Error(), "does not permit Oid4vpPresenter.Experimental"), "err = %v", err)
					require.Zero(t, transport.requests, "refused before the network")
				})
			}
		}
	}
}

// The presenter's default client negotiates TLS 1.2 or later (FAPI 2.0
// Security Profile §5.2.1; HAIP 1.0 §4).
func TestPresenterDefaultClientHasTheTLSFloor(t *testing.T) {
	require.Equal(t, httpfetch.Transport(), (&Oid4vpPresenter{}).httpClient().Transport)
}
