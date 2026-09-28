package oid4vp

import (
	"crypto/ecdsa"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/internal/testutil"
)

const (
	attesterEntityID       = "https://attester.example"
	attestedVerifier       = "verifier.example"
	attestationResponseURI = "https://verifier.example/response"
)

// attestationFixture is a Verifier holding a Verifier Attestation JWT issued by
// a trusted attester, and the Request Objects it signs with the attested key.
type attestationFixture struct {
	now         time.Time
	attesterKey *ecdsa.PrivateKey
	verifierKey *ecdsa.PrivateKey
}

func newAttestationFixture(t *testing.T) *attestationFixture {
	t.Helper()
	return &attestationFixture{
		now:         time.Now().UTC().Truncate(time.Second),
		attesterKey: testutil.NewP256Key(t),
		verifierKey: testutil.NewP256Key(t),
	}
}

func (f *attestationFixture) clientID() string { return "verifier_attestation:" + attestedVerifier }

// confirmationJWK is the cnf.jwk member for the Verifier's public key.
func confirmationJWK(t *testing.T, key *ecdsa.PrivateKey) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(jose.JSONWebKey{Key: &key.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	var jwk map[string]any
	if err := json.Unmarshal(encoded, &jwk); err != nil {
		t.Fatal(err)
	}
	return jwk
}

func (f *attestationFixture) attestationClaims(t *testing.T) map[string]any {
	return map[string]any{
		"iss": attesterEntityID, "sub": attestedVerifier,
		"iat": f.now.Unix(), "exp": f.now.Add(time.Hour).Unix(),
		"cnf": map[string]any{"jwk": confirmationJWK(t, f.verifierKey)},
	}
}

func (f *attestationFixture) attestation(t *testing.T, claims map[string]any, typ string) string {
	t.Helper()
	return signJWT(t, jose.ES256, jose.JSONWebKey{Key: f.attesterKey, KeyID: "attester-key"}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)), claims)
}

func (f *attestationFixture) requestClaims() map[string]any {
	return map[string]any{
		"iat": f.now.Unix(), "exp": f.now.Add(5 * time.Minute).Unix(),
		"aud": "https://self-issued.me/v2", "client_id": f.clientID(),
		"nonce": "nonce", "response_type": "vp_token", "response_mode": "direct_post",
		"response_uri": attestationResponseURI,
		"dcql_query": map[string]any{"credentials": []any{map[string]any{
			"id": "pid", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []string{"urn:eudi:pid:1"}},
		}}},
	}
}

// requestObject signs the Request Object with key, carrying attestation in the
// `jwt` JOSE header when it is not empty.
func (f *attestationFixture) requestObject(t *testing.T, claims map[string]any, key *ecdsa.PrivateKey, attestation string) string {
	t.Helper()
	options := (&jose.SignerOptions{}).WithType("oauth-authz-req+jwt")
	if attestation != "" {
		options = options.WithHeader("jwt", attestation)
	}
	return signJWT(t, jose.ES256, key, options, claims)
}

func (f *attestationFixture) options() RequestObjectValidationOptions {
	return RequestObjectValidationOptions{
		Now: func() time.Time { return f.now },
		VerifierAttestationIssuers: []VerifierAttestationIssuer{{
			EntityID: attesterEntityID,
			JWKS:     publicJWKS(f.attesterKey, "attester-key"),
		}},
	}
}

func (f *attestationFixture) parse(requestObject string, options RequestObjectValidationOptions) (*CredentialPresentationRequest, error) {
	presenter := &Oid4vpPresenter{RequestObjectValidation: &options}
	return parseRequestObjectForTest(presenter, requestObject, f.clientID())
}

func TestVerifierAttestationRequestObjectIsAuthenticated(t *testing.T) {
	f := newAttestationFixture(t)
	claims := f.attestationClaims(t)
	claims["redirect_uris"] = []string{attestationResponseURI}
	request, err := f.parse(f.requestObject(t, f.requestClaims(), f.verifierKey, f.attestation(t, claims, "verifier-attestation+jwt")), f.options())
	if err != nil {
		t.Fatal(err)
	}
	verification := request.RequestObjectVerification
	if verification == nil || verification.VerifierAttestation == nil || verification.ClientID != f.clientID() {
		t.Fatalf("missing attestation evidence: %+v", verification)
	}
	evidence := verification.VerifierAttestation
	want := VerifierAttestationEvidence{
		IssuerEntityID: attesterEntityID, Subject: attestedVerifier,
		ExpiresAt: f.now.Add(time.Hour), RedirectURIs: []string{attestationResponseURI},
	}
	if !reflect.DeepEqual(*evidence, want) {
		t.Fatalf("evidence = %+v, want %+v", *evidence, want)
	}
	if !verification.ExpiresAt.Equal(f.now.Add(5 * time.Minute)) {
		t.Fatalf("request object expiry = %v", verification.ExpiresAt)
	}
}

func TestVerifierAttestationRequestObjectRefusals(t *testing.T) {
	f := newAttestationFixture(t)
	stranger := testutil.NewP256Key(t)
	withClaims := func(edit func(map[string]any)) string {
		claims := f.attestationClaims(t)
		edit(claims)
		return f.attestation(t, claims, "verifier-attestation+jwt")
	}
	valid := withClaims(func(map[string]any) {})
	cases := []struct {
		name    string
		request func() string
		options func() RequestObjectValidationOptions
		want    error
	}{
		{
			name:    "missing jwt header",
			request: func() string { return f.requestObject(t, f.requestClaims(), f.verifierKey, "") },
			want:    ErrVerifierAttestationInvalid,
		},
		{
			name: "wrong attestation typ",
			request: func() string {
				return f.requestObject(t, f.requestClaims(), f.verifierKey, f.attestation(t, f.attestationClaims(t), "JWT"))
			},
			want: ErrVerifierAttestationInvalid,
		},
		{
			name: "untrusted iss",
			request: func() string {
				return f.requestObject(t, f.requestClaims(), f.verifierKey, withClaims(func(c map[string]any) { c["iss"] = "https://other-attester.example" }))
			},
			want: ErrVerifierAttestationUntrusted,
		},
		{
			name:    "no configured attester",
			request: func() string { return f.requestObject(t, f.requestClaims(), f.verifierKey, valid) },
			options: func() RequestObjectValidationOptions {
				return RequestObjectValidationOptions{Now: func() time.Time { return f.now }}
			},
			want: ErrVerifierAttestationUntrusted,
		},
		{
			name: "sub is not the original client identifier",
			request: func() string {
				return f.requestObject(t, f.requestClaims(), f.verifierKey, withClaims(func(c map[string]any) { c["sub"] = "other.example" }))
			},
			want: ErrVerifierAttestationInvalid,
		},
		{
			name: "expired attestation",
			request: func() string {
				return f.requestObject(t, f.requestClaims(), f.verifierKey, withClaims(func(c map[string]any) { c["exp"] = f.now.Add(-time.Second).Unix() }))
			},
			want: ErrVerifierAttestationExpired,
		},
		{
			name: "missing cnf.jwk",
			request: func() string {
				return f.requestObject(t, f.requestClaims(), f.verifierKey, withClaims(func(c map[string]any) { c["cnf"] = map[string]any{} }))
			},
			want: ErrVerifierAttestationInvalid,
		},
		{
			name:    "request not signed by the cnf key",
			request: func() string { return f.requestObject(t, f.requestClaims(), stranger, valid) },
			want:    ErrRequestObjectSignatureInvalid,
		},
		{
			name: "attestation signed by another key",
			request: func() string {
				forged := signJWT(t, jose.ES256, jose.JSONWebKey{Key: stranger, KeyID: "attester-key"},
					(&jose.SignerOptions{}).WithType("verifier-attestation+jwt"), f.attestationClaims(t))
				return f.requestObject(t, f.requestClaims(), f.verifierKey, forged)
			},
			want: ErrVerifierAttestationInvalid,
		},
		{
			// With direct_post the response goes to response_uri, so that is the
			// endpoint the attestation's redirect_uris constrain.
			name: "response_uri outside the attested redirect_uris",
			request: func() string {
				return f.requestObject(t, f.requestClaims(), f.verifierKey, withClaims(func(c map[string]any) {
					c["redirect_uris"] = []string{"https://verifier.example/other"}
				}))
			},
			want: ErrVerifierAttestationInvalid,
		},
		{
			// A present but malformed redirect_uris must not lose the
			// attester's constraint.
			name: "redirect_uris is a string, not an array",
			request: func() string {
				return f.requestObject(t, f.requestClaims(), f.verifierKey, withClaims(func(c map[string]any) {
					c["redirect_uris"] = attestationResponseURI
				}))
			},
			want: ErrVerifierAttestationInvalid,
		},
		{
			name: "redirect_uris holds a non-string",
			request: func() string {
				return f.requestObject(t, f.requestClaims(), f.verifierKey, withClaims(func(c map[string]any) {
					c["redirect_uris"] = []any{attestationResponseURI, 7}
				}))
			},
			want: ErrVerifierAttestationInvalid,
		},
		{
			name: "redirect_uris is empty",
			request: func() string {
				return f.requestObject(t, f.requestClaims(), f.verifierKey, withClaims(func(c map[string]any) {
					c["redirect_uris"] = []string{}
				}))
			},
			want: ErrVerifierAttestationInvalid,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			options := f.options()
			if tc.options != nil {
				options = tc.options()
			}
			request, err := f.parse(tc.request(), options)
			if request != nil {
				t.Fatalf("a refused request was returned: %+v", request)
			}
			requireErrorIs(t, err, tc.want)
		})
	}
}
