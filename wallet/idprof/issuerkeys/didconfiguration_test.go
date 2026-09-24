package issuerkeys

import (
	"net/url"
	"testing"
	"time"
)

func TestDIDRungDIDConfiguration(t *testing.T) {
	t.Parallel()
	const configurationPath = "/.well-known/did-configuration.json"
	// linkage publishes a DID Configuration for the fixture's did:jwk signer,
	// after adjust has changed the Domain Linkage Credential.
	linkage := func(t *testing.T, f *ladderFixture, adjust func(didValue string, header, claims map[string]any) testKey) Request {
		didValue := didJWK(t, f.signer.public)
		header, claims := domainLinkage(didValue, didValue+"#0", f.originString())
		key := f.signer
		if adjust != nil {
			if replacement := adjust(didValue, header, claims); replacement.private != nil {
				key = replacement
			}
		}
		f.origin.json(t, configurationPath, map[string]any{
			"@context":    "https://identity.foundation/.well-known/did-configuration/v1",
			"linked_dids": []any{signJWT(t, key, header, claims)},
		})
		return f.jwtVCRequest(didValue, didValue+"#0")
	}
	didOnly := map[string]wantDiagnostic{
		RungDID: {attempted: true, failure: "DID-only trust not accepted without metadata/config binding"},
	}
	runLadderCases(t, []ladderCase{
		{
			name: "a Domain Linkage Credential from the Credential Issuer's origin binds the DID",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, nil)
			},
			wantMechanisms: []Mechanism{MechanismDIDConfigurationBinding},
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requested(configurationPath) != 1 {
					t.Errorf("DID Configuration requested %d times", f.origin.requested(configurationPath))
				}
			},
		},
		{
			name:       "the DID Configuration switched off is never requested",
			mechanisms: func(m *Mechanisms) { m.DIDConfiguration = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, nil)
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, failure: "DID-only trust not accepted without metadata/config binding", disabledBy: []string{SwitchDIDConfiguration}},
			},
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requestCount() != 0 {
					t.Errorf("requests were made: %d", f.origin.requestCount())
				}
			},
		},
		{
			name: "a linkage to another origin does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, _, claims map[string]any) testKey {
					claims["vc"].(map[string]any)["credentialSubject"].(map[string]any)["origin"] = "https://other.example.test"
					return testKey{}
				})
			},
			wantErr:     ErrDIDOnlyTrustUnsupported,
			diagnostics: didOnly,
		},
		{
			name: "a linkage to the same host on another scheme does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, _, claims map[string]any) testKey {
					claims["vc"].(map[string]any)["credentialSubject"].(map[string]any)["origin"] = "http://" + f.origin.hostPort()
					return testKey{}
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name: "a linkage for another DID does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, _, claims map[string]any) testKey {
					claims["vc"].(map[string]any)["credentialSubject"].(map[string]any)["id"] = "did:example:other"
					return testKey{}
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name: "a linkage whose iss is another DID does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, _, claims map[string]any) testKey {
					claims["iss"] = "did:example:other"
					return testKey{}
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name: "a linkage with a typ header does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, header, _ map[string]any) testKey {
					header["typ"] = "JWT"
					return testKey{}
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name: "a linkage without a kid does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, header, _ map[string]any) testKey {
					delete(header, "kid")
					return testKey{}
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name: "an expired linkage JWT does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, _, claims map[string]any) testKey {
					claims["exp"] = testNow.Add(-time.Minute).Unix()
					return testKey{}
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name: "a linkage JWT whose exp is not a NumericDate does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, _, claims map[string]any) testKey {
					claims["exp"] = "2999-01-01"
					return testKey{}
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name: "a linkage whose expirationDate has passed does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, _, claims map[string]any) testKey {
					claims["vc"].(map[string]any)["expirationDate"] = testNow.Add(-time.Minute).Format(time.RFC3339)
					return testKey{}
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name: "a linkage whose issuanceDate is a bare past date binds",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, _, claims map[string]any) testKey {
					claims["vc"].(map[string]any)["issuanceDate"] = "2026-01-01"
					return testKey{}
				})
			},
			wantMechanisms: []Mechanism{MechanismDIDConfigurationBinding},
		},
		{
			name: "a linkage with an unreadable issuanceDate does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, _, claims map[string]any) testKey {
					claims["vc"].(map[string]any)["issuanceDate"] = "yesterday"
					return testKey{}
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name: "a linkage that does not declare DomainLinkageCredential does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, _, claims map[string]any) testKey {
					claims["vc"].(map[string]any)["type"] = []any{"VerifiableCredential"}
					return testKey{}
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name: "a linkage signed by a key of another DID does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				other := newES256Key(t, "")
				return linkage(t, f, func(_ string, header, _ map[string]any) testKey {
					header["kid"] = didJWK(t, other.public) + "#0"
					return other
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name: "a linkage whose signature does not verify does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, _, _ map[string]any) testKey {
					return f.decoy
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name:       "the DID Configuration does not apply to SD-JWT VC",
			mechanisms: func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := linkage(t, f, nil)
				request.CredentialFormat = FormatSDJWTVC
				return request
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requestCount() != 0 {
					t.Errorf("requests were made: %d", f.origin.requestCount())
				}
			},
		},
		{
			name: "the metadata binding answers before the DID Configuration is requested",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := linkage(t, f, nil)
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismDIDMetadataBinding},
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requested(configurationPath) != 0 {
					t.Errorf("the DID Configuration was requested although the metadata bound the key")
				}
			},
		},
	})
}

func TestOriginAuthority(t *testing.T) {
	t.Parallel()
	tests := []struct{ left, right string }{
		{"https://Issuer.Example.test/a", "https://issuer.example.test:443/b"},
		{"http://issuer.example.test:80/a", "http://issuer.example.test"},
	}
	for _, test := range tests {
		left, _ := url.Parse(test.left)
		right, _ := url.Parse(test.right)
		if originAuthority(left) != originAuthority(right) {
			t.Errorf("originAuthority(%q) != originAuthority(%q)", test.left, test.right)
		}
	}
	left, _ := url.Parse("https://issuer.example.test:8443")
	right, _ := url.Parse("https://issuer.example.test")
	if originAuthority(left) == originAuthority(right) {
		t.Errorf("a non-default port must be part of the authority")
	}
}
