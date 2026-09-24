package issuerkeys

import (
	"testing"
)

func TestX5CRung(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t, "root")
	leaf := newTestLeaf(t, ca, "127.0.0.1")
	runLadderCases(t, []ladderCase{
		{
			name: "an SD-JWT VC chain reports the Issuer identifier host",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.X5C = x5cOf(leaf)
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			wantDNSName:    "127.0.0.1",
			diagnostics: map[string]wantDiagnostic{
				RungX5C: {attempted: true, count: 1},
			},
		},
		{
			name:       "a switched-off x5c rung names its switch",
			mechanisms: func(m *Mechanisms) { m.X5C = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.X5C = x5cOf(leaf)
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			diagnostics: map[string]wantDiagnostic{
				RungX5C: {failure: failureDisabled, disabledBy: []string{SwitchX5C}},
			},
		},
		{
			name: "no x5c header is reported as not present",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			diagnostics: map[string]wantDiagnostic{
				RungX5C: {failure: "not present"},
			},
		},
		{
			name: "a chain longer than sixteen certificates is treated as absent",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				for range 17 {
					request.X5C = append(request.X5C, x5cOf(leaf)...)
				}
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			diagnostics: map[string]wantDiagnostic{
				RungX5C: {failure: "not present"},
			},
		},
		{
			name: "a W3C JWT VC signer must claim to be the Credential Issuer",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.CredentialFormat = FormatJWTVCJSON
				request.Issuer = f.origin.url() + "/other"
				request.X5C = x5cOf(leaf)
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungX5C:                {failure: "issuer must match credential issuer metadata"},
				RungIssuerMetadataJWKS: {failure: "issuer is not the credential issuer"},
			},
		},
		{
			name: "a W3C JWT VC signed as the Credential Issuer reports its host",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.CredentialFormat = FormatJWTVCJSON
				request.Issuer = f.credentialIssuer
				request.X5C = x5cOf(leaf)
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			wantDNSName:    "127.0.0.1",
		},
		{
			name: "no rung applies to a Data Integrity credential",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.CredentialFormat = FormatLDPVC
				request.X5C = x5cOf(leaf)
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			diagnostics: map[string]wantDiagnostic{
				RungX5C:                 {failure: "not applicable for this credential format"},
				RungJWTVCIssuerMetadata: {failure: "not applicable for this credential format"},
			},
		},
		{
			name: "an http Issuer identifier reports no DNS name without AllowHTTP",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.Issuer = "http://issuer.example.test/tenant"
				request.CredentialIssuer = request.Issuer
				request.X5C = x5cOf(leaf)
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			mechanisms:     func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			diagnostics: map[string]wantDiagnostic{
				RungX5C: {failure: "issuer identifier is not https"},
			},
		},
	})
}
