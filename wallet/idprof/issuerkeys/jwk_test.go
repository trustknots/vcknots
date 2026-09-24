package issuerkeys

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestIssuerMetadataRung(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t, "root")
	leaf := newTestLeaf(t, ca, "127.0.0.1")
	runLadderCases(t, []ladderCase{
		{
			name:       "every metadata key is tried after a stale kid match, the named key first",
			mechanisms: func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.IssuerMetadataJWKS = keySet(f.signer.withKeyID("rotated-key", ""), f.decoy.withKeyID("issuer-key-1", ""))
				return request
			},
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS, MechanismCredentialIssuerMetadataJWKS},
			wantKeyIDs:     []string{"issuer-key-1", "rotated-key"},
			diagnostics: map[string]wantDiagnostic{
				RungIssuerMetadataJWKS: {attempted: true, count: 2},
			},
			check: func(t *testing.T, f *ladderFixture, resolution *Resolution, _ error) {
				for _, candidate := range resolution.Candidates {
					if candidate.Issuer != f.credentialIssuer {
						t.Errorf("metadata candidate issuer = %q, want the Credential Issuer", candidate.Issuer)
					}
				}
			},
		},
		{
			name: "a switched-off metadata rung is not resurrected and names its switch",
			mechanisms: func(m *Mechanisms) {
				m.JWTVCIssuerMetadata = false
				m.IssuerMetadataJWKS = false
			},
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.X5C = x5cOf(leaf)
				request.IssuerMetadataJWKS = keySet(f.signer.public, leafJWK(leaf, "leaf"))
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {failure: failureDisabled, disabledBy: []string{SwitchJWTVCIssuerMetadata}},
				RungIssuerMetadataJWKS:  {failure: failureDisabled, disabledBy: []string{SwitchIssuerMetadataJWKS}},
			},
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requestCount() != 0 {
					t.Errorf("requests were made: %d", f.origin.requestCount())
				}
			},
		},
		{
			name:       "metadata keys for another algorithm only are reported as such",
			mechanisms: func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.IssuerMetadataJWKS = keySet(f.signer.withKeyID("issuer-key-1", "ES384"))
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungIssuerMetadataJWKS: {failure: "no issuer metadata key matches the credential algorithm"},
			},
		},
		{
			name:       "an x5c leaf the metadata names comes before the metadata keys, whatever the kid",
			mechanisms: func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.CredentialFormat = FormatJWTVCJSON
				request.KeyID = "stale-key"
				request.X5C = x5cOf(leaf)
				request.IssuerMetadataJWKS = keySet(f.decoy.withKeyID("stale-key", ""), leafJWK(leaf, "issuer-key-1"))
				return request
			},
			wantMechanisms: []Mechanism{MechanismX5CMetadataJWKSBinding, MechanismCredentialIssuerMetadataJWKS, MechanismCredentialIssuerMetadataJWKS},
			wantKeyIDs:     []string{"", "stale-key", "issuer-key-1"},
			wantDNSName:    "127.0.0.1",
			diagnostics: map[string]wantDiagnostic{
				RungIssuerMetadataJWKS: {attempted: true, count: 3},
			},
		},
		{
			name: "an x5c leaf binds through the metadata even with the x5c rung switched off",
			mechanisms: func(m *Mechanisms) {
				m.JWTVCIssuerMetadata = false
				m.X5C = false
			},
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.X5C = x5cOf(leaf)
				request.IssuerMetadataJWKS = keySet(leafJWK(leaf, "issuer-key-1"))
				return request
			},
			wantMechanisms: []Mechanism{MechanismX5CMetadataJWKSBinding, MechanismCredentialIssuerMetadataJWKS},
		},
		{
			name:       "an x5c leaf the metadata does not name adds nothing",
			mechanisms: func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.X5C = x5cOf(leaf)
				request.IssuerMetadataJWKS = keySet(f.decoy.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			wantDNSName:    "127.0.0.1",
		},
		{
			name:       "metadata keys are not attributed to an issuer other than the Credential Issuer",
			mechanisms: func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.Issuer = f.origin.url() + "/other"
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungIssuerMetadataJWKS: {failure: "issuer is not the credential issuer"},
			},
		},
		{
			name:       "an encryption key is never a signature candidate",
			mechanisms: func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				encryption := f.signer.withKeyID("enc-key", "")
				encryption.Use = "enc"
				signing := f.decoy.withKeyID("sig-key", "")
				signing.Use = "sig"
				request.IssuerMetadataJWKS = keySet(encryption, signing)
				return request
			},
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			wantKeyIDs:     []string{"sig-key"},
		},
		{
			name:       "a metadata set holding only encryption keys offers nothing",
			mechanisms: func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				encryption := f.signer.withKeyID("enc-key", "")
				encryption.Use = "enc"
				request.IssuerMetadataJWKS = keySet(encryption)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungIssuerMetadataJWKS: {failure: "no issuer metadata key matches the credential algorithm"},
			},
		},
		{
			name:       "a private metadata key is offered as its public half",
			mechanisms: func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.IssuerMetadataJWKS = keySet(jose.JSONWebKey{Key: f.signer.private, KeyID: "issuer-key-1"})
				return request
			},
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			check: func(t *testing.T, _ *ladderFixture, resolution *Resolution, _ error) {
				if !resolution.Candidates[0].Key.IsPublic() {
					t.Errorf("candidate key is not public")
				}
			},
		},
	})
}
