package issuerkeys

import (
	"testing"
)

// The keys of a JWT VC Issuer Metadata jwks are filtered by use and alg (RFC
// 7517 §4.2, §4.4) and ordered by the credential's kid, which orders but never
// filters.
func TestJWTVCIssuerMetadataKeySelection(t *testing.T) {
	t.Parallel()
	runLadderCases(t, []ladderCase{
		{
			name: "every key is tried after a stale kid match, the named key first",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.publishMetadata(t, f.signer.withKeyID("rotated-key", ""), f.decoy.withKeyID("issuer-key-1", ""))
				return f.sdJWTRequest()
			},
			wantMechanisms: []Mechanism{MechanismJWTVCIssuerMetadata, MechanismJWTVCIssuerMetadata},
			wantKeyIDs:     []string{"issuer-key-1", "rotated-key"},
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, count: 2},
			},
		},
		{
			name: "keys for another algorithm only are reported as such",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.publishMetadata(t, f.signer.withKeyID("issuer-key-1", "ES384"))
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "no issuer metadata key matches the credential algorithm"},
			},
		},
		{
			name: "an encryption key is never a signature candidate",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				encryption := f.signer.withKeyID("enc-key", "")
				encryption.Use = "enc"
				signing := f.decoy.withKeyID("sig-key", "")
				signing.Use = "sig"
				f.publishMetadata(t, encryption, signing)
				return f.sdJWTRequest()
			},
			wantMechanisms: []Mechanism{MechanismJWTVCIssuerMetadata},
			wantKeyIDs:     []string{"sig-key"},
		},
		{
			name: "a key set holding only encryption keys offers nothing",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				encryption := f.signer.withKeyID("enc-key", "")
				encryption.Use = "enc"
				f.publishMetadata(t, encryption)
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "no issuer metadata key matches the credential algorithm"},
			},
		},
	})
}
