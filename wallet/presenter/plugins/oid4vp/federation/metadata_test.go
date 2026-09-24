package federation

import (
	"testing"
	"time"
)

// derivationChain builds a validated-looking chain for metadata derivation:
// the subject statement and as many superior statements as the inputs need,
// the first of which is the Immediate Superior's Subordinate Statement.
type derivationChain struct {
	subjectMetadata  map[string]any
	superiorMetadata map[string]any
	policies         []map[string]any
	constraints      []map[string]any
}

func (d derivationChain) build() *TrustChain {
	count := max(len(d.policies), len(d.constraints))
	if d.superiorMetadata != nil {
		count = max(count, 1)
	}
	issued, expires := time.Date(2026, 5, 19, 2, 0, 0, 0, time.UTC), time.Date(2026, 5, 19, 3, 0, 0, 0, time.UTC)
	chain := &TrustChain{
		SubjectEntityID: testVerifierID, TrustAnchorEntityID: testAnchorID, ExpiresAt: expires,
		Statements: []EntityStatement{{
			Issuer: testVerifierID, Subject: testVerifierID, IssuedAt: issued, ExpiresAt: expires,
			Metadata: d.subjectMetadata,
		}},
	}
	for i := 0; i < count; i++ {
		statement := EntityStatement{Issuer: testAnchorID, Subject: testVerifierID, IssuedAt: issued, ExpiresAt: expires}
		if i > 0 {
			statement.Issuer, statement.Subject = "https://superior-"+string(rune('0'+i))+".example.test", testAnchorID
		}
		if i == 0 {
			statement.Metadata = d.superiorMetadata
		}
		if i < len(d.policies) {
			statement.MetadataPolicy = d.policies[i]
		}
		if i < len(d.constraints) {
			statement.Constraints = d.constraints[i]
		}
		chain.Statements = append(chain.Statements, statement)
	}
	return chain
}

func TestDeriveEntityMetadataAppliesChainPoliciesInOrder(t *testing.T) {
	got, err := DeriveEntityMetadata(derivationChain{
		subjectMetadata: obj(t, `{"openid_credential_verifier": {
			"client_name": "Original verifier",
			"contacts": ["ops@example.test"],
			"response_modes_supported": ["direct_post", "fragment"],
			"vp_formats_supported": ["dc+sd-jwt", "jwt_vp_json"]
		}}`),
		policies: []map[string]any{
			obj(t, `{"openid_credential_verifier": {
				"client_name": {"value": "Federated verifier"},
				"contacts": {"add": ["security@example.test"]},
				"response_modes_supported": {"subset_of": ["direct_post", "direct_post.jwt"]}
			}}`),
			obj(t, `{"openid_credential_verifier": {
				"logo_uri": {"default": "https://verifier.example.test/logo.png"},
				"vp_formats_supported": {"superset_of": ["dc+sd-jwt"]}
			}}`),
		},
	}.build(), VerifierEntityType)
	if err != nil {
		t.Fatal(err)
	}
	requireJSON(t, got, `{
		"client_name": "Federated verifier",
		"contacts": ["ops@example.test", "security@example.test"],
		"logo_uri": "https://verifier.example.test/logo.png",
		"response_modes_supported": ["direct_post"],
		"vp_formats_supported": ["dc+sd-jwt", "jwt_vp_json"]
	}`)
}

func TestDeriveEntityMetadataDoesNotMutateTheChain(t *testing.T) {
	subject := obj(t, `{"openid_credential_verifier": {"client_name": "Original verifier"}}`)
	got, err := DeriveEntityMetadata(derivationChain{
		subjectMetadata: subject,
		policies:        []map[string]any{obj(t, `{"openid_credential_verifier": {"client_name": {"value": "Federated verifier"}}}`)},
	}.build(), VerifierEntityType)
	if err != nil {
		t.Fatal(err)
	}
	requireJSON(t, got, `{"client_name": "Federated verifier"}`)
	requireJSON(t, subject, `{"openid_credential_verifier": {"client_name": "Original verifier"}}`)
}

func TestDeriveEntityMetadataOverlaysImmediateSuperiorMetadata(t *testing.T) {
	got, err := DeriveEntityMetadata(derivationChain{
		subjectMetadata: obj(t, `{"openid_credential_verifier": {
			"client_name": "Self-published verifier",
			"contacts": ["ops@example.test"],
			"logo_uri": "https://verifier.example.test/self-logo.png"
		}}`),
		superiorMetadata: obj(t, `{"openid_credential_verifier": {
			"client_name": "Superior verifier",
			"policy_uri": "https://superior.example.test/policy"
		}}`),
		policies: []map[string]any{obj(t, `{"openid_credential_verifier": {
			"client_name": {"value": "Superior verifier"},
			"contacts": {"add": ["security@example.test"]}
		}}`)},
	}.build(), VerifierEntityType)
	if err != nil {
		t.Fatal(err)
	}
	requireJSON(t, got, `{
		"client_name": "Superior verifier",
		"contacts": ["ops@example.test", "security@example.test"],
		"logo_uri": "https://verifier.example.test/self-logo.png",
		"policy_uri": "https://superior.example.test/policy"
	}`)
}

func TestDeriveEntityMetadataRefusals(t *testing.T) {
	cases := []struct {
		name     string
		chain    derivationChain
		sentinel error
		fragment string
	}{
		{"missing subject scope", derivationChain{subjectMetadata: obj(t, `{}`)}, ErrMetadataDerivationFailed, "subject metadata is missing"},
		{"malformed subject scope", derivationChain{subjectMetadata: obj(t, `{"openid_credential_verifier": ["not", "object"]}`)}, ErrMetadataDerivationFailed, "subject metadata scope must be an object"},
		{
			"malformed superior scope",
			derivationChain{subjectMetadata: obj(t, `{"openid_credential_verifier": {}}`), superiorMetadata: obj(t, `{"openid_credential_verifier": ["not", "object"]}`)},
			ErrMetadataDerivationFailed, "immediate superior metadata scope must be an object",
		},
		{"null subject parameter", derivationChain{subjectMetadata: obj(t, `{"openid_credential_verifier": {"client_name": null}}`)}, ErrMetadataDerivationFailed, "subject metadata parameters must not be null"},
		{
			"null superior parameter",
			derivationChain{subjectMetadata: obj(t, `{"openid_credential_verifier": {}}`), superiorMetadata: obj(t, `{"openid_credential_verifier": {"client_name": null}}`)},
			ErrMetadataDerivationFailed, "immediate superior metadata parameters must not be null",
		},
		{
			"entity type disallowed by constraints",
			derivationChain{
				subjectMetadata: obj(t, `{"openid_credential_verifier": {"client_name": "x"}}`),
				constraints:     []map[string]any{obj(t, `{"allowed_entity_types": ["openid_credential_issuer"]}`)},
			},
			ErrMetadataDerivationFailed, "metadata entity type is disallowed by constraints",
		},
		{
			"conflicting chain policies",
			derivationChain{
				subjectMetadata: obj(t, `{"openid_credential_verifier": {"client_name": "Federated verifier"}}`),
				policies: []map[string]any{
					obj(t, `{"openid_credential_verifier": {"client_name": {"value": "Immediate superior verifier"}}}`),
					obj(t, `{"openid_credential_verifier": {"client_name": {"value": "Trust anchor verifier"}}}`),
				},
			},
			ErrMetadataPolicyInvalid, "metadata value policy values do not match",
		},
		{
			"essential parameter missing",
			derivationChain{
				subjectMetadata: obj(t, `{"openid_credential_verifier": {}}`),
				policies:        []map[string]any{obj(t, `{"openid_credential_verifier": {"client_name": {"essential": true}}}`)},
			},
			ErrMetadataPolicyInvalid, "metadata essential value is missing",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DeriveEntityMetadata(tc.chain.build(), VerifierEntityType)
			requireCode(t, err, tc.sentinel, tc.fragment)
		})
	}
}

func TestDeriveEntityMetadataNeverRestrictsFederationEntity(t *testing.T) {
	got, err := DeriveEntityMetadata(derivationChain{
		subjectMetadata: obj(t, `{"federation_entity": {"organization_name": "Example"}}`),
		constraints:     []map[string]any{obj(t, `{"allowed_entity_types": ["openid_credential_issuer"]}`)},
	}.build(), federationEntityType)
	if err != nil {
		t.Fatal(err)
	}
	requireJSON(t, got, `{"organization_name": "Example"}`)
}
