package federation

import (
	"reflect"
	"testing"
	"time"
)

const (
	testVerifierID     = "https://verifier.example.test"
	testAnchorID       = "https://anchor.example.test"
	testIntermediateID = "https://intermediate.example.test"
)

// chainOptions varies the three-statement chain the tests build.
type chainOptions struct {
	leafHeader             header
	leafIssuedAt           int64
	leafExpires            int64
	leafMetadata           any
	leafMetadataPolicy     any
	leafMetadataPolicyCrit any
	leafConstraints        any
	leafCrit               any
	leafExtra              map[string]any
	subordinateSubject     string
	subordinateExpires     int64
	subordinatePolicyCrit  any
	subordinateConstraints any
}

type chainFixture struct {
	chain      []string
	anchorJWKS TrustAnchor
}

func newChainFixture(t *testing.T, opts chainOptions) chainFixture {
	t.Helper()
	leafKey, anchorKey := newSigningKey(t, "leaf-key"), newSigningKey(t, "anchor-key")
	if opts.leafIssuedAt == 0 {
		opts.leafIssuedAt = testIssuedAt
	}
	if opts.leafExpires == 0 {
		opts.leafExpires = testIssuedAt + 600
	}
	if opts.leafMetadata == nil {
		opts.leafMetadata = map[string]any{VerifierEntityType: map[string]any{"client_name": "Federated verifier"}}
	}
	if opts.subordinateSubject == "" {
		opts.subordinateSubject = testVerifierID
	}
	if opts.subordinateExpires == 0 {
		opts.subordinateExpires = testIssuedAt + 300
	}
	leaf := signStatement(t, statement{
		issuer: testVerifierID, subject: testVerifierID, jwks: leafKey.jwks,
		issuedAt: opts.leafIssuedAt, expires: opts.leafExpires, metadata: opts.leafMetadata,
		metadataPolicy: opts.leafMetadataPolicy, metadataPolicyCrit: opts.leafMetadataPolicyCrit,
		constraints: opts.leafConstraints, crit: opts.leafCrit, extra: opts.leafExtra,
	}, leafKey, opts.leafHeader)
	subordinate := signStatement(t, statement{
		issuer: testAnchorID, subject: opts.subordinateSubject, jwks: leafKey.jwks,
		issuedAt: testIssuedAt, expires: opts.subordinateExpires,
		metadataPolicy: map[string]any{VerifierEntityType: map[string]any{
			"client_name": map[string]any{"value": "Federated verifier"},
		}},
		metadataPolicyCrit: opts.subordinatePolicyCrit, constraints: opts.subordinateConstraints,
	}, anchorKey, header{})
	anchor := signStatement(t, statement{
		issuer: testAnchorID, subject: testAnchorID, jwks: anchorKey.jwks,
		issuedAt: testIssuedAt, expires: testIssuedAt + 900,
	}, anchorKey, header{})
	return chainFixture{
		chain:      []string{leaf, subordinate, anchor},
		anchorJWKS: TrustAnchor{EntityID: testAnchorID, JWKS: anchorKey.jwks},
	}
}

// newIntermediateChain builds verifier -> intermediate -> anchor with
// constraints on the anchor's statement about the intermediate.
func newIntermediateChain(t *testing.T, intermediateID string, anchorConstraints any) chainFixture {
	t.Helper()
	leafKey := newSigningKey(t, "leaf-key")
	intermediateKey := newSigningKey(t, "intermediate-key")
	anchorKey := newSigningKey(t, "anchor-key")
	leaf := signStatement(t, statement{
		issuer: testVerifierID, subject: testVerifierID, jwks: leafKey.jwks,
		issuedAt: testIssuedAt, expires: testIssuedAt + 600,
		metadata: map[string]any{VerifierEntityType: map[string]any{"client_name": "Federated verifier"}},
	}, leafKey, header{})
	leafSubordinate := signStatement(t, statement{
		issuer: intermediateID, subject: testVerifierID, jwks: leafKey.jwks,
		issuedAt: testIssuedAt, expires: testIssuedAt + 400,
	}, intermediateKey, header{})
	intermediateSubordinate := signStatement(t, statement{
		issuer: testAnchorID, subject: intermediateID, jwks: intermediateKey.jwks,
		issuedAt: testIssuedAt, expires: testIssuedAt + 500, constraints: anchorConstraints,
	}, anchorKey, header{})
	anchor := signStatement(t, statement{
		issuer: testAnchorID, subject: testAnchorID, jwks: anchorKey.jwks,
		issuedAt: testIssuedAt, expires: testIssuedAt + 900,
	}, anchorKey, header{})
	return chainFixture{
		chain:      []string{leaf, leafSubordinate, intermediateSubordinate, anchor},
		anchorJWKS: TrustAnchor{EntityID: testAnchorID, JWKS: anchorKey.jwks},
	}
}

func TestValidateTrustChainAcceptsAnOrderedChain(t *testing.T) {
	fixture := newChainFixture(t, chainOptions{})
	chain, err := ValidateTrustChain(fixture.chain, testVerifierID, []TrustAnchor{fixture.anchorJWKS}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if chain.SubjectEntityID != testVerifierID || chain.TrustAnchorEntityID != testAnchorID {
		t.Fatalf("unexpected chain ends: %+v", chain)
	}
	if want := time.Unix(testIssuedAt+300, 0).UTC(); !chain.ExpiresAt.Equal(want) {
		t.Fatalf("expiresAt = %v, want the earliest exp %v", chain.ExpiresAt, want)
	}
	want := [][2]string{{testVerifierID, testVerifierID}, {testAnchorID, testVerifierID}, {testAnchorID, testAnchorID}}
	if got := statementPairs(chain); !reflect.DeepEqual(got, want) {
		t.Fatalf("statements = %v, want %v", got, want)
	}
	if name := chain.Statements[0].Metadata[VerifierEntityType].(map[string]any)["client_name"]; name != "Federated verifier" {
		t.Fatalf("subject metadata not kept: %v", chain.Statements[0].Metadata)
	}
	policy := chain.Statements[1].MetadataPolicy[VerifierEntityType].(map[string]any)["client_name"].(map[string]any)
	if policy["value"] != "Federated verifier" {
		t.Fatalf("subordinate metadata policy not kept: %v", chain.Statements[1].MetadataPolicy)
	}
	if len(chain.Statements[0].JWKS.Keys) != 1 || !chain.Statements[0].JWKS.Keys[0].IsPublic() {
		t.Fatalf("subject jwks not kept as public keys: %+v", chain.Statements[0].JWKS)
	}
}

func TestValidateTrustChainAcceptsAnAnchorSelfChain(t *testing.T) {
	anchorKey := newSigningKey(t, "anchor-key")
	anchor := signStatement(t, statement{
		issuer: testAnchorID, subject: testAnchorID, jwks: anchorKey.jwks,
		issuedAt: testIssuedAt, expires: testIssuedAt + 900,
	}, anchorKey, header{})
	chain, err := ValidateTrustChain([]string{anchor}, testAnchorID, []TrustAnchor{{EntityID: testAnchorID, JWKS: anchorKey.jwks}}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if chain.SubjectEntityID != testAnchorID || chain.TrustAnchorEntityID != testAnchorID || len(chain.Statements) != 1 {
		t.Fatalf("unexpected self chain: %+v", chain)
	}
}

func TestValidateTrustChainRefusesInvalidChains(t *testing.T) {
	now := testNow.Unix()
	cases := []struct {
		name     string
		opts     chainOptions
		fragment string
	}{
		{"expired subordinate statement", chainOptions{subordinateExpires: now - 1}, "entity statement has expired"},
		{"statement issued in the future", chainOptions{leafIssuedAt: now + 60, leafExpires: now + 600}, "entity statement is not active yet"},
		{"broken issuer/subject topology", chainOptions{subordinateSubject: "https://other-verifier.example.test"}, "trust chain topology is invalid"},
		{"missing kid", chainOptions{leafHeader: header{omitKid: true}}, "entity statement kid is required"},
		{"plain JWT typ", chainOptions{leafHeader: header{typ: "JWT"}}, "entity statement typ is invalid"},
		{"HTTP media type as typ", chainOptions{leafHeader: header{typ: "application/entity-statement+jwt"}}, "entity statement typ is invalid"},
		{"metadata that is not an object", chainOptions{leafMetadata: []string{"not", "object"}}, "entity statement metadata claim must be an object"},
		{"unsupported critical policy operator", chainOptions{subordinatePolicyCrit: []string{"regexp"}}, `metadata_policy_crit operator "regexp" is unsupported`},
		{"empty metadata_policy_crit", chainOptions{subordinatePolicyCrit: []string{}}, "metadata_policy_crit claim must be a non-empty string array"},
		{"standard operator in metadata_policy_crit", chainOptions{subordinatePolicyCrit: []string{"value"}}, "must not include standard metadata policy operators"},
		{
			"metadata_policy on an entity configuration",
			chainOptions{leafMetadataPolicy: map[string]any{VerifierEntityType: map[string]any{"client_name": map[string]any{"value": "x"}}}},
			"metadata_policy claim is only allowed in subordinate statements",
		},
		{"metadata_policy_crit on an entity configuration", chainOptions{leafMetadataPolicyCrit: []string{"regexp"}}, "metadata_policy_crit claim is only allowed in subordinate statements"},
		{"constraints on an entity configuration", chainOptions{leafConstraints: map[string]any{"max_path_length": 0}}, "constraints claim is only allowed in subordinate statements"},
		{"excluded naming constraint", chainOptions{subordinateConstraints: map[string]any{"naming_constraints": map[string]any{"excluded": []string{".example.test"}}}}, "trust chain violates naming_constraints"},
		{"malformed allowed_entity_types", chainOptions{subordinateConstraints: map[string]any{"allowed_entity_types": []any{VerifierEntityType, 1}}}, "allowed_entity_types must be a string array"},
		{"negative max_path_length", chainOptions{subordinateConstraints: map[string]any{"max_path_length": -1}}, "max_path_length must be a non-negative integer"},
		{"unsupported critical extension claim", chainOptions{leafCrit: []string{"example_extension"}, leafExtra: map[string]any{"example_extension": true}}, `critical claim "example_extension" is unsupported`},
		{"critical claim that is absent", chainOptions{leafCrit: []string{"example_extension"}}, `critical claim "example_extension" is not present`},
		{"standard claim listed as critical", chainOptions{leafCrit: []string{"jwks"}}, "crit claim must not include standard claims"},
		{"duplicate critical claims", chainOptions{leafCrit: []string{"a", "a"}, leafExtra: map[string]any{"a": 1}}, "crit claim must not contain duplicates"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newChainFixture(t, tc.opts)
			_, err := ValidateTrustChain(fixture.chain, testVerifierID, []TrustAnchor{fixture.anchorJWKS}, testNow)
			requireCode(t, err, ErrTrustChainInvalid, tc.fragment)
		})
	}
}

func TestValidateTrustChainRefusesUntrustedAnchors(t *testing.T) {
	fixture := newChainFixture(t, chainOptions{})
	other := newSigningKey(t, "anchor-key")

	_, err := ValidateTrustChain(fixture.chain, testVerifierID, []TrustAnchor{{EntityID: testAnchorID, JWKS: other.jwks}}, testNow)
	requireCode(t, err, ErrTrustChainInvalid, "signature is invalid")

	_, err = ValidateTrustChain(fixture.chain, testVerifierID, []TrustAnchor{{EntityID: "https://other-anchor.example.test", JWKS: fixture.anchorJWKS.JWKS}}, testNow)
	requireCode(t, err, ErrTrustChainInvalid, "trust anchor is not configured")

	_, err = ValidateTrustChain(fixture.chain, "https://someone-else.example.test", []TrustAnchor{fixture.anchorJWKS}, testNow)
	requireCode(t, err, ErrTrustChainInvalid, "trust chain subject does not match")

	_, err = ValidateTrustChain(nil, testVerifierID, []TrustAnchor{fixture.anchorJWKS}, testNow)
	requireCode(t, err, ErrTrustChainInvalid, "at least one statement")

	_, err = ValidateTrustChain([]string{"not-a-jwt"}, testVerifierID, []TrustAnchor{fixture.anchorJWKS}, testNow)
	requireCode(t, err, ErrTrustChainInvalid, "not a JWT")
}

func TestValidateTrustChainRefusesASubjectStatementSignedByAnotherKey(t *testing.T) {
	fixture := newChainFixture(t, chainOptions{})
	stranger := newSigningKey(t, "leaf-key")
	fixture.chain[0] = signStatement(t, statement{
		issuer: testVerifierID, subject: testVerifierID, jwks: stranger.jwks,
		issuedAt: testIssuedAt, expires: testIssuedAt + 600,
	}, stranger, header{})
	// The forged configuration verifies with its own keys, but not with the
	// keys the superior published about the subject.
	_, err := ValidateTrustChain(fixture.chain, testVerifierID, []TrustAnchor{fixture.anchorJWKS}, testNow)
	requireCode(t, err, ErrTrustChainInvalid, "signature is invalid")
}

func TestValidateTrustChainAppliesIntermediateConstraints(t *testing.T) {
	anchors := func(f chainFixture) []TrustAnchor { return []TrustAnchor{f.anchorJWKS} }

	valid := newIntermediateChain(t, testIntermediateID, map[string]any{"max_path_length": 1})
	if _, err := ValidateTrustChain(valid.chain, testVerifierID, anchors(valid), testNow); err != nil {
		t.Fatalf("one intermediate is within max_path_length 1: %v", err)
	}

	tooLong := newIntermediateChain(t, testIntermediateID, map[string]any{"max_path_length": 0})
	_, err := ValidateTrustChain(tooLong.chain, testVerifierID, anchors(tooLong), testNow)
	requireCode(t, err, ErrTrustChainInvalid, "violates max_path_length constraint")

	outside := newIntermediateChain(t, "https://intermediate.evil.test", map[string]any{
		"naming_constraints": map[string]any{"permitted": []string{".example.test"}},
	})
	_, err = ValidateTrustChain(outside.chain, testVerifierID, anchors(outside), testNow)
	requireCode(t, err, ErrTrustChainInvalid, "violates naming_constraints")

	inside := newIntermediateChain(t, testIntermediateID, map[string]any{
		"naming_constraints": map[string]any{"permitted": []string{".EXAMPLE.test"}},
	})
	if _, err := ValidateTrustChain(inside.chain, testVerifierID, anchors(inside), testNow); err != nil {
		t.Fatalf("permitted subtree must match case-insensitively: %v", err)
	}
}

func TestHostInNameSubtree(t *testing.T) {
	cases := []struct {
		host, subtree string
		want          bool
	}{
		{"a.example.test", ".example.test", true},
		{"example.test", ".example.test", false},
		{"example.test", "example.test", true},
		{"a.example.test", "example.test", false},
		{"badexample.test", ".example.test", false},
	}
	for _, tc := range cases {
		if got := hostInNameSubtree(tc.host, tc.subtree); got != tc.want {
			t.Errorf("hostInNameSubtree(%q, %q) = %v, want %v", tc.host, tc.subtree, got, tc.want)
		}
	}
}
