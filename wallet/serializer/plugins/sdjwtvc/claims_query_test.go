package sdjwtvc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/serializer/types"
)

// testDisclosure encodes a disclosure and returns it with its sha-256 digest.
func testDisclosure(t *testing.T, parts ...any) (encoded, digest string) {
	t.Helper()
	raw, err := json.Marshal(parts)
	require.NoError(t, err)
	encoded = base64.RawURLEncoding.EncodeToString(raw)
	digest, err = computeDisclosureHash(encoded, "sha-256")
	require.NoError(t, err)
	return encoded, digest
}

// TestSelectDisclosures pins how DCQL claims map to the disclosures of an SD-JWT
// shaped like the PID used for conformance: top-level _sd, nested _sd inside
// disclosed objects, and selectively disclosable array elements.
func TestSelectDisclosures(t *testing.T) {
	given, givenDigest := testDisclosure(t, "s1", "given_name", "Erika")
	family, familyDigest := testDisclosure(t, "s2", "family_name", "Mustermann")
	locality, localityDigest := testDisclosure(t, "s3", "locality", "Berlin")
	placeOfBirth, placeOfBirthDigest := testDisclosure(t, "s4", "place_of_birth", map[string]any{"_sd": []any{localityDigest}})
	over18, over18Digest := testDisclosure(t, "s5", "18", true)
	ageOver, ageOverDigest := testDisclosure(t, "s6", "age_equal_or_over", map[string]any{"_sd": []any{over18Digest}})
	nationalityDE, nationalityDEDigest := testDisclosure(t, "s7", "DE")
	nationalityFR, nationalityFRDigest := testDisclosure(t, "s8", "FR")

	payload := map[string]any{
		"vct": "urn:eu.europa.ec.eudi:pid:1",
		"_sd": []any{givenDigest, familyDigest, placeOfBirthDigest, ageOverDigest},
		"nationalities": []any{
			map[string]any{"...": nationalityDEDigest},
			map[string]any{"...": nationalityFRDigest},
		},
	}
	all := []string{given, family, locality, placeOfBirth, over18, ageOver, nationalityDE, nationalityFR}

	claims := func(paths ...[]any) *types.ClaimsQuery {
		q := &types.ClaimsQuery{}
		for _, p := range paths {
			q.Claims = append(q.Claims, types.ClaimQuery{Path: p})
		}
		return q
	}

	tests := []struct {
		name  string
		query *types.ClaimsQuery
		want  []string
	}{
		{"claims absent discloses nothing", &types.ClaimsQuery{}, nil},
		{"top-level claims only", claims([]any{"given_name"}, []any{"family_name"}), []string{given, family}},
		{"nested claim brings its parent", claims([]any{"place_of_birth", "locality"}), []string{locality, placeOfBirth}},
		{"object claim brings what is nested in it", claims([]any{"age_equal_or_over"}), []string{over18, ageOver}},
		{"null selects every array element", claims([]any{"nationalities", nil}), []string{nationalityDE, nationalityFR}},
		{"index selects one array element (JSON number)", claims([]any{"nationalities", float64(1)}), []string{nationalityFR}},
		{"index selects one array element (Go int)", claims([]any{"nationalities", 1}), []string{nationalityFR}},
		{"always visible claim needs no disclosure", claims([]any{"vct"}), nil},
		{
			"claim_sets takes the first satisfiable option",
			&types.ClaimsQuery{
				Claims: []types.ClaimQuery{
					{ID: "missing", Path: []any{"address"}},
					{ID: "given", Path: []any{"given_name"}},
				},
				ClaimSets: [][]string{{"missing"}, {"given"}},
			},
			[]string{given},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectDisclosures(payload, all, "sha-256", tt.query, nil)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	t.Run("a requested claim the credential lacks is not satisfiable", func(t *testing.T) {
		_, err := selectDisclosures(payload, all, "sha-256", claims([]any{"given_name"}, []any{"address"}), nil)
		assert.ErrorIs(t, err, types.ErrClaimsNotSatisfiable)
	})

	t.Run("no claim_sets option is satisfiable", func(t *testing.T) {
		_, err := selectDisclosures(payload, all, "sha-256", &types.ClaimsQuery{
			Claims:    []types.ClaimQuery{{ID: "missing", Path: []any{"address"}}},
			ClaimSets: [][]string{{"missing"}},
		}, nil)
		assert.ErrorIs(t, err, types.ErrClaimsNotSatisfiable)
	})

	t.Run("a claim whose disclosure the holder lacks is not satisfiable", func(t *testing.T) {
		_, err := selectDisclosures(payload, []string{family}, "sha-256", claims([]any{"given_name"}), nil)
		assert.ErrorIs(t, err, types.ErrClaimsNotSatisfiable)
	})

	t.Run("a string component on an array aborts processing", func(t *testing.T) {
		_, err := selectDisclosures(payload, all, "sha-256", claims([]any{"nationalities", "DE"}), nil)
		assert.ErrorIs(t, err, types.ErrClaimsNotSatisfiable)
	})
}

// TestSelectDisclosures_ArrayIndexSkipsDecoys pins that an index counts the elements
// the Credential reveals: a decoy digest has no disclosure and is not an element.
func TestSelectDisclosures_ArrayIndexSkipsDecoys(t *testing.T) {
	de, deDigest := testDisclosure(t, "s1", "DE")
	fr, frDigest := testDisclosure(t, "s2", "FR")
	payload := map[string]any{"nationalities": []any{
		map[string]any{"...": "decoy-digest-without-disclosure"},
		map[string]any{"...": deDigest},
		map[string]any{"...": frDigest},
	}}

	got, err := selectDisclosures(payload, []string{de, fr}, "sha-256", &types.ClaimsQuery{
		Claims: []types.ClaimQuery{{Path: []any{"nationalities", float64(0)}}},
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{de}, got)
}

// TestSelectDisclosures_RejectsDigestReuse pins that a crafted SD-JWT referencing
// one digest twice fails instead of making the walk grow exponentially.
func TestSelectDisclosures_RejectsDigestReuse(t *testing.T) {
	leaf, leafDigest := testDisclosure(t, "s1", "x")
	pair, pairDigest := testDisclosure(t, "s2", []any{map[string]any{"...": leafDigest}, map[string]any{"...": leafDigest}})
	payload := map[string]any{"a": []any{map[string]any{"...": pairDigest}}}

	_, err := selectDisclosures(payload, []string{leaf, pair}, "sha-256", &types.ClaimsQuery{
		Claims: []types.ClaimQuery{{Path: []any{"a", nil, nil}}},
	}, nil)
	assert.ErrorIs(t, err, types.ErrClaimsNotSatisfiable)
}

// TestSelectDisclosures_AbortsOnMisplacedComponent pins the abort rules of the
// claims path pointer: a component that does not fit the element it is applied to
// ends the processing instead of selecting something else (OID4VP 1.0 Section 7.1.1).
func TestSelectDisclosures_AbortsOnMisplacedComponent(t *testing.T) {
	given, givenDigest := testDisclosure(t, "s1", "given_name", "Erika")
	de, deDigest := testDisclosure(t, "s2", "DE")
	payload := map[string]any{
		"_sd":           []any{givenDigest},
		"nationalities": []any{map[string]any{"...": deDigest}},
	}
	all := []string{given, de}

	tests := []struct {
		name string
		path []any
	}{
		{"null on a string", []any{"given_name", nil}},
		{"null on an object", []any{nil}},
		{"index on an object", []any{float64(0)}},
		{"index past the last element", []any{"nationalities", float64(1)}},
		{"string on an array", []any{"nationalities", "DE"}},
		{"boolean component", []any{true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := selectDisclosures(payload, all, "sha-256", &types.ClaimsQuery{
				Claims: []types.ClaimQuery{{Path: tt.path}},
			}, nil)
			assert.ErrorIs(t, err, types.ErrClaimsNotSatisfiable)
		})
	}
}

// TestChooseClaims_ClaimSetsOrder pins that the first satisfiable option wins, not
// any other one, and that an empty option is never the answer (Section 6.4.1).
func TestChooseClaims_ClaimSetsOrder(t *testing.T) {
	given, givenDigest := testDisclosure(t, "s1", "given_name", "Erika")
	family, familyDigest := testDisclosure(t, "s2", "family_name", "Mustermann")
	payload := map[string]any{"_sd": []any{givenDigest, familyDigest}}
	all := []string{given, family}
	query := func(sets ...[]string) *types.ClaimsQuery {
		return &types.ClaimsQuery{
			Claims: []types.ClaimQuery{
				{ID: "g", Path: []any{"given_name"}},
				{ID: "f", Path: []any{"family_name"}},
				{ID: "x", Path: []any{"address"}},
			},
			ClaimSets: sets,
		}
	}

	t.Run("the earlier of two satisfiable options wins", func(t *testing.T) {
		got, err := selectDisclosures(payload, all, "sha-256", query([]string{"g"}, []string{"f"}), nil)
		require.NoError(t, err)
		assert.Equal(t, []string{given}, got)
	})

	t.Run("an unsatisfiable option is skipped for the next one", func(t *testing.T) {
		got, err := selectDisclosures(payload, all, "sha-256", query([]string{"x"}, []string{"f"}), nil)
		require.NoError(t, err)
		assert.Equal(t, []string{family}, got)
	})

	t.Run("an empty option is not an answer", func(t *testing.T) {
		got, err := selectDisclosures(payload, all, "sha-256", query([]string{}, []string{"f"}), nil)
		require.NoError(t, err)
		assert.Equal(t, []string{family}, got)
	})
}

// TestSelectDisclosures_SelectedClaimsCapsArrayElements pins that the cap also
// holds for selectively disclosable array elements, which carry no claim name of
// their own and so cannot be checked by name.
func TestSelectDisclosures_SelectedClaimsCapsArrayElements(t *testing.T) {
	given, givenDigest := testDisclosure(t, "s1", "given_name", "Erika")
	secret, secretDigest := testDisclosure(t, "s2", "TOP-SECRET")
	payload := map[string]any{
		"_sd": []any{givenDigest},
		// An always visible array whose elements are selectively disclosable.
		"nationalities": []any{map[string]any{"...": secretDigest}},
	}
	all := []string{given, secret}
	allowed := []string{"given_name"}

	t.Run("an element of a claim outside the cap is refused", func(t *testing.T) {
		_, err := selectDisclosures(payload, all, "sha-256", &types.ClaimsQuery{
			Claims: []types.ClaimQuery{{Path: []any{"nationalities", nil}}},
		}, allowed)
		assert.ErrorIs(t, err, types.ErrClaimsNotSatisfiable)
	})

	t.Run("a claim within the cap still works", func(t *testing.T) {
		got, err := selectDisclosures(payload, all, "sha-256", &types.ClaimsQuery{
			Claims: []types.ClaimQuery{{Path: []any{"given_name"}}},
		}, allowed)
		require.NoError(t, err)
		assert.Equal(t, []string{given}, got)
	})

	// Section 7.3 pulls the sub-claims of a selected claim in with it, so a claim
	// inside the cap can still reach a name outside it.
	t.Run("a sub-claim outside the cap is refused", func(t *testing.T) {
		locality, localityDigest := testDisclosure(t, "s3", "locality", "Berlin")
		place, placeDigest := testDisclosure(t, "s4", "place_of_birth", map[string]any{"_sd": []any{localityDigest}})
		nested := map[string]any{"_sd": []any{placeDigest}}

		_, err := selectDisclosures(nested, []string{locality, place}, "sha-256", &types.ClaimsQuery{
			Claims: []types.ClaimQuery{{Path: []any{"place_of_birth"}}},
		}, []string{"place_of_birth"})
		assert.ErrorIs(t, err, types.ErrClaimsNotSatisfiable)
	})
}

// TestAppendNestedDisclosures_DeepChain pins that a credential whose disclosures
// nest into one another does not overflow the stack. Recursion here would reach a
// depth of chain*nesting, which Go ends with an unrecoverable fatal error.
func TestAppendNestedDisclosures_DeepChain(t *testing.T) {
	const (
		chain   = 300
		nesting = 9000
	)

	// nest wraps value in `nesting` levels of single-element arrays.
	nest := func(value any) any {
		for i := 0; i < nesting; i++ {
			value = []any{value}
		}
		return value
	}

	byDigest := make(map[string]credential.SDJwtDisclosure, chain)
	previous := ""
	for i := 0; i < chain; i++ {
		inner := any(map[string]any{})
		if previous != "" {
			inner = map[string]any{"_sd": []any{previous}}
		}
		digest := fmt.Sprintf("digest-%d", i)
		byDigest[digest] = credential.SDJwtDisclosure{
			Digest: digest,
			Name:   fmt.Sprintf("n%d", i),
			Value:  nest(inner),
		}
		previous = digest
	}

	got := appendNestedDisclosures(nil, map[string]any{"_sd": []any{previous}}, byDigest, map[string]bool{})
	assert.Len(t, got, chain)
}
