package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/credential"
)

func TestSelectedDisclosuresRespectRootCommitments(t *testing.T) {
	encode := func(parts ...any) (string, string) {
		raw, err := json.Marshal(parts)
		require.NoError(t, err)
		encoded := base64.RawURLEncoding.EncodeToString(raw)
		digest := sha256.Sum256([]byte(encoded))
		return encoded, base64.RawURLEncoding.EncodeToString(digest[:])
	}
	root, rootHash := encode("root-salt", "given_name", "Taro")
	nested, nestedHash := encode("nested-salt", "given_name", "Another Person")
	array, arrayHash := encode("array-salt", "Array value")
	for _, tc := range []struct {
		name                      string
		payload                   map[string]any
		disclosures, claims, want []string
		wantError                 bool
	}{
		{name: "requested plaintext requires no disclosure", payload: map[string]any{"nationality": "JP", "_sd": []any{rootHash}}, disclosures: []string{root}, claims: []string{"nationality"}},
		{name: "root names do not disclose same-named nested claims", payload: map[string]any{"_sd": []any{rootHash}, "other": map[string]any{"_sd": []any{nestedHash}}}, disclosures: []string{root, nested}, claims: []string{"given_name"}, want: []string{root}},
		{name: "nested name cannot satisfy root request", payload: map[string]any{"other": map[string]any{"_sd": []any{nestedHash}}}, disclosures: []string{nested}, claims: []string{"given_name"}, wantError: true},
		{name: "uncommitted disclosure cannot satisfy request", payload: map[string]any{"_sd": []any{"wrong-digest"}}, disclosures: []string{root}, claims: []string{"given_name"}, wantError: true},
		{name: "duplicate root digest rejected", payload: map[string]any{"_sd": []any{rootHash, rootHash}}, disclosures: []string{root}, claims: []string{"given_name"}, wantError: true},
		{name: "duplicate root property rejected", payload: map[string]any{"_sd": []any{rootHash, nestedHash}}, disclosures: []string{root, nested}, claims: []string{"given_name"}, wantError: true},
		{name: "selective cannot overwrite plaintext", payload: map[string]any{"given_name": "Existing", "_sd": []any{rootHash}}, disclosures: []string{root}, claims: []string{"given_name"}, wantError: true},
		{name: "array element is not an object property", payload: map[string]any{"_sd": []any{arrayHash}}, disclosures: []string{array}, claims: []string{"given_name"}, wantError: true},
		{name: "no requested claims discloses none", payload: map[string]any{"_sd": []any{rootHash}}, disclosures: []string{root}},
		{name: "duplicate request selects once", payload: map[string]any{"_sd": []any{rootHash}}, disclosures: []string{root}, claims: []string{"given_name", "given_name"}, want: []string{root}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectTopLevelDisclosures(tc.payload, tc.disclosures, "sha-256", tc.claims)
			if tc.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.ElementsMatch(t, tc.want, got)
		})
	}
}

func TestDeserializeCredentialKeepsNestedNamesOutOfRootClaims(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("dc+sd-jwt"))
	require.NoError(t, err)
	raw, err := json.Marshal([]any{"nested-salt", "given_name", "Jiro"})
	require.NoError(t, err)
	disclosure := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(disclosure))
	hash := base64.RawURLEncoding.EncodeToString(digest[:])
	for _, tc := range []struct {
		name      string
		payload   map[string]any
		want      string
		wantError bool
	}{
		{name: "nested value cannot overwrite plaintext", payload: map[string]any{"given_name": "Taro", "other": map[string]any{"_sd": []any{hash}}}, want: "Taro"},
		{name: "nested-only name is not a root property", payload: map[string]any{"other": map[string]any{"_sd": []any{hash}}}},
		{name: "uncommitted name is not a root property", payload: map[string]any{}},
		{name: "committed root name is reconstructed", payload: map[string]any{"_sd": []any{hash}}, want: "Jiro"},
		{name: "root disclosure cannot overwrite plaintext", payload: map[string]any{"given_name": "Taro", "_sd": []any{hash}}, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.payload["iss"] = "https://issuer.example"
			tc.payload["vct"] = "urn:test:identity"
			signed, err := jwt.Signed(signer).Claims(tc.payload).Serialize()
			require.NoError(t, err)
			serializer, err := NewSdJwtVcSerializer()
			require.NoError(t, err)
			parsed, err := serializer.DeserializeCredential(credential.SDJwtVC, []byte(signed+"~"+disclosure+"~"))
			if tc.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tc.want == "" {
				require.NotContains(t, *parsed.Claims, "given_name")
			} else {
				require.Equal(t, tc.want, (*parsed.Claims)["given_name"])
			}
		})
	}
}

func TestSelectTopLevelDisclosuresNestedPaths(t *testing.T) {
	encode := func(parts ...any) (string, string) {
		raw, err := json.Marshal(parts)
		require.NoError(t, err)
		encoded := base64.RawURLEncoding.EncodeToString(raw)
		digest := sha256.Sum256([]byte(encoded))
		return encoded, base64.RawURLEncoding.EncodeToString(digest[:])
	}

	t.Run("nested object property selects only the leaf disclosure", func(t *testing.T) {
		postal, postalHash := encode("salt-p", "postal_code", "12345")
		city, cityHash := encode("salt-c", "city", "Milliways")
		payload := map[string]any{"address": map[string]any{"_sd": []any{postalHash, cityHash}}}
		selected, err := selectTopLevelDisclosures(payload, []string{postal, city}, "sha-256", []string{`["address","postal_code"]`})
		require.NoError(t, err)
		require.Equal(t, []string{postal}, selected)
	})

	t.Run("null selects every array element and only the requested member", func(t *testing.T) {
		type1, type1Hash := encode("salt-t1", "type", "BSc")
		type2, type2Hash := encode("salt-t2", "type", "MSc")
		other, otherHash := encode("salt-o", "university", "Betelgeuse")
		payload := map[string]any{"degrees": []any{
			map[string]any{"_sd": []any{type1Hash, otherHash}},
			map[string]any{"_sd": []any{type2Hash, otherHash}},
		}}
		selected, err := selectTopLevelDisclosures(payload, []string{type1, type2, other}, "sha-256", []string{`["degrees",null,"type"]`})
		require.NoError(t, err)
		require.ElementsMatch(t, []string{type1, type2}, selected)
	})

	t.Run("integer index selects a disclosed array element", func(t *testing.T) {
		cherry, cherryHash := encode("salt-ch", "Cherry")
		payload := map[string]any{"fruits": []any{"Apple", map[string]any{"...": cherryHash}}}
		selected, err := selectTopLevelDisclosures(payload, []string{cherry}, "sha-256", []string{`["fruits",1]`})
		require.NoError(t, err)
		require.Equal(t, []string{cherry}, selected)
	})

	t.Run("unselected sibling remains hidden", func(t *testing.T) {
		postal, postalHash := encode("salt-p", "postal_code", "12345")
		city, cityHash := encode("salt-c", "city", "Milliways")
		payload := map[string]any{"address": map[string]any{"_sd": []any{postalHash, cityHash}}}
		selected, err := selectTopLevelDisclosures(payload, []string{postal, city}, "sha-256", []string{`["address","postal_code"]`})
		require.NoError(t, err)
		require.NotContains(t, selected, city)
	})
}

func TestReconstructClaimsObjectAppliesNestedDisclosures(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("dc+sd-jwt"))
	require.NoError(t, err)

	encode := func(parts ...any) (string, string) {
		raw, err := json.Marshal(parts)
		require.NoError(t, err)
		encoded := base64.RawURLEncoding.EncodeToString(raw)
		digest := sha256.Sum256([]byte(encoded))
		return encoded, base64.RawURLEncoding.EncodeToString(digest[:])
	}
	postal, postalHash := encode("salt-p", "postal_code", "12345")
	type1, type1Hash := encode("salt-t1", "type", "BSc")
	cherry, cherryHash := encode("salt-ch", "Cherry")

	payload := map[string]any{
		"iss":     "https://issuer.example",
		"vct":     "urn:test:identity",
		"address": map[string]any{"_sd": []any{postalHash}},
		"degrees": []any{map[string]any{"_sd": []any{type1Hash}}},
		"fruits":  []any{"Apple", map[string]any{"...": cherryHash}},
		"_sd_alg": "sha-256",
	}
	signed, err := jwt.Signed(signer).Claims(payload).Serialize()
	require.NoError(t, err)
	wire := signed + "~" + postal + "~" + type1 + "~" + cherry + "~"

	object, err := ReconstructClaimsObject(wire)
	require.NoError(t, err)
	require.Equal(t, "12345", object["address"].(map[string]any)["postal_code"])
	require.Equal(t, "BSc", object["degrees"].([]any)[0].(map[string]any)["type"])
	require.Equal(t, "Cherry", object["fruits"].([]any)[1])
}

// A claims path pointer selects each element as a whole (OID4VP 1.0 Section
// 7), so the selectively disclosable members of a selected object or array
// element are disclosed with it, while a sibling claim is not.
func TestSelectedDisclosuresIncludeMembersOfSelectedElements(t *testing.T) {
	encode := func(parts ...any) (string, string) {
		raw, err := json.Marshal(parts)
		require.NoError(t, err)
		encoded := base64.RawURLEncoding.EncodeToString(raw)
		digest := sha256.Sum256([]byte(encoded))
		return encoded, base64.RawURLEncoding.EncodeToString(digest[:])
	}
	street, streetHash := encode("s1", "street", "1 Main St")
	city, cityHash := encode("s2", "city", "Milliways")
	address, addressHash := encode("s3", "address", map[string]any{"_sd": []any{streetHash, cityHash, "decoy-digest"}})
	degreeType, degreeTypeHash := encode("s4", "type", "Bachelor")
	degree, degreeHash := encode("s5", map[string]any{"_sd": []any{degreeTypeHash}})
	given, givenHash := encode("s6", "given_name", "Taro")
	payload := map[string]any{
		"_sd":     []any{addressHash, givenHash},
		"degrees": []any{map[string]any{"...": degreeHash}},
	}
	disclosures := []string{street, city, address, degreeType, degree, given}

	got, err := selectTopLevelDisclosures(payload, disclosures, "sha-256", []string{"address"})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{address, street, city}, got)

	got, err = selectTopLevelDisclosures(payload, disclosures, "sha-256", []string{`["degrees",null]`})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{degree, degreeType}, got)

	got, err = selectTopLevelDisclosures(payload, disclosures, "sha-256", []string{`["address","city"]`})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{address, city}, got)
}

// An array may hold decoy digests (RFC 9901 Section 4.2.5). A selected array or
// object discloses its real elements only, a decoy takes no index, and the
// reconstructed view the DCQL matcher reads drops it, so both count the same
// elements.
func TestSelectedDisclosuresSkipArrayDecoys(t *testing.T) {
	encode := func(parts ...any) (string, string) {
		raw, err := json.Marshal(parts)
		require.NoError(t, err)
		encoded := base64.RawURLEncoding.EncodeToString(raw)
		digest := sha256.Sum256([]byte(encoded))
		return encoded, base64.RawURLEncoding.EncodeToString(digest[:])
	}
	de, deHash := encode("s1", "DE")
	fr, frHash := encode("s2", "FR")
	other, otherHash := encode("s3", "other_claim", "x")
	decoy := map[string]any{"...": "decoy-array-digest"}
	payload := map[string]any{
		"_sd":           []any{otherHash},
		"nationalities": []any{decoy, map[string]any{"...": deHash}, decoy, map[string]any{"...": frHash}},
		"address":       map[string]any{"countries": []any{map[string]any{"...": deHash}, decoy}},
	}
	disclosures := []string{de, fr, other}

	for claim, want := range map[string][]string{
		"nationalities":           {de, fr},
		`["nationalities",null]`:  {de, fr},
		`["nationalities",0]`:     {de},
		`["nationalities",1]`:     {fr},
		"address":                 {de},
		`["address","countries"]`: {de},
	} {
		got, err := selectTopLevelDisclosures(payload, disclosures, "sha-256", []string{claim})
		require.NoError(t, err, claim)
		require.ElementsMatch(t, want, got, claim)
	}
	_, err := selectTopLevelDisclosures(payload, disclosures, "sha-256", []string{`["nationalities",2]`})
	require.Error(t, err, "a decoy takes no index")

	// A placeholder naming an object property disclosure is malformed.
	malformed := map[string]any{"_sd": []any{otherHash}, "list": []any{map[string]any{"...": otherHash}}}
	_, err = selectTopLevelDisclosures(malformed, disclosures, "sha-256", []string{"list"})
	require.Error(t, err)

	resolver, err := newSDJWTDisclosureResolver(disclosures, "sha-256")
	require.NoError(t, err)
	reconstructed, err := resolver.reconstruct(payload)
	require.NoError(t, err)
	object := reconstructed.(map[string]any)
	require.Equal(t, []any{"DE", "FR"}, object["nationalities"])
	require.Equal(t, []any{"DE"}, object["address"].(map[string]any)["countries"])
}
