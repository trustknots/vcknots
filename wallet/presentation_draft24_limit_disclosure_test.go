package wallet

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
)

// limitedDefinition asks for the identity credential with limit_disclosure
// "required" and one listed field.
const limitedDefinition = `{"id":"limited","input_descriptors":[{"id":"identity","format":{"vc+sd-jwt":{}},` +
	`"constraints":{"limit_disclosure":"required","fields":[{"path":["$.given_name"]}]}}]}`

func limitedDisclosureURI(baseURL, definition string) string {
	return "openid4vp://present?" + url.Values{
		"client_id":               {"redirect_uri:" + baseURL + "/response"},
		"response_uri":            {baseURL + "/response"},
		"response_type":           {"vp_token"},
		"response_mode":           {"direct_post"},
		"nonce":                   {"presentation-nonce"},
		"presentation_definition": {definition},
	}.Encode()
}

// DIF Presentation Exchange 2.0, Input Descriptor Object, limit_disclosure
// "required": "the Conformant Consumer MUST limit submitted fields to those
// listed in the fields array". Without DisclosedClaims the presentation
// discloses the listed fields only, and a caller disclosure beyond them is
// refused before anything is sent.
func TestWallet_Draft24LimitDisclosureRequired(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro", "family_name": "Yamada"})
	request := parseDraft24(t, fixture.wallet, limitedDisclosureURI(fixture.baseURL, limitedDefinition))

	selections, err := fixture.wallet.SelectCredentials(t.Context(), request)
	require.NoError(t, err)
	_, err = presentSelections(t, fixture.wallet, request, fixture.key, selections)
	require.NoError(t, err)
	form := <-fixture.posted
	require.Equal(t, []string{"given_name"}, disclosedNames(t, form.Get("vp_token")))

	id := draft24SelectionCredentialIDs(t, fixture)["urn:test:identity"]
	_, err = presentSelections(t, fixture.wallet, request, fixture.key, []CredentialSelection{
		{CredentialID: id, QueryIDs: []string{"identity"}, DisclosedClaims: []string{"given_name", "family_name"}},
	})
	require.ErrorIs(t, err, ErrLimitDisclosureUnsatisfiable)
	select {
	case <-fixture.posted:
		t.Fatal("a presentation beyond the listed fields was sent")
	default:
	}

	// A descriptor without limit_disclosure keeps the caller's choice.
	unlimited := `{"id":"open","input_descriptors":[{"id":"identity","format":{"vc+sd-jwt":{}},"constraints":{"fields":[{"path":["$.given_name"]}]}}]}`
	request = parseDraft24(t, fixture.wallet, limitedDisclosureURI(fixture.baseURL, unlimited))
	_, err = presentSelections(t, fixture.wallet, request, fixture.key, []CredentialSelection{
		{CredentialID: id, QueryIDs: []string{"identity"}, DisclosedClaims: []string{"given_name", "family_name"}},
	})
	require.NoError(t, err)
	form = <-fixture.posted
	require.ElementsMatch(t, []string{"given_name", "family_name"}, disclosedNames(t, form.Get("vp_token")))
}

// A JWT or Data Integrity W3C VC is presented whole, so it cannot limit
// disclosure; Presentation Exchange lets the Wallet "return nothing".
func TestWallet_Draft24LimitDisclosureRequiredRefusesAWholeCredential(t *testing.T) {
	controller, key := receiveCredentialForPresentationTest(t)
	entries, _, err := controller.GetCredentialEntries(GetCredentialEntriesRequest{})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	definition := `{"id":"limited","input_descriptors":[{"id":"d1","constraints":{"limit_disclosure":"required","fields":[{"path":["$.credentialSubject.name"]}]}}]}`
	req := &oid4vp.CredentialPresentationRequest{
		OAuthAuthzRequest:         &oid4vp.OAuthAuthzRequest{ResponseType: "vp_token", ClientID: "redirect_uri:https://verifier.example/response", Nonce: "n"},
		PresentationDefinition:    &oid4vp.PresentationDefinition{ID: "limited"},
		RawPresentationDefinition: json.RawMessage(definition),
	}
	selections := []CredentialSelection{{CredentialID: entries[0].Entry.Id, QueryIDs: []string{"d1"}}}
	credentials, err := controller.resolveSelections(selections, key)
	require.NoError(t, err)
	_, err = draft24DisclosureLimits(req.RawPresentationDefinition, selections, credentials)
	require.ErrorIs(t, err, ErrLimitDisclosureUnsatisfiable)
}

func TestJSONPathClaimsPointer(t *testing.T) {
	for path, want := range map[string]string{
		"$.given_name":                       `["given_name"]`,
		"$.address.street_address":           `["address","street_address"]`,
		"$['given_name']":                    `["given_name"]`,
		`$["address"]["locality"]`:           `["address","locality"]`,
		"$.nationalities[0]":                 `["nationalities",0]`,
		"$.nationalities[*]":                 `["nationalities",null]`,
		"$.degrees.*.type":                   `["degrees",null,"type"]`,
		"$.vc.credentialSubject.family_name": `["vc","credentialSubject","family_name"]`,
		"$.address['locality'][0]":           `["address","locality",0]`,
	} {
		pointer, ok := jsonPathClaimsPointer(path)
		require.True(t, ok, path)
		require.Equal(t, want, pointer, path)
	}
	// Recursive descent could select a same-named claim at any level.
	for _, path := range []string{"", "given_name", "$", "$.*", "$[0]", "$..birthdate", "$[?(@.age > 18)]", "$.a[", "$.a[b]", "$.a[-1]"} {
		_, ok := jsonPathClaimsPointer(path)
		require.False(t, ok, path)
	}
}

// A nested selectively disclosable claim is reachable only through its
// parent's disclosure (RFC 9901, recursive disclosures), so a required
// $.address.city discloses address and city - and nothing else.
func TestWallet_Draft24LimitDisclosureRequiredKeepsTheParentOfANestedClaim(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	given, givenHash := sdDisclosure(t, "salt-given", "given_name", "Taro")
	postal, postalHash := sdDisclosure(t, "salt-postal", "postal_code", "12345")
	city, cityHash := sdDisclosure(t, "salt-city", "city", "Milliways")
	address, addressHash := sdDisclosure(t, "salt-address", "address", map[string]any{"_sd": []any{postalHash, cityHash}})
	storeSDJWT(t, fixture, map[string]any{"_sd": []any{givenHash, addressHash}}, given, address, postal, city)
	definition := `{"id":"limited","input_descriptors":[{"id":"identity","format":{"vc+sd-jwt":{}},` +
		`"constraints":{"limit_disclosure":"required","fields":[{"path":["$.address.city"]}]}}]}`
	request := parseDraft24(t, fixture.wallet, limitedDisclosureURI(fixture.baseURL, definition))
	selections, err := fixture.wallet.SelectCredentials(t.Context(), request)
	require.NoError(t, err)
	_, err = presentSelections(t, fixture.wallet, request, fixture.key, selections)
	require.NoError(t, err)
	form := <-fixture.posted
	require.ElementsMatch(t, []string{"address", "city"}, disclosedNames(t, form.Get("vp_token")))
}

// A disclosure is revealed whole, so disclosing the parent address to reach a
// listed $.address.city would also show its plaintext street_address, which no
// field lists (Presentation Exchange 2.0 limit_disclosure "required"). The
// presentation is refused; listing street_address as well makes it allowed.
func TestWallet_Draft24LimitDisclosureRequiredRefusesAParentsUnlistedPlaintext(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	city, cityHash := sdDisclosure(t, "salt-city", "city", "Milliways")
	address, addressHash := sdDisclosure(t, "salt-address", "address", map[string]any{"street_address": "42 Main St", "_sd": []any{cityHash}})
	storeSDJWT(t, fixture, map[string]any{"_sd": []any{addressHash}}, address, city)
	cityOnly := `{"id":"limited","input_descriptors":[{"id":"identity","format":{"vc+sd-jwt":{}},` +
		`"constraints":{"limit_disclosure":"required","fields":[{"path":["$.address.city"]}]}}]}`
	request := parseDraft24(t, fixture.wallet, limitedDisclosureURI(fixture.baseURL, cityOnly))
	selections, err := fixture.wallet.SelectCredentials(t.Context(), request)
	require.NoError(t, err)
	_, err = presentSelections(t, fixture.wallet, request, fixture.key, selections)
	require.ErrorIs(t, err, ErrLimitDisclosureUnsatisfiable)
	select {
	case <-fixture.posted:
		t.Fatal("a presentation showing an unlisted plaintext member was sent")
	default:
	}

	both := `{"id":"limited","input_descriptors":[{"id":"identity","format":{"vc+sd-jwt":{}},` +
		`"constraints":{"limit_disclosure":"required","fields":[{"path":["$.address.city"]},{"path":["$.address.street_address"]}]}}]}`
	request = parseDraft24(t, fixture.wallet, limitedDisclosureURI(fixture.baseURL, both))
	selections, err = fixture.wallet.SelectCredentials(t.Context(), request)
	require.NoError(t, err)
	_, err = presentSelections(t, fixture.wallet, request, fixture.key, selections)
	require.NoError(t, err)
	form := <-fixture.posted
	require.ElementsMatch(t, []string{"address", "city"}, disclosedNames(t, form.Get("vp_token")))
}

// The same applies to an array element disclosure: reaching the listed type of
// each degree would also show the plaintext name beside it.
func TestWallet_Draft24LimitDisclosureRequiredRefusesAnElementsUnlistedPlaintext(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	degree, degreeHash := sdDisclosure(t, "salt-degree", map[string]any{"type": "BachelorDegree", "name": "Bachelor of Science"})
	storeSDJWT(t, fixture, map[string]any{"degrees": []any{map[string]any{"...": degreeHash}}}, degree)
	definition := `{"id":"limited","input_descriptors":[{"id":"identity","format":{"vc+sd-jwt":{}},` +
		`"constraints":{"limit_disclosure":"required","fields":[{"path":["$.degrees[*].type"]}]}}]}`
	request := parseDraft24(t, fixture.wallet, limitedDisclosureURI(fixture.baseURL, definition))
	selections, err := fixture.wallet.SelectCredentials(t.Context(), request)
	require.NoError(t, err)
	_, err = presentSelections(t, fixture.wallet, request, fixture.key, selections)
	require.ErrorIs(t, err, ErrLimitDisclosureUnsatisfiable)
}

// A field is matched by its full path. $.employer.name discloses the employer
// and the name inside it, never the Holder's own root-level name, whose
// disclosure has the same claim name.
func TestWallet_Draft24LimitDisclosureRequiredMatchesTheFullPath(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	rootName, rootNameHash := sdDisclosure(t, "salt-root-name", "name", "Taro Yamada")
	employerName, employerNameHash := sdDisclosure(t, "salt-employer-name", "name", "ACME Corporation")
	employer, employerHash := sdDisclosure(t, "salt-employer", "employer", map[string]any{"_sd": []any{employerNameHash}})
	storeSDJWT(t, fixture, map[string]any{"_sd": []any{rootNameHash, employerHash}}, rootName, employer, employerName)
	definition := `{"id":"limited","input_descriptors":[{"id":"identity","format":{"vc+sd-jwt":{}},` +
		`"constraints":{"limit_disclosure":"required","fields":[{"path":["$.employer.name"]}]}}]}`
	request := parseDraft24(t, fixture.wallet, limitedDisclosureURI(fixture.baseURL, definition))
	selections, err := fixture.wallet.SelectCredentials(t.Context(), request)
	require.NoError(t, err)
	_, err = presentSelections(t, fixture.wallet, request, fixture.key, selections)
	require.NoError(t, err)
	vpToken := (<-fixture.posted).Get("vp_token")
	require.ElementsMatch(t, []string{"employer", "name"}, disclosedNames(t, vpToken))
	require.Contains(t, vpToken, employerName)
	require.NotContains(t, vpToken, rootName)

	// A Holder who kept only "name" did not keep the employer the field
	// needs, so the field is left out rather than matched by name.
	id := selections[0].CredentialID
	_, err = presentSelections(t, fixture.wallet, request, fixture.key, []CredentialSelection{
		{CredentialID: id, QueryIDs: []string{"identity"}, DisclosedClaims: []string{"name"}},
	})
	require.NoError(t, err)
	vpToken = (<-fixture.posted).Get("vp_token")
	require.Empty(t, disclosedNames(t, vpToken))
}

// A listed nested claim the issuer signed in plaintext needs no disclosure, so
// a same-named selectively disclosable claim at the root is not disclosed in
// its place.
func TestWallet_Draft24LimitDisclosureRequiredDoesNotSubstituteASameNamedClaim(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	rootName, rootNameHash := sdDisclosure(t, "salt-root-name", "name", "Taro Yamada")
	storeSDJWT(t, fixture, map[string]any{"employer": map[string]any{"name": "ACME Corporation"}, "_sd": []any{rootNameHash}}, rootName)
	definition := `{"id":"limited","input_descriptors":[{"id":"identity","format":{"vc+sd-jwt":{}},` +
		`"constraints":{"limit_disclosure":"required","fields":[{"path":["$.employer.name"]}]}}]}`
	request := parseDraft24(t, fixture.wallet, limitedDisclosureURI(fixture.baseURL, definition))
	selections, err := fixture.wallet.SelectCredentials(t.Context(), request)
	require.NoError(t, err)
	_, err = presentSelections(t, fixture.wallet, request, fixture.key, selections)
	require.NoError(t, err)
	vpToken := (<-fixture.posted).Get("vp_token")
	require.Empty(t, disclosedNames(t, vpToken))
	require.NotContains(t, vpToken, rootName)
}
