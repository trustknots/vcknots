package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/profile"
)

// draft24PresentationDefinition answers two input descriptors so the caller's
// per-descriptor choice is observable in descriptor_map.
const draft24PresentationDefinition = `{"id":"definition-1","input_descriptors":[{"id":"identity"},{"id":"address"}]}`

func draft24PresentationURI(baseURL, responseMode, clientMetadata string) string {
	params := url.Values{
		"client_id":               {"redirect_uri:" + baseURL + "/response"},
		"response_uri":            {baseURL + "/response"},
		"response_type":           {"vp_token"},
		"response_mode":           {responseMode},
		"nonce":                   {"presentation-nonce"},
		"state":                   {"state-to-preserve"},
		"presentation_definition": {draft24PresentationDefinition},
	}
	if clientMetadata != "" {
		params.Set("client_metadata", clientMetadata)
	}
	return "openid4vp://present?" + params.Encode()
}

func draft24SelectionCredentialIDs(t *testing.T, fixture sdjwtPresentationFixture) map[string]string {
	t.Helper()
	entries, _, err := fixture.wallet.GetCredentialEntries(GetCredentialEntriesRequest{Offset: 0, Limit: nil})
	require.NoError(t, err)
	byVCT := map[string]string{}
	for _, entry := range entries {
		require.NotEmpty(t, entry.Credential.Types)
		byVCT[entry.Credential.Types[0]] = entry.Entry.Id
	}
	return byVCT
}

// The Holder's per-input-descriptor choice must reach descriptor_map, and each
// selected credential must carry its own disclosure selection.
func TestWallet_SubmitPresentationDraft24UsesCallerChoice(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro", "family_name": "Yamada"})
	fixture.receive("urn:test:address", &holder, nil, map[string]string{"street_address": "1 Example St", "postal_code": "100-0000"})
	ids := draft24SelectionCredentialIDs(t, fixture)

	request := parseDraft24(t, fixture.wallet, draft24PresentationURI(fixture.baseURL, "direct_post", ""))

	redirect, err := presentSelections(t, fixture.wallet, request, fixture.key, []CredentialSelection{
		{CredentialID: ids["urn:test:identity"], QueryIDs: []string{"identity"}, DisclosedClaims: []string{"given_name"}},
		{CredentialID: ids["urn:test:address"], QueryIDs: []string{"address"}, DisclosedClaims: []string{"postal_code"}},
	})
	require.NoError(t, err)
	require.Equal(t, fixture.baseURL+"/done", redirect)

	form := <-fixture.posted
	require.Equal(t, "state-to-preserve", form.Get("state"))
	var tokens []string
	require.NoError(t, json.Unmarshal([]byte(form.Get("vp_token")), &tokens))
	require.Len(t, tokens, 2)
	require.Equal(t, []string{"given_name"}, disclosedNames(t, tokens[0]))
	require.Equal(t, []string{"postal_code"}, disclosedNames(t, tokens[1]))

	var submission presenterTypes.PresentationSubmission
	require.NoError(t, json.Unmarshal([]byte(form.Get("presentation_submission")), &submission))
	require.Equal(t, "definition-1", submission.DefinitionID)
	require.Len(t, submission.DescriptorMap, 2)
	require.Equal(t, "identity", submission.DescriptorMap[0].ID)
	require.Equal(t, "dc+sd-jwt", submission.DescriptorMap[0].Format)
	require.Equal(t, "$[0]", submission.DescriptorMap[0].Path)
	require.Equal(t, "address", submission.DescriptorMap[1].ID)
	require.Equal(t, "$[1]", submission.DescriptorMap[1].Path)
}

// A single selection keeps the vp_token a bare presentation at path "$".
func TestWallet_SubmitPresentationDraft24SingleCredentialKeepsRootPath(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	ids := draft24SelectionCredentialIDs(t, fixture)

	request := parseDraft24(t, fixture.wallet, draft24PresentationURI(fixture.baseURL, "direct_post", ""))

	_, err := presentSelections(t, fixture.wallet, request, fixture.key, []CredentialSelection{
		{CredentialID: ids["urn:test:identity"], QueryIDs: []string{"identity"}, DisclosedClaims: []string{"given_name"}},
	})
	require.NoError(t, err)

	form := <-fixture.posted
	require.NotContains(t, form.Get("vp_token"), "[")
	require.Equal(t, []string{"given_name"}, disclosedNames(t, form.Get("vp_token")))
	var submission presenterTypes.PresentationSubmission
	require.NoError(t, json.Unmarshal([]byte(form.Get("presentation_submission")), &submission))
	require.Len(t, submission.DescriptorMap, 1)
	require.Equal(t, "$", submission.DescriptorMap[0].Path)
}

// response_mode=direct_post.jwt must encrypt, send the JWE alone, and carry
// presentation_submission as a JSON object rather than the legacy
// double-encoded string (OID4VP 1.0 Section 8.3).
func TestWallet_SubmitPresentationDraft24EncryptsDirectPostJWT(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	ids := draft24SelectionCredentialIDs(t, fixture)

	verifierKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &verifierKey.PublicKey, KeyID: "recipient", Use: "enc", Algorithm: "ECDH-ES"}}})
	require.NoError(t, err)
	clientMetadata := `{"jwks":` + string(jwks) + `,"encrypted_response_enc_values_supported":["A256GCM"],"authorization_encrypted_response_alg":"ECDH-ES","authorization_encrypted_response_enc":"A256GCM"}`

	request := parseDraft24(t, fixture.wallet, draft24PresentationURI(fixture.baseURL, "direct_post.jwt", clientMetadata))

	result, err := fixture.wallet.SubmitPresentation(t.Context(), request, Presentation{Key: fixture.key, Credentials: []CredentialSelection{
		{CredentialID: ids["urn:test:identity"], QueryIDs: []string{"identity"}, DisclosedClaims: []string{"given_name"}},
	}})
	require.NoError(t, err)
	require.True(t, result.Encrypted)

	form := <-fixture.posted
	require.Len(t, form, 1)
	require.NotEmpty(t, form.Get("response"))
	jwe, err := jose.ParseEncrypted(form.Get("response"), []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	require.NoError(t, err)
	plaintext, err := jwe.Decrypt(verifierKey)
	require.NoError(t, err)
	payload := map[string]any{}
	require.NoError(t, json.Unmarshal(plaintext, &payload))
	require.Equal(t, "state-to-preserve", payload["state"])
	require.IsType(t, "", payload["vp_token"])
	submission, ok := payload["presentation_submission"].(map[string]any)
	require.True(t, ok, "presentation_submission must be a JSON object, got %#v", payload["presentation_submission"])
	require.Equal(t, "definition-1", submission["definition_id"])
}

// An unknown credential id must not be silently skipped: the descriptor_map
// would then describe credentials the wallet never sent.
func TestWallet_SubmitPresentationDraft24RejectsUnknownCredential(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})

	request := parseDraft24(t, fixture.wallet, draft24PresentationURI(fixture.baseURL, "direct_post", ""))

	_, err := presentSelections(t, fixture.wallet, request, fixture.key, []CredentialSelection{
		{CredentialID: "not-stored", QueryIDs: []string{"identity"}},
	})
	require.ErrorContains(t, err, "not stored in this wallet")
	select {
	case <-fixture.posted:
		t.Fatal("an unresolvable selection disclosed credentials")
	default:
	}
}

// A Presentation Exchange vp_token cannot express "no credential"; only the
// DCQL response object can, so an empty selection is refused before any POST.
// A selection must also name the input descriptors it answers.
func TestWallet_SubmitPresentationDraft24RejectsIncompleteSelections(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	request := parseDraft24(t, fixture.wallet, draft24PresentationURI(fixture.baseURL, "direct_post", ""))

	_, err := presentSelections(t, fixture.wallet, request, fixture.key, nil)
	require.ErrorContains(t, err, "at least one credential selection is required")
	require.ErrorIs(t, err, ErrInvalidArgument)

	_, err = presentSelections(t, fixture.wallet, request, fixture.key, []CredentialSelection{
		{CredentialID: draft24SelectionCredentialIDs(t, fixture)["urn:test:identity"]},
	})
	require.ErrorContains(t, err, "must name its input descriptors")
	select {
	case <-fixture.posted:
		t.Fatal("an incomplete selection disclosed credentials")
	default:
	}
}

// The library's own choice for a Draft 24 request is the newest credential
// answering every input descriptor, and presenting it needs nothing more.
func TestWallet_SelectCredentialsDraft24(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	request := parseDraft24(t, fixture.wallet, draft24PresentationURI(fixture.baseURL, "direct_post", ""))

	selections, err := fixture.wallet.SelectCredentials(t.Context(), request)
	require.NoError(t, err)
	require.Equal(t, []CredentialSelection{{
		CredentialID: draft24SelectionCredentialIDs(t, fixture)["urn:test:identity"],
		QueryIDs:     []string{"identity", "address"},
	}}, selections)
	_, err = presentSelections(t, fixture.wallet, request, fixture.key, selections)
	require.NoError(t, err)
	var submission presenterTypes.PresentationSubmission
	require.NoError(t, json.Unmarshal([]byte((<-fixture.posted).Get("presentation_submission")), &submission))
	require.Len(t, submission.DescriptorMap, 2)
}

// HAIP applies to OpenID4VP 1.0 only: the Draft 24 view refuses to parse,
// and a Draft 24 handle is neither answered nor declined.
func TestWallet_Draft24RefusedUnderHAIP(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	uri := draft24PresentationURI(fixture.baseURL, "direct_post", "")
	request := parseDraft24(t, fixture.wallet, uri)
	fixture.wallet.profile = profile.HAIP

	_, err := fixture.wallet.Draft24().ParsePresentationRequest(t.Context(), uri)
	require.ErrorIs(t, err, ErrProfileForbidsDraft)
	_, err = fixture.wallet.Draft24().ParsePresentationRequestObject(t.Context(), "a.b.c", presenterTypes.RequestObjectSource{})
	require.ErrorIs(t, err, ErrProfileForbidsDraft)
	_, err = fixture.wallet.SelectCredentials(t.Context(), request)
	require.ErrorIs(t, err, ErrProfileForbidsDraft)
	_, err = presentSelections(t, fixture.wallet, request, fixture.key, []CredentialSelection{
		{CredentialID: draft24SelectionCredentialIDs(t, fixture)["urn:test:identity"], QueryIDs: []string{"identity"}},
	})
	require.ErrorIs(t, err, ErrProfileForbidsDraft)
	_, err = fixture.wallet.DeclinePresentation(t.Context(), request, "access_denied", "")
	require.ErrorIs(t, err, ErrProfileForbidsDraft)
	require.Len(t, fixture.posted, 0)
}

// buildDraft24DescriptorMap decides two things the vp_token shape depends on:
// an SD-JWT VC Presentation holds one credential, so several of them are a JSON
// array the path indexes, while a JWT Verifiable Presentation holds them all and
// stays a single token at "$" whose path_nested distinguishes them.
func TestBuildDraft24DescriptorMapPathsFollowTheVPTokenShape(t *testing.T) {
	for _, tc := range []struct {
		name       string
		flavor     credential.SupportedSerializationFlavor
		paths      []string
		nested     []string
		vpFormat   string
		descriptor [][]string
		wantIDs    []string
	}{
		{
			name:       "sd-jwt vc indexes the vp_token array",
			flavor:     credential.SDJwtVC,
			paths:      []string{"$[0]", "$[0]", "$[1]"},
			vpFormat:   "dc+sd-jwt",
			descriptor: [][]string{{"identity", "identity-backup"}, {"address"}},
			wantIDs:    []string{"identity", "identity-backup", "address"},
		},
		{
			name:       "jwt vc indexes inside one presentation",
			flavor:     credential.JwtVc,
			paths:      []string{"$", "$", "$"},
			nested:     []string{"$.vp.verifiableCredential[0]", "$.vp.verifiableCredential[0]", "$.vp.verifiableCredential[1]"},
			vpFormat:   "jwt_vp_json",
			descriptor: [][]string{{"identity", "identity-backup"}, {"address"}},
			wantIDs:    []string{"identity", "identity-backup", "address"},
		},
		{
			name:       "ldp vp indexes the presentation itself",
			flavor:     credential.LdpVc,
			paths:      []string{"$", "$", "$"},
			nested:     []string{"$.verifiableCredential[0]", "$.verifiableCredential[0]", "$.verifiableCredential[1]"},
			vpFormat:   "ldp_vp",
			descriptor: [][]string{{"identity", "identity-backup"}, {"address"}},
			wantIDs:    []string{"identity", "identity-backup", "address"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			descriptorMap, err := buildDraft24DescriptorMap(2, tc.flavor, tc.descriptor)
			require.NoError(t, err)
			require.Len(t, descriptorMap, len(tc.wantIDs))
			for index, item := range descriptorMap {
				require.Equal(t, tc.wantIDs[index], item.ID)
				require.Equal(t, tc.vpFormat, item.Format)
				require.Equal(t, tc.paths[index], item.Path)
				if len(tc.nested) == 0 {
					require.Nil(t, item.PathNested)
					continue
				}
				require.NotNil(t, item.PathNested)
				require.Equal(t, tc.nested[index], item.PathNested.Path)
				require.Equal(t, tc.wantIDs[index], item.PathNested.ID)
			}
		})
	}
}

// parseDraft24 admits a Draft 24 request through w's Draft 24 view.
func parseDraft24(t *testing.T, w *Wallet, uri string) *oid4vp.AdmittedRequest {
	t.Helper()
	request, err := w.Draft24().ParsePresentationRequest(t.Context(), uri)
	require.NoError(t, err)
	require.True(t, request.Draft24())
	return request
}
