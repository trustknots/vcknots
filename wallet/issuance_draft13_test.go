package wallet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/internal/observetest"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver"
	receiverOid4vci "github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

const (
	draft13ClientID    = "https://wallet.example/credential-offer/callback"
	draft13RedirectURI = "https://wallet.example/credential-offer/callback"
)

// draft13Fixture is a Draft 13 Credential Issuer and Authorization Server on
// one httptest server, and a wallet configured for it. Each endpoint records
// what it received and answers with a handler the test may replace. The
// default credential is an SD-JWT VC bound to key and signed by issuerKey,
// which the wallet's acceptance policy resolves.
type draft13Fixture struct {
	t         *testing.T
	server    *httptest.Server
	wallet    *Wallet
	obs       *serverObservations
	key       IKeyEntry
	issuerKey *ecdsa.PrivateKey
	// credential is the SD-JWT VC the default handlers issue.
	credential string
	configure  []func(*Config)

	mu                       sync.Mutex
	configuration            map[string]any
	credentialIssuerOverride string
	authorizationServers     bool
	asIssuerOverride         string
	asMetadataExtra          map[string]any
	tokenForms               []url.Values
	tokenHeaders             []http.Header
	credentialRequests       []map[string]any
	deferredRequests         []map[string]any
	notificationRequests     []map[string]any
	tokenResponse            func(form url.Values) (int, any)
	credentialResponse       func(call int, request map[string]any) (int, any)
	deferredResponse         func(call int) (int, any)
	notificationResponse     func() (int, any)
	credentialCalls          int
	deferredCalls            int
}

// newDraft13Fixture builds the fixture; configure changes the wallet's Config
// after the defaults (receiver, store, acceptance policy) are set.
func newDraft13Fixture(t *testing.T, configure ...func(*Config)) *draft13Fixture {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := newInMemoryECKeyEntry()
	require.NoError(t, err)
	f := &draft13Fixture{
		t:         t,
		obs:       newServerObservations(t),
		key:       key,
		issuerKey: issuerKey,
		configure: configure,
		configuration: map[string]any{
			"format": "vc+sd-jwt",
			"vct":    "https://credentials.example/degree",
			"scope":  "degree",
			"cryptographic_binding_methods_supported": []string{"did:key"},
			"proof_types_supported": map[string]any{
				"jwt": map[string]any{"proof_signing_alg_values_supported": []string{"ES256"}},
			},
		},
	}
	f.credential = buildTestSDJWTVCWithIssuerKey(t, issuerKey, key.PublicKey(), map[string]string{"degree": "BSc"})
	f.tokenResponse = func(url.Values) (int, any) {
		return http.StatusOK, map[string]any{"access_token": "access-1", "token_type": "Bearer", "c_nonce": "nonce-1"}
	}
	f.credentialResponse = func(int, map[string]any) (int, any) {
		return http.StatusOK, map[string]any{"credential": f.credential, "notification_id": "notification-1", "c_nonce": "nonce-2"}
	}
	f.deferredResponse = func(int) (int, any) {
		return http.StatusOK, map[string]any{"credential": f.credential, "notification_id": "notification-2"}
	}
	f.notificationResponse = func() (int, any) { return http.StatusNoContent, nil }

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-credential-issuer", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		base := f.server.URL
		issuer := base
		if f.credentialIssuerOverride != "" {
			issuer = f.credentialIssuerOverride
		}
		metadata := map[string]any{
			"credential_issuer":            issuer,
			"credential_endpoint":          base + "/credential",
			"deferred_credential_endpoint": base + "/deferred",
			"notification_endpoint":        base + "/notification",
			"credential_configurations_supported": map[string]any{
				"degree": f.configuration,
			},
		}
		if f.authorizationServers {
			metadata["authorization_servers"] = []string{base}
		}
		draft13WriteJSON(w, http.StatusOK, metadata)
	})
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		base := f.server.URL
		issuer := base
		if f.asIssuerOverride != "" {
			issuer = f.asIssuerOverride
		}
		metadata := map[string]any{
			"issuer":                   issuer,
			"authorization_endpoint":   base + "/authorize",
			"token_endpoint":           base + "/token",
			"response_types_supported": []string{"code"},
		}
		for name, value := range f.asMetadataExtra {
			metadata[name] = value
		}
		draft13WriteJSON(w, http.StatusOK, metadata)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			f.obs.Errorf("token request form: %v", err)
		}
		f.mu.Lock()
		f.tokenForms = append(f.tokenForms, r.PostForm)
		f.tokenHeaders = append(f.tokenHeaders, r.Header.Clone())
		respond := f.tokenResponse
		f.mu.Unlock()
		status, body := respond(r.PostForm)
		draft13WriteJSON(w, status, body)
	})
	mux.HandleFunc("POST /credential", func(w http.ResponseWriter, r *http.Request) {
		request := f.decodeBody(r)
		f.mu.Lock()
		f.credentialRequests = append(f.credentialRequests, request)
		f.credentialCalls++
		call := f.credentialCalls
		respond := f.credentialResponse
		f.mu.Unlock()
		status, body := respond(call, request)
		draft13WriteJSON(w, status, body)
	})
	mux.HandleFunc("POST /deferred", func(w http.ResponseWriter, r *http.Request) {
		request := f.decodeBody(r)
		f.mu.Lock()
		f.deferredRequests = append(f.deferredRequests, request)
		f.deferredCalls++
		call := f.deferredCalls
		respond := f.deferredResponse
		f.mu.Unlock()
		status, body := respond(call)
		draft13WriteJSON(w, status, body)
	})
	mux.HandleFunc("POST /notification", func(w http.ResponseWriter, r *http.Request) {
		request := f.decodeBody(r)
		f.mu.Lock()
		f.notificationRequests = append(f.notificationRequests, request)
		respond := f.notificationResponse
		f.mu.Unlock()
		status, body := respond()
		draft13WriteJSON(w, status, body)
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	f.wallet = f.newWallet(t)
	return f
}

// newWallet builds another wallet for the fixture server with the fixture's
// Config and then extra.
func (f *draft13Fixture) newWallet(t *testing.T, extra ...func(*Config)) *Wallet {
	t.Helper()
	config := Config{
		Receiver:             f.receiver(t, f.server.Client()),
		CredStore:            newProfileCredStore(t),
		CredentialAcceptance: acceptIssuerKeyPolicy(f.issuerKey),
	}
	for _, configure := range append(append([]func(*Config){}, f.configure...), extra...) {
		configure(&config)
	}
	w, err := NewWalletWithConfig(config)
	require.NoError(t, err)
	return w
}

// receiver is a receiving dispatcher whose OpenID4VCI plugin uses client.
func (f *draft13Fixture) receiver(t *testing.T, client *http.Client) *receiver.ReceivingDispatcher {
	t.Helper()
	plugin := receiverTypes.Receiver(&receiverOid4vci.Oid4vciReceiver{HTTPClient: client, AllowHTTP: true})
	receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, plugin))
	require.NoError(t, err)
	return receiving
}

// draft13RegisteredClient names the client_id and redirect_uri the
// Authorization Code Flow needs.
func draft13RegisteredClient(config *Config) {
	config.ClientAuth.ClientID = draft13ClientID
	config.Issuance.RedirectURI = draft13RedirectURI
}

func draft13WriteJSON(w http.ResponseWriter, status int, body any) {
	if body == nil {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// decodeBody decodes a JSON request body and records the Authorization and
// DPoP headers as "_authorization" and "_dpop".
func (f *draft13Fixture) decodeBody(r *http.Request) map[string]any {
	decoded := map[string]any{}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		f.obs.Errorf("read request body: %v", err)
	} else if err := json.Unmarshal(raw, &decoded); err != nil {
		f.obs.Errorf("decode request body %q: %v", raw, err)
	}
	decoded["_authorization"] = r.Header.Get("Authorization")
	decoded["_dpop"] = r.Header.Get("DPoP")
	return decoded
}

func (f *draft13Fixture) tokens() []url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]url.Values(nil), f.tokenForms...)
}

func (f *draft13Fixture) tokenRequestHeaders() []http.Header {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]http.Header(nil), f.tokenHeaders...)
}

func (f *draft13Fixture) credentials() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.credentialRequests...)
}

func (f *draft13Fixture) deferreds() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.deferredRequests...)
}

func (f *draft13Fixture) notifications() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.notificationRequests...)
}

func (f *draft13Fixture) set(change func(*draft13Fixture)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

func (f *draft13Fixture) offer(grants map[string]*CredentialOfferGrant) *CredentialOffer {
	issuer, err := url.Parse(f.server.URL)
	require.NoError(f.t, err)
	return &CredentialOffer{CredentialIssuer: issuer, CredentialConfigurationIDs: []string{"degree"}, Grants: grants}
}

func (f *draft13Fixture) preAuthorizedOffer() *CredentialOffer {
	return f.offer(map[string]*CredentialOfferGrant{
		string(receiverTypes.PreAuthorizedCode): {PreAuthorizedCode: "pre-code-1", TxCode: &TxCode{Length: 4}},
	})
}

func (f *draft13Fixture) authorizationCodeOffer() *CredentialOffer {
	return f.offer(map[string]*CredentialOfferGrant{
		"authorization_code": {IssuerState: "issuer-state-1"},
	})
}

func (f *draft13Fixture) preAuthorizedRequest() PreAuthorizedIssuanceRequest {
	return PreAuthorizedIssuanceRequest{CredentialOffer: f.preAuthorizedOffer(), TxCode: "4321"}
}

func (f *draft13Fixture) holder() CredentialRequest {
	return CredentialRequest{HolderKeys: []IKeyEntry{f.key}}
}

// preAuthorize runs the Pre-Authorized Code token request in w.
func (f *draft13Fixture) preAuthorize(t *testing.T, w *Wallet) *IssuanceGrant {
	t.Helper()
	grant, err := w.Draft13().AuthorizePreAuthorizedIssuance(context.Background(), f.preAuthorizedRequest())
	require.NoError(t, err)
	return grant
}

// receivePreAuthorized runs the whole Pre-Authorized Code Flow in the
// fixture wallet with the holder key.
func (f *draft13Fixture) receivePreAuthorized(t *testing.T) (*IssuanceResult, error) {
	t.Helper()
	grant := f.preAuthorize(t, f.wallet)
	return f.wallet.Draft13().RequestCredential(context.Background(), grant, f.holder())
}

// draft13StoredCount is the number of credentials w holds.
func draft13StoredCount(t *testing.T, w *Wallet) int {
	t.Helper()
	_, total, err := w.GetCredentialEntries(GetCredentialEntriesRequest{})
	require.NoError(t, err)
	return total
}

// draft13RequireCoded asserts errors.Is(err, target) and that err carries a
// code other than unclassified.
func draft13RequireCoded(t *testing.T, err error, target error) {
	t.Helper()
	require.ErrorIs(t, err, target)
	code, ok := ErrorCode(err)
	require.True(t, ok, "error has a code: %v", err)
	require.NotEqual(t, "unclassified", code, "error is classified: %v", err)
}

// draft13ProofParts decodes the compact JWS, header and claims of the one key
// proof a recorded Credential Request carried.
func draft13ProofParts(t *testing.T, request map[string]any) (string, map[string]any, map[string]any) {
	t.Helper()
	proof, ok := request["proof"].(map[string]any)
	require.True(t, ok, "credential request carries a proof object")
	require.Equal(t, "jwt", proof["proof_type"])
	compact, ok := proof["jwt"].(string)
	require.True(t, ok)
	return compact, draft13DecodeProof(t, compact, 0), draft13DecodeProof(t, compact, 1)
}

func draft13DecodeProof(t *testing.T, compact string, segment int) map[string]any {
	t.Helper()
	segments := strings.Split(compact, ".")
	require.Len(t, segments, 3)
	raw, err := base64.RawURLEncoding.DecodeString(segments[segment])
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))
	return decoded
}

// draft13JWTVC signs a W3C VC JWT with issuerKey, bound to holder through
// cnf.jwk.
func draft13JWTVC(t *testing.T, issuerKey *ecdsa.PrivateKey, holder jose.JSONWebKey) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: issuerKey}, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)
	now := time.Now()
	signed, err := jwt.Signed(signer).Claims(map[string]any{
		"iss": "https://issuer.example.test",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"cnf": map[string]any{"jwk": holder.Public()},
		"vc": map[string]any{
			"@context":          []string{"https://www.w3.org/2018/credentials/v1"},
			"id":                "urn:uuid:3f1c0b1e-6a0e-4c43-9d0b-2b8f3f7b1a01",
			"type":              []string{"VerifiableCredential", "UniversityDegree"},
			"issuer":            "https://issuer.example.test",
			"credentialSubject": map[string]any{"degree": "BSc"},
		},
	}).Serialize()
	require.NoError(t, err)
	return signed
}

func TestDraft13PreAuthorizedCodeFlow(t *testing.T) {
	fixture := newDraft13Fixture(t)
	ctx := context.Background()

	grant := fixture.preAuthorize(t, fixture.wallet)
	require.Equal(t, IssuanceVersionDraft13, grant.Version)
	require.Equal(t, "nonce-1", grant.CNonce, "Draft 13 takes the c_nonce from the Token Response")
	result, err := fixture.wallet.Draft13().RequestCredential(ctx, grant, fixture.holder())
	require.NoError(t, err)
	require.Nil(t, result.Deferred)
	require.Len(t, result.Credentials, 1)
	require.Equal(t, fixture.credential, string(result.Credentials[0].Entry.Raw))
	require.Equal(t, string(credential.SDJwtVC), result.Credentials[0].Entry.MimeType)
	require.True(t, result.Credentials[0].Verification.HolderBound)
	require.NotNil(t, result.CredentialResponse.CNonce)
	require.Equal(t, "nonce-2", *result.CredentialResponse.CNonce)
	require.NotNil(t, result.Notification)
	require.Equal(t, IssuanceVersionDraft13, result.Notification.Version)
	require.Equal(t, "notification-1", result.Notification.NotificationID)
	require.Equal(t, "access-1", result.Notification.AccessToken.Token)
	require.Equal(t, 1, draft13StoredCount(t, fixture.wallet), "the view verifies and stores")
	require.Empty(t, fixture.notifications(), "the library never notifies on its own")

	// Section 6.1: the anonymous grant sends no client_id.
	tokens := fixture.tokens()
	require.Len(t, tokens, 1)
	form := tokens[0]
	require.Equal(t, string(receiverTypes.PreAuthorizedCode), form.Get("grant_type"))
	require.Equal(t, "pre-code-1", form.Get("pre-authorized_code"))
	require.Equal(t, "4321", form.Get("tx_code"))
	require.False(t, form.Has("client_id"))

	// Section 7.2: the SD-JWT VC is named by format and vct, with one proof.
	requests := fixture.credentials()
	require.Len(t, requests, 1)
	request := requests[0]
	require.Equal(t, "Bearer access-1", request["_authorization"])
	require.Equal(t, "vc+sd-jwt", request["format"])
	require.Equal(t, "https://credentials.example/degree", request["vct"])
	require.NotContains(t, request, "credential_identifier")
	require.NotContains(t, request, "proofs")

	_, header, claims := draft13ProofParts(t, request)
	require.Equal(t, "openid4vci-proof+jwt", header["typ"])
	require.Equal(t, "ES256", header["alg"])
	require.NotContains(t, header, "jwk")
	kid, _ := header["kid"].(string)
	did, identifier, found := strings.Cut(kid, "#")
	require.True(t, found, "a kid-bound proof names a DID URL, not a bare DID")
	require.Equal(t, "did:key:"+identifier, did)
	require.Equal(t, fixture.server.URL, claims["aud"])
	require.Equal(t, "nonce-1", claims["nonce"])
	require.NotContains(t, claims, "iss", "the anonymous flow has no client_id to put in iss")
}

// Section 6.1 and 7.2.1.1: a configured client_id is sent in the
// pre-authorized token request and named as iss in the key proof.
func TestDraft13PreAuthorizedCodeFlowNamesAConfiguredClient(t *testing.T) {
	fixture := newDraft13Fixture(t, draft13RegisteredClient)
	_, err := fixture.receivePreAuthorized(t)
	require.NoError(t, err)
	require.Equal(t, draft13ClientID, fixture.tokens()[0].Get("client_id"))
	_, _, claims := draft13ProofParts(t, fixture.credentials()[0])
	require.Equal(t, draft13ClientID, claims["iss"])
}

func TestDraft13NamesJWTVCByTypeOnly(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.set(func(f *draft13Fixture) {
		f.configuration = map[string]any{
			"format": "jwt_vc_json",
			"credential_definition": map[string]any{
				"type":              []string{"VerifiableCredential", "UniversityDegree"},
				"credentialSubject": map[string]any{"degree": map[string]any{"mandatory": true}},
			},
			"cryptographic_binding_methods_supported": []string{"did:key"},
		}
	})
	jwtVC := draft13JWTVC(t, fixture.issuerKey, fixture.key.PublicKey())
	fixture.set(func(f *draft13Fixture) {
		f.credentialResponse = func(int, map[string]any) (int, any) {
			return http.StatusOK, map[string]any{"credential": jwtVC}
		}
	})

	result, err := fixture.receivePreAuthorized(t)
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	require.Equal(t, string(credential.JwtVc), result.Credentials[0].Entry.MimeType)
	request := fixture.credentials()[0]
	require.Equal(t, "jwt_vc_json", request["format"])
	require.Equal(t, map[string]any{"type": []any{"VerifiableCredential", "UniversityDegree"}}, request["credential_definition"])
	require.NotContains(t, request, "vct")
}

func TestDraft13RetriesInvalidProofOnceWithTheFreshNonce(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.set(func(f *draft13Fixture) {
		f.credentialResponse = func(call int, _ map[string]any) (int, any) {
			if call == 1 {
				return http.StatusBadRequest, map[string]any{"error": "invalid_proof", "c_nonce": "fresh-nonce"}
			}
			return http.StatusOK, map[string]any{"credential": f.credential}
		}
	})

	result, err := fixture.receivePreAuthorized(t)
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	requests := fixture.credentials()
	require.Len(t, requests, 2)
	_, _, first := draft13ProofParts(t, requests[0])
	require.Equal(t, "nonce-1", first["nonce"])
	_, _, retried := draft13ProofParts(t, requests[1])
	require.Equal(t, "fresh-nonce", retried["nonce"])
}

func TestDraft13ReportsASecondInvalidProof(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.set(func(f *draft13Fixture) {
		f.credentialResponse = func(call int, _ map[string]any) (int, any) {
			return http.StatusBadRequest, map[string]any{"error": "invalid_proof", "c_nonce": "fresh-nonce-" + string(rune('0'+call))}
		}
	})

	_, err := fixture.receivePreAuthorized(t)
	draft13RequireCoded(t, err, receiverTypes.ErrDraft13InvalidProof)
	require.Len(t, fixture.credentials(), 2, "invalid_proof is retried exactly once")
	require.Zero(t, draft13StoredCount(t, fixture.wallet))
}

func TestDraft13KeyProofHookRewritesTheProofBeforeAndAfterSigning(t *testing.T) {
	var seenNonce any
	fixture := newDraft13Fixture(t, func(c *Config) {
		c.TestHooks = &TestHooks{KeyProof: ProofTransform{
			Content: func(content ProofJWTContent) (ProofJWTContent, error) {
				seenNonce = content.Claims["nonce"]
				content.Header["kid"] = "did:key:elsewhere#elsewhere"
				content.Claims["nonce"] = "replayed"
				return content, nil
			},
			Serialized: func(compact string) (string, error) {
				return compact + "-tampered", nil
			},
		}}
	})
	fixture.set(func(f *draft13Fixture) {
		f.credentialResponse = func(int, map[string]any) (int, any) {
			return http.StatusOK, map[string]any{"credential": f.credential}
		}
	})

	_, err := fixture.receivePreAuthorized(t)
	require.NoError(t, err)
	require.Equal(t, "nonce-1", seenNonce, "the hook sees the proof the library built")

	sent := fixture.credentials()[0]["proof"].(map[string]any)["jwt"].(string)
	require.True(t, strings.HasSuffix(sent, "-tampered"))
	compact := strings.TrimSuffix(sent, "-tampered")
	require.Equal(t, "did:key:elsewhere#elsewhere", draft13DecodeProof(t, compact, 0)["kid"])
	require.Equal(t, "replayed", draft13DecodeProof(t, compact, 1)["nonce"])

	// The content rewrite happened before signing: the signature verifies
	// over what the proof now says.
	signed, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	publicKey := fixture.key.PublicKey()
	_, err = signed.Verify(publicKey.Public())
	require.NoError(t, err)
}

func TestDraft13ZeroProofTransformIsTheUntouchedProof(t *testing.T) {
	fixture := newDraft13Fixture(t)
	nonce := "nonce-1"
	build := func(transform ProofTransform) (map[string]any, map[string]any) {
		compact, err := fixture.wallet.generateJWTProofWithTransform(context.Background(), fixture.key, "did:key:zExample#zExample", &nonce, "https://issuer.example", nil, credentialRequestProofBindingMethodKID, transform)
		require.NoError(t, err)
		claims := draft13DecodeProof(t, compact, 1)
		delete(claims, "iat")
		return draft13DecodeProof(t, compact, 0), claims
	}
	identity := ProofTransform{
		Content:    func(content ProofJWTContent) (ProofJWTContent, error) { return content, nil },
		Serialized: func(compact string) (string, error) { return compact, nil },
	}
	zeroHeader, zeroClaims := build(ProofTransform{})
	identityHeader, identityClaims := build(identity)
	require.Equal(t, zeroHeader, identityHeader)
	require.Equal(t, zeroClaims, identityClaims)
	require.Equal(t, map[string]any{"typ": "openid4vci-proof+jwt", "alg": "ES256", "kid": "did:key:zExample#zExample"}, zeroHeader)
}

func TestDraft13KeyProofHookFailureSendsNothing(t *testing.T) {
	fixture := newDraft13Fixture(t, func(c *Config) {
		c.TestHooks = &TestHooks{KeyProof: ProofTransform{Content: func(ProofJWTContent) (ProofJWTContent, error) {
			return ProofJWTContent{}, io.ErrUnexpectedEOF
		}}}
	})

	_, err := fixture.receivePreAuthorized(t)
	draft13RequireCoded(t, err, ErrDraft13ProofTransformFailed)
	require.Empty(t, fixture.credentials())
}

// TestHooks are refused when a HAIP wallet is constructed.
func TestDraft13KeyProofHookIsRefusedUnderHAIP(t *testing.T) {
	_, err := NewWalletWithConfig(Config{
		Profile:   profile.HAIP,
		CredStore: newProfileCredStore(t),
		TestHooks: &TestHooks{KeyProof: ProofTransform{}},
	})
	draft13RequireCoded(t, err, ErrProfileForbidsDraft)
}

func TestDraft13RequiresOneHolderKey(t *testing.T) {
	fixture := newDraft13Fixture(t)
	ctx := context.Background()
	grant := fixture.preAuthorize(t, fixture.wallet)

	_, err := fixture.wallet.Draft13().RequestCredential(ctx, grant, CredentialRequest{})
	draft13RequireCoded(t, err, ErrDraft13HolderKeyMissing)

	other, err := newInMemoryECKeyEntry()
	require.NoError(t, err)
	_, err = fixture.wallet.Draft13().RequestCredential(ctx, grant, CredentialRequest{HolderKeys: []IKeyEntry{fixture.key, other}})
	draft13RequireCoded(t, err, ErrInvalidArgument)

	_, err = fixture.wallet.Draft13().RequestCredential(ctx, grant, CredentialRequest{HolderKeys: []IKeyEntry{fixture.key}, IncludeKeyAttestation: true})
	draft13RequireCoded(t, err, ErrInvalidArgument)
	require.Empty(t, fixture.credentials())
}

func TestDraft13RequiresAnOffer(t *testing.T) {
	fixture := newDraft13Fixture(t, draft13RegisteredClient)
	ctx := context.Background()

	_, err := fixture.wallet.Draft13().BeginIssuance(ctx, IssuanceRequest{CredentialIssuer: fixture.server.URL, CredentialConfigurationID: "degree"})
	draft13RequireCoded(t, err, ErrInvalidArgument)
	_, err = fixture.wallet.Draft13().AuthorizePreAuthorizedIssuance(ctx, PreAuthorizedIssuanceRequest{})
	draft13RequireCoded(t, err, ErrDraft13OfferMissing)
	require.Empty(t, fixture.tokens())
}

// Section 11.2.1: the metadata's credential_issuer must be the identifier it
// was fetched for.
func TestDraft13RefusesMetadataOfAnotherIssuer(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.set(func(f *draft13Fixture) { f.credentialIssuerOverride = "https://other-issuer.example" })

	_, err := fixture.wallet.Draft13().AuthorizePreAuthorizedIssuance(context.Background(), fixture.preAuthorizedRequest())
	draft13RequireCoded(t, err, ErrIssuerIdentifierMismatch)
	require.Empty(t, fixture.tokens())
}

// RFC 8414 Section 3.3: the authorization server metadata's issuer must be
// identical to the identifier it was fetched for.
func TestDraft13RefusesForeignAuthorizationServerIssuer(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.set(func(f *draft13Fixture) { f.asIssuerOverride = "https://other-as.example" })

	_, err := fixture.wallet.Draft13().AuthorizePreAuthorizedIssuance(context.Background(), fixture.preAuthorizedRequest())
	draft13RequireCoded(t, err, receiverOid4vci.ErrAuthorizationServerIssuerMismatch)
	require.Empty(t, fixture.tokens())
}

// An object credential reaches the caller as its JSON text in
// CredentialResponse; it is not the configured SD-JWT VC, so verification
// refuses it and the result carries the notification for credential_failure.
func TestDraft13ReportsAnObjectCredentialAsJSONAndRefusesIt(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.set(func(f *draft13Fixture) {
		f.credentialResponse = func(int, map[string]any) (int, any) {
			return http.StatusOK, map[string]any{"credential": map[string]any{"type": []string{"VerifiableCredential"}}, "notification_id": "notification-1"}
		}
	})

	result, err := fixture.receivePreAuthorized(t)
	require.Error(t, err)
	code, ok := ErrorCode(err)
	require.True(t, ok)
	require.NotEqual(t, "unclassified", code)
	require.NotNil(t, result)
	require.Len(t, result.CredentialResponse.Credentials, 1)
	entry := result.CredentialResponse.Credentials[0].(map[string]any)
	require.JSONEq(t, `{"type":["VerifiableCredential"]}`, entry["credential"].(string))
	require.Empty(t, result.Credentials)
	require.NotNil(t, result.Notification)
	require.Equal(t, "notification-1", result.Notification.NotificationID)
	require.Zero(t, draft13StoredCount(t, fixture.wallet))

	require.NoError(t, fixture.wallet.Draft13().NotifyIssuer(context.Background(), result.Notification, NotificationCredentialFailure, "unreadable"))
	require.Equal(t, "credential_failure", fixture.notifications()[0]["event"])
}

// A pending transaction is a result with Deferred and the issuer's interval,
// not an error; the library sends no deferred request on its own. The
// deferred state resumes from JSON in another wallet.
func TestDraft13DeferredTransaction(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.set(func(f *draft13Fixture) {
		f.credentialResponse = func(int, map[string]any) (int, any) {
			return http.StatusAccepted, map[string]any{"transaction_id": "transaction-1", "interval": 7}
		}
	})
	ctx := context.Background()

	result, err := fixture.receivePreAuthorized(t)
	require.NoError(t, err)
	require.Empty(t, result.Credentials)
	require.NotNil(t, result.Deferred)
	require.Equal(t, IssuanceVersionDraft13, result.Deferred.Version)
	require.Equal(t, "transaction-1", result.Deferred.TransactionID)
	require.Equal(t, 7*time.Second, result.Deferred.Interval)
	require.Empty(t, fixture.deferreds(), "the library does not poll")

	var stored DeferredIssuance
	requireJSONRoundTrip(t, result.Deferred, &stored)
	resumed := fixture.newWallet(t)
	issued, err := resumed.Draft13().RequestDeferredCredential(ctx, &stored)
	require.NoError(t, err)
	require.Nil(t, issued.Deferred)
	require.Len(t, issued.Credentials, 1)
	require.Equal(t, fixture.credential, string(issued.Credentials[0].Entry.Raw))
	require.NotNil(t, issued.Notification)
	require.Equal(t, "notification-2", issued.Notification.NotificationID)
	require.Equal(t, 1, draft13StoredCount(t, resumed))
	deferred := fixture.deferreds()
	require.Len(t, deferred, 1)
	require.Equal(t, "transaction-1", deferred[0]["transaction_id"])
	require.Equal(t, "Bearer access-1", deferred[0]["_authorization"])
}

// Section 9.2: issuance_pending is a result with Deferred and the interval
// the issuer named; the next request may succeed.
func TestDraft13DeferredIssuancePendingIsNotAnError(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.set(func(f *draft13Fixture) {
		f.credentialResponse = func(int, map[string]any) (int, any) {
			return http.StatusAccepted, map[string]any{"transaction_id": "transaction-1"}
		}
		f.deferredResponse = func(call int) (int, any) {
			if call == 1 {
				return http.StatusBadRequest, map[string]any{"error": "issuance_pending", "interval": 30}
			}
			return http.StatusOK, map[string]any{"credential": f.credential, "notification_id": "notification-2"}
		}
	})
	ctx := context.Background()

	result, err := fixture.receivePreAuthorized(t)
	require.NoError(t, err)
	require.NotNil(t, result.Deferred)
	require.Zero(t, result.Deferred.Interval, "no interval was named")

	pending, err := fixture.wallet.Draft13().RequestDeferredCredential(ctx, result.Deferred)
	require.NoError(t, err)
	require.Empty(t, pending.Credentials)
	require.NotNil(t, pending.Deferred)
	require.Equal(t, "transaction-1", pending.Deferred.TransactionID)
	require.Equal(t, 30*time.Second, pending.Deferred.Interval)
	require.Len(t, fixture.deferreds(), 1, "one request per call")

	issued, err := fixture.wallet.Draft13().RequestDeferredCredential(ctx, pending.Deferred)
	require.NoError(t, err)
	require.Len(t, issued.Credentials, 1)
	require.Equal(t, "notification-2", issued.Notification.NotificationID)
	require.Len(t, fixture.deferreds(), 2)
}

func TestDraft13DeferredReportsATerminalRefusal(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.set(func(f *draft13Fixture) {
		f.credentialResponse = func(int, map[string]any) (int, any) {
			return http.StatusAccepted, map[string]any{"transaction_id": "transaction-1"}
		}
		f.deferredResponse = func(int) (int, any) {
			return http.StatusBadRequest, map[string]any{"error": "invalid_transaction_id"}
		}
	})
	result, err := fixture.receivePreAuthorized(t)
	require.NoError(t, err)

	_, err = fixture.wallet.Draft13().RequestDeferredCredential(context.Background(), result.Deferred)
	require.Error(t, err)
	require.NotErrorIs(t, err, receiverTypes.ErrDraft13IssuancePending)
	var endpointError *receiverTypes.Draft13CredentialEndpointError
	require.ErrorAs(t, err, &endpointError)
	require.Equal(t, "invalid_transaction_id", endpointError.Code)
	require.Equal(t, []string{"draft13_credential_endpoint_failed"}, ErrorCodes(err)[:1])
	require.Len(t, fixture.deferreds(), 1)
}

// A DPoP-bound token needs Config.DPoP.Key, and the key the token is bound
// to; both are checked before anything is sent.
func TestDraft13DeferredRequiresTheDPoPKeyOfTheToken(t *testing.T) {
	fixture := newDraft13Fixture(t)
	deferred := &DeferredIssuance{
		Version:                   IssuanceVersionDraft13,
		CredentialIssuer:          fixture.server.URL,
		CredentialConfigurationID: "degree",
		TransactionID:             "transaction-1",
		AccessToken:               &receiverTypes.CredentialIssuanceAccessToken{Token: "access-1", TokenType: "DPoP"},
	}

	_, err := fixture.wallet.Draft13().RequestDeferredCredential(context.Background(), deferred)
	draft13RequireCoded(t, err, ErrDPoPKeyMismatch)

	withKey := fixture.newWallet(t, func(c *Config) { c.DPoP.Enabled = true })
	deferred.DPoPKeyThumbprint = "thumbprint-of-another-key"
	_, err = withKey.Draft13().RequestDeferredCredential(context.Background(), deferred)
	draft13RequireCoded(t, err, ErrDPoPKeyMismatch)
	require.Empty(t, fixture.deferreds())
}

// With a DPoP key and an authorization server that advertises DPoP, the
// token is DPoP-bound; a wallet with another DPoP key cannot use the grant.
func TestDraft13DPoPBoundGrant(t *testing.T) {
	fixture := newDraft13Fixture(t, func(c *Config) { c.DPoP.Enabled = true })
	fixture.set(func(f *draft13Fixture) {
		f.asMetadataExtra = map[string]any{"dpop_signing_alg_values_supported": []string{"ES256"}}
		f.tokenResponse = func(url.Values) (int, any) {
			return http.StatusOK, map[string]any{"access_token": "access-1", "token_type": "DPoP", "c_nonce": "nonce-1"}
		}
	})
	ctx := context.Background()

	grant := fixture.preAuthorize(t, fixture.wallet)
	require.NotEmpty(t, fixture.tokenRequestHeaders()[0].Get("DPoP"))
	require.NotEmpty(t, grant.DPoPKeyThumbprint)

	var stored IssuanceGrant
	requireJSONRoundTrip(t, grant, &stored)
	other := fixture.newWallet(t)
	_, err := other.Draft13().RequestCredential(ctx, &stored, fixture.holder())
	draft13RequireCoded(t, err, ErrDPoPKeyMismatch)
	require.Empty(t, fixture.credentials())

	result, err := fixture.wallet.Draft13().RequestCredential(ctx, grant, fixture.holder())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	request := fixture.credentials()[0]
	require.Equal(t, "DPoP access-1", request["_authorization"])
	require.NotEmpty(t, request["_dpop"])
}

func TestDraft13NotifyIssuer(t *testing.T) {
	fixture := newDraft13Fixture(t)
	ctx := context.Background()
	notification := &IssuanceNotification{
		Version:          IssuanceVersionDraft13,
		CredentialIssuer: fixture.server.URL,
		NotificationID:   "notification-1",
		AccessToken:      &receiverTypes.CredentialIssuanceAccessToken{Token: "access-1", TokenType: "Bearer"},
	}
	draft13 := fixture.wallet.Draft13()

	require.NoError(t, draft13.NotifyIssuer(ctx, notification, NotificationCredentialAccepted, "stored"))
	require.Equal(t, []map[string]any{{
		"_authorization":    "Bearer access-1",
		"_dpop":             "",
		"notification_id":   "notification-1",
		"event":             "credential_accepted",
		"event_description": "stored",
	}}, fixture.notifications())

	fixture.set(func(f *draft13Fixture) {
		f.notificationResponse = func() (int, any) {
			return http.StatusBadRequest, map[string]any{"error": "invalid_notification_id"}
		}
	})
	err := draft13.NotifyIssuer(ctx, notification, NotificationCredentialAccepted, "")
	var endpointError *receiverTypes.Draft13CredentialEndpointError
	require.ErrorAs(t, err, &endpointError)
	require.Equal(t, "invalid_notification_id", endpointError.Code)

	draft13RequireCoded(t, draft13.NotifyIssuer(ctx, notification, NotificationEvent("credential_lost"), ""), ErrNotificationEventInvalid)
	draft13RequireCoded(t, draft13.NotifyIssuer(ctx, notification, NotificationCredentialAccepted, `quote " refused`), ErrNotificationEventDescriptionInvalid)
	require.Len(t, fixture.notifications(), 2)
}

// beginAuthorization starts an Authorization Code Flow from the fixture's offer.
func (f *draft13Fixture) beginAuthorization(t *testing.T, w *Wallet, req IssuanceRequest) *IssuanceAuthorization {
	t.Helper()
	if req.CredentialOffer == nil {
		req.CredentialOffer = f.authorizationCodeOffer()
	}
	authorization, err := w.Draft13().BeginIssuance(context.Background(), req)
	require.NoError(t, err)
	return authorization
}

// draft13Redirect is the redirect a browser delivers for authorization.
func draft13Redirect(authorization *IssuanceAuthorization, iss string) string {
	redirect := draft13RedirectURI + "?code=code-1&state=" + url.QueryEscape(authorization.State)
	if iss != "" {
		redirect += "&iss=" + url.QueryEscape(iss)
	}
	return redirect
}

// The authorization and grant states resume from JSON in another wallet that
// shares the Config.
func TestDraft13AuthorizationCodeFlowSurvivesJSONRoundTrip(t *testing.T) {
	fixture := newDraft13Fixture(t, draft13RegisteredClient)
	fixture.set(func(f *draft13Fixture) { f.authorizationServers = true })
	ctx := context.Background()

	authorization := fixture.beginAuthorization(t, fixture.wallet, IssuanceRequest{})
	require.Equal(t, IssuanceVersionDraft13, authorization.Version)
	require.Empty(t, fixture.tokens(), "beginning the flow sends nothing to the token endpoint")

	authorizationURL, err := url.Parse(authorization.AuthorizationURL)
	require.NoError(t, err)
	require.Equal(t, fixture.server.URL+"/authorize", authorizationURL.Scheme+"://"+authorizationURL.Host+authorizationURL.Path)
	query := authorizationURL.Query()
	require.Equal(t, "code", query.Get("response_type"))
	require.Equal(t, draft13ClientID, query.Get("client_id"))
	require.Equal(t, draft13RedirectURI, query.Get("redirect_uri"))
	require.Equal(t, authorization.State, query.Get("state"))
	require.Equal(t, "S256", query.Get("code_challenge_method"))
	require.NotEmpty(t, query.Get("code_challenge"))
	require.Equal(t, "degree", query.Get("scope"))
	require.Equal(t, "issuer-state-1", query.Get("issuer_state"))
	require.Equal(t, fixture.server.URL, query.Get("resource"))

	var restored IssuanceAuthorization
	requireJSONRoundTrip(t, authorization, &restored)
	resumed := fixture.newWallet(t)
	grant, err := resumed.Draft13().AuthorizeIssuance(ctx, &restored, draft13Redirect(&restored, fixture.server.URL))
	require.NoError(t, err)
	require.Equal(t, IssuanceVersionDraft13, grant.Version)

	var storedGrant IssuanceGrant
	requireJSONRoundTrip(t, grant, &storedGrant)
	result, err := fixture.newWallet(t).Draft13().RequestCredential(ctx, &storedGrant, fixture.holder())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)

	form := fixture.tokens()[0]
	require.Equal(t, "authorization_code", form.Get("grant_type"))
	require.Equal(t, "code-1", form.Get("code"))
	require.Equal(t, draft13RedirectURI, form.Get("redirect_uri"))
	require.Equal(t, draft13ClientID, form.Get("client_id"))
	require.Equal(t, restored.CodeVerifier, form.Get("code_verifier"))

	_, _, claims := draft13ProofParts(t, fixture.credentials()[0])
	require.Equal(t, draft13ClientID, claims["iss"], "a registered client names itself in the proof")
}

func TestDraft13BeginIssuanceRequiresARegisteredClient(t *testing.T) {
	fixture := newDraft13Fixture(t)
	_, err := fixture.wallet.Draft13().BeginIssuance(context.Background(), IssuanceRequest{CredentialOffer: fixture.authorizationCodeOffer()})
	draft13RequireCoded(t, err, ErrInvalidArgument)
}

func TestDraft13BeginIssuanceRequiresTheGrant(t *testing.T) {
	fixture := newDraft13Fixture(t, draft13RegisteredClient)
	_, err := fixture.wallet.Draft13().BeginIssuance(context.Background(), IssuanceRequest{CredentialOffer: fixture.preAuthorizedOffer()})
	draft13RequireCoded(t, err, ErrDraft13AuthorizationCodeGrantMissing)
}

func TestDraft13AuthorizeIssuanceRefusesAForeignState(t *testing.T) {
	fixture := newDraft13Fixture(t, draft13RegisteredClient)
	authorization := fixture.beginAuthorization(t, fixture.wallet, IssuanceRequest{})

	_, err := fixture.wallet.Draft13().AuthorizeIssuance(context.Background(), authorization, draft13RedirectURI+"?code=code-1&state=someone-else")
	draft13RequireCoded(t, err, ErrAuthorizationStateMismatch)
	require.Empty(t, fixture.tokens())
}

// A state that names an issuer or authorization server the issuer does not
// delegate to, that is incomplete, or that was made with another client_id
// or redirect_uri than Config names is refused before the code is redeemed.
func TestDraft13AuthorizeIssuanceRefusesAStateThatDoesNotFit(t *testing.T) {
	for name, tc := range map[string]struct {
		tamper    func(t *testing.T, a *IssuanceAuthorization)
		configure func(*Config)
	}{
		"issuer that does not delegate to the authorization server": {
			tamper: func(t *testing.T, a *IssuanceAuthorization) {
				a.CredentialIssuer = newDraft13Fixture(t).server.URL
			},
		},
		"undelegated authorization server": {
			tamper: func(_ *testing.T, a *IssuanceAuthorization) { a.AuthorizationServer = "https://attacker.example" },
		},
		"missing code_verifier": {
			tamper: func(_ *testing.T, a *IssuanceAuthorization) { a.CodeVerifier = "" },
		},
		"another client_id in Config": {
			configure: func(c *Config) { c.ClientAuth.ClientID = "https://other-wallet.example" },
		},
		"another redirect_uri in Config": {
			configure: func(c *Config) { c.Issuance.RedirectURI = "https://wallet.example/other" },
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newDraft13Fixture(t, draft13RegisteredClient)
			authorization := fixture.beginAuthorization(t, fixture.wallet, IssuanceRequest{})
			var restored IssuanceAuthorization
			requireJSONRoundTrip(t, authorization, &restored)
			if tc.tamper != nil {
				tc.tamper(t, &restored)
			}
			resumed := fixture.wallet
			if tc.configure != nil {
				resumed = fixture.newWallet(t, tc.configure)
			}

			_, err := resumed.Draft13().AuthorizeIssuance(context.Background(), &restored, draft13Redirect(&restored, ""))
			draft13RequireCoded(t, err, ErrIssuanceStateMismatch)
			require.Empty(t, fixture.tokens())
		})
	}
}

func TestDraft13AuthorizeIssuanceRequiresAuthorizationDetailsItAskedFor(t *testing.T) {
	fixture := newDraft13Fixture(t, draft13RegisteredClient)
	authorization := fixture.beginAuthorization(t, fixture.wallet, IssuanceRequest{AuthorizationRequestType: AuthorizationRequestDetails})
	require.True(t, authorization.AuthorizationDetailsRequested)
	authorizationURL, err := url.Parse(authorization.AuthorizationURL)
	require.NoError(t, err)
	require.NotEmpty(t, authorizationURL.Query().Get("authorization_details"))
	require.Empty(t, authorizationURL.Query().Get("scope"))

	_, err = fixture.wallet.Draft13().AuthorizeIssuance(context.Background(), authorization, draft13Redirect(authorization, ""))
	draft13RequireCoded(t, err, ErrAuthorizationDetailsMissing)
	require.Len(t, fixture.tokens(), 1)
	require.Empty(t, fixture.credentials())
}

// Every Draft 13 stage requires Config.CredentialAcceptance before it sends
// anything.
func TestDraft13RequiresAnAcceptancePolicy(t *testing.T) {
	fixture := newDraft13Fixture(t, draft13RegisteredClient)
	ctx := context.Background()
	grant := fixture.preAuthorize(t, fixture.wallet)
	tokens := len(fixture.tokens())
	unverified := fixture.newWallet(t, func(c *Config) { c.CredentialAcceptance = nil })

	_, err := unverified.Draft13().AuthorizePreAuthorizedIssuance(ctx, fixture.preAuthorizedRequest())
	draft13RequireCoded(t, err, ErrCredentialAcceptancePolicyRequired)
	_, err = unverified.Draft13().BeginIssuance(ctx, IssuanceRequest{CredentialOffer: fixture.authorizationCodeOffer()})
	draft13RequireCoded(t, err, ErrCredentialAcceptancePolicyRequired)
	_, err = unverified.Draft13().RequestCredential(ctx, grant, fixture.holder())
	draft13RequireCoded(t, err, ErrCredentialAcceptancePolicyRequired)

	require.Len(t, fixture.tokens(), tokens)
	require.Empty(t, fixture.credentials())
	require.Zero(t, draft13StoredCount(t, unverified))
}

// draft13States returns a complete state of each stage for issuer, stamped
// with version.
func draft13States(issuer string, version IssuanceVersion) (*IssuanceAuthorization, *IssuanceGrant, *DeferredIssuance, *IssuanceNotification) {
	token := &receiverTypes.CredentialIssuanceAccessToken{Token: "access-1", TokenType: "Bearer"}
	return &IssuanceAuthorization{
			Version:                   version,
			AuthorizationURL:          issuer + "/authorize?state=state-1",
			State:                     "state-1",
			CodeVerifier:              "verifier-1",
			CredentialIssuer:          issuer,
			CredentialConfigurationID: "degree",
			AuthorizationServer:       issuer,
			ClientID:                  draft13ClientID,
			RedirectURI:               draft13RedirectURI,
		}, &IssuanceGrant{
			Version:                   version,
			CredentialIssuer:          issuer,
			CredentialConfigurationID: "degree",
			AuthorizationServer:       issuer,
			AccessToken:               token,
			CNonce:                    "nonce-1",
		}, &DeferredIssuance{
			Version:                   version,
			CredentialIssuer:          issuer,
			CredentialConfigurationID: "degree",
			TransactionID:             "transaction-1",
			AccessToken:               token,
		}, &IssuanceNotification{
			Version:          version,
			CredentialIssuer: issuer,
			NotificationID:   "notification-1",
			AccessToken:      token,
		}
}

// HAIP 1.0 applies to OpenID4VCI 1.0 only: every Draft 13 method is refused
// before anything is sent.
func TestDraft13IsForbiddenUnderHAIP(t *testing.T) {
	fixture := newDraft13Fixture(t)
	haip := newProfileWallet(t, profile.HAIP, &receiverOid4vci.Oid4vciReceiver{Profile: profile.HAIP}, nil, acceptIssuerKeyPolicy(fixture.issuerKey))
	draft13 := haip.Draft13()
	ctx := context.Background()
	authorization, grant, deferred, notification := draft13States(fixture.server.URL, IssuanceVersionDraft13)

	_, err := draft13.BeginIssuance(ctx, IssuanceRequest{CredentialOffer: fixture.authorizationCodeOffer()})
	draft13RequireCoded(t, err, ErrProfileForbidsDraft)
	_, err = draft13.AuthorizeIssuance(ctx, authorization, draft13Redirect(authorization, ""))
	draft13RequireCoded(t, err, ErrProfileForbidsDraft)
	_, err = draft13.AuthorizePreAuthorizedIssuance(ctx, fixture.preAuthorizedRequest())
	draft13RequireCoded(t, err, ErrProfileForbidsDraft)
	_, err = draft13.RequestCredential(ctx, grant, fixture.holder())
	draft13RequireCoded(t, err, ErrProfileForbidsDraft)
	_, err = draft13.RequestDeferredCredential(ctx, deferred)
	draft13RequireCoded(t, err, ErrProfileForbidsDraft)
	draft13RequireCoded(t, draft13.NotifyIssuer(ctx, notification, NotificationCredentialAccepted, ""), ErrProfileForbidsDraft)

	require.Empty(t, fixture.tokens())
	require.Empty(t, fixture.credentials())
	require.Empty(t, fixture.deferreds())
	require.Empty(t, fixture.notifications())
}

// A state of one OpenID4VCI version is refused by the other version's
// methods before anything is sent.
func TestDraft13StatesAndFinalStatesDoNotMix(t *testing.T) {
	fixture := newDraft13Fixture(t, draft13RegisteredClient)
	ctx := context.Background()
	w := fixture.wallet
	draft13 := w.Draft13()

	authorization, grant, deferred, notification := draft13States(fixture.server.URL, IssuanceVersionDraft13)
	_, err := w.AuthorizeIssuance(ctx, authorization, draft13Redirect(authorization, ""))
	draft13RequireCoded(t, err, ErrIssuanceVersionMismatch)
	_, err = w.RequestCredential(ctx, grant, fixture.holder())
	draft13RequireCoded(t, err, ErrIssuanceVersionMismatch)
	_, err = w.RequestDeferredCredential(ctx, deferred)
	draft13RequireCoded(t, err, ErrIssuanceVersionMismatch)
	draft13RequireCoded(t, w.NotifyIssuer(ctx, notification, NotificationCredentialAccepted, ""), ErrIssuanceVersionMismatch)

	authorization, grant, deferred, notification = draft13States(fixture.server.URL, IssuanceVersionFinal)
	_, err = draft13.AuthorizeIssuance(ctx, authorization, draft13Redirect(authorization, ""))
	draft13RequireCoded(t, err, ErrIssuanceVersionMismatch)
	_, err = draft13.RequestCredential(ctx, grant, fixture.holder())
	draft13RequireCoded(t, err, ErrIssuanceVersionMismatch)
	_, err = draft13.RequestDeferredCredential(ctx, deferred)
	draft13RequireCoded(t, err, ErrIssuanceVersionMismatch)
	draft13RequireCoded(t, draft13.NotifyIssuer(ctx, notification, NotificationCredentialAccepted, ""), ErrIssuanceVersionMismatch)

	require.Empty(t, fixture.tokens())
	require.Empty(t, fixture.credentials())
	require.Empty(t, fixture.deferreds())
	require.Empty(t, fixture.notifications())
}

// Every request of a Draft 13 issuance, its deferred request and its
// notification carries the role it was sent for.
func TestObserveLabelsEveryDraft13IssuanceRequest(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.set(func(f *draft13Fixture) {
		f.credentialResponse = func(int, map[string]any) (int, any) {
			return http.StatusAccepted, map[string]any{"transaction_id": "transaction-1"}
		}
	})
	recorder := &observetest.Recorder{}
	w := fixture.newWallet(t, func(c *Config) {
		c.Receiver = fixture.receiver(t, observedClient(fixture.server.Client(), recorder))
	})
	ctx := context.Background()

	grant := fixture.preAuthorize(t, w)
	result, err := w.Draft13().RequestCredential(ctx, grant, fixture.holder())
	require.NoError(t, err)
	issued, err := w.Draft13().RequestDeferredCredential(ctx, result.Deferred)
	require.NoError(t, err)
	require.NoError(t, w.Draft13().NotifyIssuer(ctx, issued.Notification, NotificationCredentialAccepted, ""))

	byPath := map[string]observe.Endpoint{
		"/.well-known/openid-credential-issuer":   observe.EndpointIssuerMetadata,
		"/.well-known/oauth-authorization-server": observe.EndpointAuthorizationServerMetadata,
		"/token":        observe.EndpointToken,
		"/credential":   observe.EndpointCredential,
		"/deferred":     observe.EndpointDeferredCredential,
		"/notification": observe.EndpointNotification,
	}
	for _, exchange := range recorder.Exchanges() {
		require.Equal(t, byPath[exchange.Request.URL.Path], exchange.Endpoint, "role of %s", exchange.Request.URL.Path)
		require.NotNil(t, exchange.Response)
	}
	require.Equal(t, []observe.Endpoint{
		observe.EndpointIssuerMetadata,
		observe.EndpointAuthorizationServerMetadata,
		observe.EndpointToken,
		observe.EndpointCredential,
		observe.EndpointDeferredCredential,
		observe.EndpointIssuerMetadata,
		observe.EndpointNotification,
	}, recorder.Endpoints())
}

// Under HAIP the Draft 13 view refuses before it reads the state it is given.
func TestDraft13RefusesUnderHAIPBeforeReadingTheState(t *testing.T) {
	w := newHAIPIssuanceFixture(t).wallet.Draft13()
	_, err := w.RequestCredential(context.Background(), nil, CredentialRequest{})
	require.ErrorIs(t, err, ErrProfileForbidsDraft)
	_, err = w.RequestDeferredCredential(context.Background(), nil)
	require.ErrorIs(t, err, ErrProfileForbidsDraft)
	_, err = w.AuthorizeIssuance(context.Background(), nil, "")
	require.ErrorIs(t, err, ErrProfileForbidsDraft)
	require.ErrorIs(t, w.NotifyIssuer(context.Background(), nil, NotificationCredentialAccepted, ""), ErrProfileForbidsDraft)
}

// A configuration that lists cryptographic_binding_methods_supported requires a
// cnf, as on the Final path: an unbound credential is refused, not stored.
func TestDraft13RefusesUnboundCredentialWhenBindingIsRequired(t *testing.T) {
	fixture := newDraft13Fixture(t)
	unbound := flowTestUnboundSDJWTVC(t, fixture.issuerKey)
	fixture.set(func(f *draft13Fixture) {
		f.credentialResponse = func(int, map[string]any) (int, any) {
			return 200, map[string]any{"credential": unbound, "notification_id": "notification-1"}
		}
	})
	grant := fixture.preAuthorize(t, fixture.wallet)
	result, err := fixture.wallet.Draft13().RequestCredential(context.Background(), grant, fixture.holder())
	require.ErrorIs(t, err, acceptance.ErrHolderBindingMissing)
	require.NotNil(t, result)
	require.Empty(t, result.Credentials)
	require.NotNil(t, result.Notification)
	require.Zero(t, draft13StoredCount(t, fixture.wallet))
}
