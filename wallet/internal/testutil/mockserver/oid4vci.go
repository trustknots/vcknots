package mockserver

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// OID4VCIIssuerConfig holds configuration for an OID4VCI issuer mock server
type OID4VCIIssuerConfig struct {
	KeyPair                  *KeyPair
	IssuerID                 string
	CredentialConfigurations map[string]interface{}
	TokenResponse            map[string]interface{}
	// PreAuthorizedGrantAnonymous controls the OPTIONAL authorization server
	// metadata parameter pre-authorized_grant_anonymous_access_supported. A nil
	// value omits the parameter from the metadata entirely, which is what real
	// issuers commonly do and what a plain bool cannot express.
	PreAuthorizedGrantAnonymous *bool
	CustomCredentials           map[string]string
	OmitAuthorizationServers    bool
	EmptyAuthorizationServers   bool

	// TokenEndpointAuthMethodsSupported is advertised in the authorization
	// server metadata as token_endpoint_auth_methods_supported.
	TokenEndpointAuthMethodsSupported []string
	TokenEndpointAuthSigningAlgs      []string
	// RequireClientAssertion, when true, makes /token require a valid
	// private_key_jwt client_assertion signed by ClientAuthPublicKey.
	RequireClientAssertion bool
	ClientAuthPublicKey    *jose.JSONWebKey
	ExpectedClientID       string

	// RequireClientAttestation, when true, makes /token require the
	// attestation-based client authentication of
	// draft-ietf-oauth-attestation-based-client-auth (OpenID4VCI 1.0 Appendix
	// E) on every grant it accepts, the Pre-Authorized Code grant included. The
	// headers are validated, not merely counted: the OAuth-Client-Attestation
	// JWT must be signed by ClientAttesterPublicKey, name ExpectedClientID in
	// sub and carry the wallet instance key in cnf.jwk, and the
	// OAuth-Client-Attestation-PoP JWT must be signed by that instance key,
	// name the client in iss and this server's issuer identifier in aud.
	RequireClientAttestation bool
	// ClientAttesterPublicKey verifies the Client Attestation signature. It is
	// registration data: an attestation that is only checked against a key
	// taken from itself proves nothing.
	ClientAttesterPublicKey *jose.JSONWebKey
	// ClientAssertionAudience is the registered aud value that client_assertion
	// must carry. It must be set before a token request is validated. Deriving
	// it from the incoming request would make the aud check tautological,
	// because the wallet resolves the same value from this server's metadata.
	ClientAssertionAudience string

	// CredentialIssuerIdentifier is the credential_issuer the metadata document
	// states, and the aud every key proof must carry. Empty means the server's
	// own base URL.
	//
	// It is never taken from the request's Host header. OpenID4VCI 1.0 §12.2.4
	// makes credential_issuer "REQUIRED. The Credential Issuer's identifier ...
	// The value MUST be identical to the Credential Issuer's identifier value
	// into which the well-known URI string was inserted to create the URL used
	// to retrieve the metadata. If these values are not identical (when
	// compared using a simple string comparison with no normalization), the
	// data contained in the response MUST NOT be used." A document that echoes
	// the request it answers can never fail that comparison, so a wallet that
	// never performs it still passes; setting a different value here is how a
	// test makes the comparison fail.
	CredentialIssuerIdentifier string

	// SupportedGrantTypes lists the grant types the token endpoint accepts. Nil
	// means the two this issuer implements, authorization_code and
	// urn:ietf:params:oauth:grant-type:pre-authorized_code. Anything else is
	// answered with the RFC 6749 §5.2 unsupported_grant_type error, as a real
	// authorization server does.
	SupportedGrantTypes []string

	// PKCECodeChallenge is the RFC 7636 S256 code_challenge the authorization
	// request carried. When set, the token endpoint requires a code_verifier
	// that hashes to it: §4.6 says that "If the values are not equal, an error
	// response indicating invalid_grant MUST be returned".
	PKCECodeChallenge string

	// RequirePKCE refuses an authorization_code token request that carries no
	// code_verifier even when no challenge is configured.
	RequirePKCE bool

	// RequireDPoP refuses a token or credential request that carries no RFC
	// 9449 DPoP proof, and validates the proof it does carry. HAIP §4 requires
	// a sender-constrained access token ("Sender-constrained access token: MUST
	// support DPoP"), and an issuer that issues one does not accept a proofless
	// request.
	RequireDPoP bool

	// TokenDPoPNonce, when set, makes the first token request answer with RFC
	// 9449 §8 use_dpop_nonce and this DPoP-Nonce header, so the retry is
	// exercised; the second attempt must carry the nonce in its proof.
	TokenDPoPNonce string

	// NonceDPoPNonce is sent as the DPoP-Nonce header of the Nonce Response.
	// OpenID4VCI 1.0 §7.2: "The Credential Issuer MAY provide a DPoP nonce in
	// an HTTP header ... In this case, the Wallet uses the new nonce value in
	// the DPoP proof when presenting an access token at the Credential
	// Endpoint."
	NonceDPoPNonce string

	// RequireCredentialProof requires a §8.2.1.1 "jwt" key proof on every
	// credential request. Nil means "whenever the requested credential
	// configuration advertises proof_types_supported", which is what a real
	// issuer's metadata promises. A proof that is present is always validated.
	RequireCredentialProof *bool
}

// defaultSupportedGrantTypes lists the grant types this mock issuer implements.
var defaultSupportedGrantTypes = []string{"authorization_code", "urn:ietf:params:oauth:grant-type:pre-authorized_code"}

// credentialProofJWTType is the typ OpenID4VCI 1.0 §8.2.1.1 requires of a "jwt"
// key proof: "REQUIRED. MUST be `openid4vci-proof+jwt`, which explicitly types
// the key proof JWT as recommended in Section 3.11 of [@!RFC8725]".
const credentialProofJWTType = "openid4vci-proof+jwt"

// dpopProofJWTType is the typ RFC 9449 §4.2 requires of a DPoP proof.
const dpopProofJWTType = "dpop+jwt"

// DefaultOID4VCIIssuerConfig creates a default configuration for OID4VCI issuer
func DefaultOID4VCIIssuerConfig() *OID4VCIIssuerConfig {
	return &OID4VCIIssuerConfig{
		KeyPair:  MustGenerateKeyPair("issuer-key-id"),
		IssuerID: "test-issuer",
		CredentialConfigurations: map[string]interface{}{
			"test-config": map[string]interface{}{
				"format": "jwt_vc_json",
				"credential_definition": map[string]interface{}{
					"type": []string{"VerifiableCredential"},
				},
			},
		},
		TokenResponse: map[string]interface{}{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"c_nonce":      "mock-nonce",
		},
		PreAuthorizedGrantAnonymous: BoolPtr(true),
		CustomCredentials:           make(map[string]string),
	}
}

// BoolPtr returns a pointer to v, for the optional metadata parameters whose
// absence and explicit false mean different things.
func BoolPtr(v bool) *bool { return &v }

// OID4VCIIssuerServer is a mock OID4VCI issuer server
type OID4VCIIssuerServer struct {
	server     *MockServer
	config     *OID4VCIIssuerConfig
	jwtBuilder *JWTBuilder

	// mu guards the recorded requests, which the handlers write from the
	// server's goroutine while the test reads them from its own.
	mu                  sync.Mutex
	tokenRequests       []url.Values
	tokenRequestHeaders []http.Header
	credentialRequests  []CredentialEndpointRequest
	nonceRequests       int
	// tokenDPoPNonceSent records that the RFC 9449 §8 use_dpop_nonce challenge
	// has already been issued once, so the retry is answered rather than
	// challenged again.
	tokenDPoPNonceSent bool
	// issuedCNonce is the c_nonce this issuer last handed out, which every key
	// proof must echo (§8.2.1.1).
	issuedCNonce string
}

// CredentialEndpointRequest is one Credential Endpoint request as the issuer saw
// it. The handler answers every request the same way, so a test that needs to
// know what the wallet actually sent -- which Authorization scheme, whether a
// DPoP proof accompanied it, which body and media type -- reads it here instead
// of inferring it from a successful response.
type CredentialEndpointRequest struct {
	// Authorization is the raw Authorization header, scheme included.
	Authorization string
	// DPoP is the RFC 9449 proof header, empty when none was sent.
	DPoP string
	// ContentType is the request media type: application/json for a plain
	// request, application/jwt for an encrypted one.
	ContentType string
	// Body is the request body exactly as it arrived, still encrypted when the
	// wallet encrypted it.
	Body []byte
}

// NewOID4VCIIssuerServer creates a new OID4VCI issuer mock server
func NewOID4VCIIssuerServer(config *OID4VCIIssuerConfig) *OID4VCIIssuerServer {
	if config == nil {
		config = DefaultOID4VCIIssuerConfig()
	}

	server := NewMockServer()
	jwtBuilder := MustNewJWTBuilder(config.KeyPair)

	is := &OID4VCIIssuerServer{
		server:     server,
		config:     config,
		jwtBuilder: jwtBuilder,
	}
	// The c_nonce the token response states is the one this issuer would have
	// issued, so a credential request that never went through /token or /nonce
	// is still judged against it rather than against nothing.
	if cNonce, ok := config.TokenResponse["c_nonce"].(string); ok {
		is.issuedCNonce = cNonce
	}

	is.setupRoutes()
	return is
}

// setupRoutes configures the server routes
func (is *OID4VCIIssuerServer) setupRoutes() {
	// Credential issuer metadata endpoint
	is.server.HandleFunc("/.well-known/openid-credential-issuer", is.handleCredentialIssuerMetadata)

	// Authorization server metadata endpoint
	is.server.HandleFunc("/.well-known/oauth-authorization-server", is.handleAuthServerMetadata)

	// Token endpoint
	is.server.HandleFunc("/token", is.handleToken)

	// Nonce endpoint
	is.server.HandleFunc("/nonce", is.handleNonce)

	// Credential endpoint
	is.server.HandleFunc("/credential", is.handleCredential)
}

// IssuerIdentifier is the Credential Issuer Identifier this server states in
// its metadata: the configured value, or the server's own base URL. A test
// asserting on the §12.2.2 identity comparison reads it here instead of
// rebuilding it.
func (is *OID4VCIIssuerServer) IssuerIdentifier() string {
	if identifier := strings.TrimSpace(is.config.CredentialIssuerIdentifier); identifier != "" {
		return identifier
	}
	return is.server.URL()
}

// handleCredentialIssuerMetadata handles the credential issuer metadata endpoint
func (is *OID4VCIIssuerServer) handleCredentialIssuerMetadata(w http.ResponseWriter, _ *http.Request) {
	// The endpoints stay on the address the server actually listens on; only
	// the identifier is the configured one, so a test can make the §12.2.4
	// credential_issuer comparison fail without making the issuer unreachable.
	baseURL := is.server.URL()

	metadata := map[string]interface{}{
		"credential_issuer":                   is.IssuerIdentifier(),
		"credential_endpoint":                 baseURL + "/credential",
		"nonce_endpoint":                      baseURL + "/nonce",
		"credential_configurations_supported": is.config.CredentialConfigurations,
	}
	if !is.config.OmitAuthorizationServers {
		metadata["authorization_servers"] = []string{baseURL}
	}
	if is.config.EmptyAuthorizationServers {
		metadata["authorization_servers"] = []string{}
	}

	JSONResponse(w, http.StatusOK, metadata)
}

// handleAuthServerMetadata handles the authorization server metadata endpoint
func (is *OID4VCIIssuerServer) handleAuthServerMetadata(w http.ResponseWriter, _ *http.Request) {
	baseURL := is.server.URL()

	metadata := map[string]interface{}{
		"issuer":                   baseURL,
		"token_endpoint":           baseURL + "/token",
		"response_types_supported": []string{"code"},
	}

	if is.config.PreAuthorizedGrantAnonymous != nil {
		metadata["pre-authorized_grant_anonymous_access_supported"] = *is.config.PreAuthorizedGrantAnonymous
	}

	if len(is.config.TokenEndpointAuthMethodsSupported) > 0 {
		metadata["token_endpoint_auth_methods_supported"] = is.config.TokenEndpointAuthMethodsSupported
	}
	if len(is.config.TokenEndpointAuthSigningAlgs) > 0 {
		metadata["token_endpoint_auth_signing_alg_values_supported"] = is.config.TokenEndpointAuthSigningAlgs
	}

	JSONResponse(w, http.StatusOK, metadata)
}

// TokenRequests returns the form of every token request the server has received,
// so a test can assert on what the wallet actually sent rather than only on
// whether the call succeeded.
func (is *OID4VCIIssuerServer) TokenRequests() []url.Values {
	is.mu.Lock()
	defer is.mu.Unlock()
	return slices.Clone(is.tokenRequests)
}

// TokenRequestHeaders returns the headers of every token request the server has
// received, in arrival order, so a test can assert on what travelled outside
// the form: the RFC 9449 DPoP proof and the Appendix E
// OAuth-Client-Attestation headers.
func (is *OID4VCIIssuerServer) TokenRequestHeaders() []http.Header {
	is.mu.Lock()
	defer is.mu.Unlock()
	return slices.Clone(is.tokenRequestHeaders)
}

// CredentialRequests returns every Credential Endpoint request the server has
// received, in arrival order.
func (is *OID4VCIIssuerServer) CredentialRequests() []CredentialEndpointRequest {
	is.mu.Lock()
	defer is.mu.Unlock()
	return slices.Clone(is.credentialRequests)
}

// NonceRequests returns how many Nonce Endpoint requests the server has
// received, so a test can tell a refreshed c_nonce from the constant one the
// handler serves.
func (is *OID4VCIIssuerServer) NonceRequests() int {
	is.mu.Lock()
	defer is.mu.Unlock()
	return is.nonceRequests
}

// handleToken handles the token endpoint
func (is *OID4VCIIssuerServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Only POST method is allowed")
		return
	}

	if err := r.ParseForm(); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "failed to parse token request form")
		return
	}
	is.mu.Lock()
	is.tokenRequests = append(is.tokenRequests, r.PostForm)
	is.tokenRequestHeaders = append(is.tokenRequestHeaders, r.Header.Clone())
	is.mu.Unlock()

	if err := is.validateGrant(r); err != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]interface{}{
			"error":             err.code,
			"error_description": err.description,
		})
		return
	}

	if is.config.RequireClientAssertion {
		if err := is.validateClientAssertion(r); err != nil {
			JSONResponse(w, http.StatusBadRequest, map[string]interface{}{
				"error":             "invalid_client",
				"error_description": err.Error(),
			})
			return
		}
	}

	// The Appendix E headers authenticate the client whichever grant the
	// request carries, so the check is not conditioned on grant_type: an issuer
	// that accepts an attested client on the authorization code grant and an
	// anonymous one on the pre-authorized code grant would authenticate nothing.
	if is.config.RequireClientAttestation {
		if err := is.validateClientAttestation(r); err != nil {
			JSONResponse(w, http.StatusBadRequest, map[string]interface{}{
				"error":             "invalid_client",
				"error_description": err.Error(),
			})
			return
		}
	}

	if is.config.RequireDPoP {
		// RFC 9449 §8: the first request may legitimately carry no nonce; the
		// server then answers use_dpop_nonce with the nonce to use. A request
		// with no proof at all is refused outright.
		nonce := ""
		if is.config.TokenDPoPNonce != "" {
			is.mu.Lock()
			seen := is.tokenDPoPNonceSent
			is.tokenDPoPNonceSent = true
			is.mu.Unlock()
			if !seen {
				w.Header().Set("DPoP-Nonce", is.config.TokenDPoPNonce)
				JSONResponse(w, http.StatusBadRequest, map[string]interface{}{
					"error":             "use_dpop_nonce",
					"error_description": "authorization server requires nonce in DPoP proof",
				})
				return
			}
			nonce = is.config.TokenDPoPNonce
		}
		if err := is.validateDPoPProof(r, is.server.URL()+"/token", "", nonce); err != nil {
			w.Header().Set("WWW-Authenticate", "DPoP error=\"invalid_dpop_proof\"")
			JSONResponse(w, http.StatusBadRequest, map[string]interface{}{
				"error":             "invalid_dpop_proof",
				"error_description": err.Error(),
			})
			return
		}
	}

	if cNonce, ok := is.config.TokenResponse["c_nonce"].(string); ok && cNonce != "" {
		is.mu.Lock()
		is.issuedCNonce = cNonce
		is.mu.Unlock()
	}
	JSONResponse(w, http.StatusOK, is.config.TokenResponse)
}

// oauthError is one RFC 6749 §5.2 error response the token endpoint returns.
type oauthError struct {
	code        string
	description string
}

func (e *oauthError) Error() string { return e.code + ": " + e.description }

// validateGrant applies the grant rules a real authorization server applies
// before it issues a token: RFC 6749 §5.2 ("unsupported_grant_type: The
// authorization grant type is not supported by the authorization server"), the
// per-grant required parameter, and the RFC 7636 §4.6 PKCE verification ("If
// the values are not equal, an error response indicating invalid_grant MUST be
// returned").
func (is *OID4VCIIssuerServer) validateGrant(r *http.Request) *oauthError {
	grantType := r.PostForm.Get("grant_type")
	supported := is.config.SupportedGrantTypes
	if len(supported) == 0 {
		supported = defaultSupportedGrantTypes
	}
	if !slices.Contains(supported, grantType) {
		return &oauthError{code: "unsupported_grant_type", description: fmt.Sprintf("grant_type %q is not supported", grantType)}
	}
	switch grantType {
	case "authorization_code":
		if r.PostForm.Get("code") == "" {
			return &oauthError{code: "invalid_request", description: "code is required"}
		}
		if err := is.validatePKCE(r.PostForm.Get("code_verifier")); err != nil {
			return err
		}
	case "urn:ietf:params:oauth:grant-type:pre-authorized_code":
		if r.PostForm.Get("pre-authorized_code") == "" {
			return &oauthError{code: "invalid_request", description: "pre-authorized_code is required"}
		}
	}
	return nil
}

// validatePKCE checks the code_verifier against the configured code_challenge.
// RFC 7636 §4.1 bounds the verifier at 43 to 128 unreserved characters, and
// §4.6 compares BASE64URL(SHA256(code_verifier)) with the stored challenge.
func (is *OID4VCIIssuerServer) validatePKCE(verifier string) *oauthError {
	challenge := strings.TrimSpace(is.config.PKCECodeChallenge)
	if challenge == "" && !is.config.RequirePKCE {
		return nil
	}
	if verifier == "" {
		return &oauthError{code: "invalid_grant", description: "code_verifier is required"}
	}
	if len(verifier) < 43 || len(verifier) > 128 || strings.Trim(verifier, pkceVerifierAlphabet) != "" {
		return &oauthError{code: "invalid_grant", description: "code_verifier is not a valid RFC 7636 code verifier"}
	}
	if challenge == "" {
		return nil
	}
	digest := sha256.Sum256([]byte(verifier))
	if base64.RawURLEncoding.EncodeToString(digest[:]) != challenge {
		return &oauthError{code: "invalid_grant", description: "code_verifier does not match the code_challenge"}
	}
	return nil
}

// pkceVerifierAlphabet is the RFC 7636 §4.1 unreserved character set.
const pkceVerifierAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

// validateClientAssertion validates a private_key_jwt client_assertion sent in a
// token request against the configured public key.
func (is *OID4VCIIssuerServer) validateClientAssertion(r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("failed to parse form: %w", err)
	}

	assertionType := r.FormValue("client_assertion_type")
	if assertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		return fmt.Errorf("client_assertion_type must be urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	}

	assertion := r.FormValue("client_assertion")
	if assertion == "" {
		return fmt.Errorf("client_assertion is required")
	}

	clientID := r.FormValue("client_id")
	if clientID == "" {
		return fmt.Errorf("client_id is required")
	}
	// The expected client_id is registration data, never the value the request
	// happens to carry: initialising it from the request made the iss/sub check
	// below compare the assertion with itself.
	expectedID := is.config.ExpectedClientID
	if expectedID == "" {
		return fmt.Errorf("ExpectedClientID must be configured to validate client_assertion iss/sub")
	}

	token, err := jose.ParseSigned(assertion, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return fmt.Errorf("failed to parse client_assertion: %w", err)
	}

	if is.config.ClientAuthPublicKey == nil {
		return fmt.Errorf("server has no client auth public key configured")
	}

	verified, err := token.Verify(is.config.ClientAuthPublicKey)
	if err != nil {
		return fmt.Errorf("client_assertion signature verification failed: %w", err)
	}

	var claims struct {
		ISS string `json:"iss"`
		SUB string `json:"sub"`
		AUD string `json:"aud"`
		EXP int64  `json:"exp"`
		NBF int64  `json:"nbf"`
	}
	if err := json.Unmarshal(verified, &claims); err != nil {
		return fmt.Errorf("failed to parse client_assertion claims: %w", err)
	}

	if claims.ISS != expectedID || claims.SUB != expectedID {
		return fmt.Errorf("client_assertion iss/sub must match client_id")
	}
	expectedAudience := is.config.ClientAssertionAudience
	if expectedAudience == "" {
		return fmt.Errorf("ClientAssertionAudience must be configured to validate client_assertion aud")
	}
	if claims.AUD != expectedAudience {
		return fmt.Errorf("client_assertion aud must match registered authorization server audience")
	}
	if claims.EXP == 0 {
		return fmt.Errorf("client_assertion exp is required")
	}
	now := time.Now().Unix()
	if claims.EXP <= now {
		return fmt.Errorf("client_assertion has expired")
	}
	if claims.NBF > now {
		return fmt.Errorf("client_assertion is not yet valid")
	}

	return nil
}

// Attestation-based client authentication typ values from
// draft-ietf-oauth-attestation-based-client-auth Section 4, which OpenID4VCI
// 1.0 Appendix E profiles.
const (
	clientAttestationJWTType    = "oauth-client-attestation+jwt"
	clientAttestationPopJWTType = "oauth-client-attestation-pop+jwt"
)

// validateClientAttestation validates the OAuth-Client-Attestation and
// OAuth-Client-Attestation-PoP headers of a token request the way an
// authorization server does: the attestation is signed by the registered
// attester and binds a wallet instance key to the registered client_id, and the
// PoP is signed by exactly that instance key and addressed to this server. A
// PoP verified against a key taken from the request alone would prove nothing,
// which is why the attester key is registration data on the config.
func (is *OID4VCIIssuerServer) validateClientAttestation(r *http.Request) error {
	attestation := strings.TrimSpace(r.Header.Get("OAuth-Client-Attestation"))
	if attestation == "" {
		return fmt.Errorf("OAuth-Client-Attestation header is required")
	}
	pop := strings.TrimSpace(r.Header.Get("OAuth-Client-Attestation-PoP"))
	if pop == "" {
		return fmt.Errorf("OAuth-Client-Attestation-PoP header is required")
	}
	expectedID := strings.TrimSpace(is.config.ExpectedClientID)
	if expectedID == "" {
		return fmt.Errorf("ExpectedClientID must be configured to validate the client attestation")
	}
	if is.config.ClientAttesterPublicKey == nil {
		return fmt.Errorf("server has no client attester public key configured")
	}

	attestationToken, err := jose.ParseSigned(attestation, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return fmt.Errorf("failed to parse the client attestation: %w", err)
	}
	if typ := jwtTypeHeader(attestationToken); typ != clientAttestationJWTType {
		return fmt.Errorf("client attestation typ must be %q, got %q", clientAttestationJWTType, typ)
	}
	attestationPayload, err := attestationToken.Verify(is.config.ClientAttesterPublicKey)
	if err != nil {
		return fmt.Errorf("client attestation signature verification failed: %w", err)
	}
	var attestationClaims struct {
		ISS string `json:"iss"`
		SUB string `json:"sub"`
		AUD string `json:"aud"`
		EXP int64  `json:"exp"`
		CNF struct {
			JWK *jose.JSONWebKey `json:"jwk"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(attestationPayload, &attestationClaims); err != nil {
		return fmt.Errorf("failed to parse the client attestation claims: %w", err)
	}
	if attestationClaims.SUB != expectedID {
		return fmt.Errorf("client attestation sub must be the registered client_id")
	}
	if attestationClaims.CNF.JWK == nil {
		return fmt.Errorf("client attestation cnf.jwk is required")
	}
	now := time.Now().Unix()
	if attestationClaims.EXP == 0 || attestationClaims.EXP <= now {
		return fmt.Errorf("client attestation is expired or carries no exp")
	}
	// HAIP Section 4.4.1: "Wallet Attestations MUST NOT be reused across
	// different Issuers." An audience-restricted attestation naming another
	// server is exactly the reuse that restriction exists to catch.
	if attestationClaims.AUD != "" && attestationClaims.AUD != is.server.URL() {
		return fmt.Errorf("client attestation aud %q was not minted for this authorization server", attestationClaims.AUD)
	}

	popToken, err := jose.ParseSigned(pop, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return fmt.Errorf("failed to parse the client attestation PoP: %w", err)
	}
	if typ := jwtTypeHeader(popToken); typ != clientAttestationPopJWTType {
		return fmt.Errorf("client attestation PoP typ must be %q, got %q", clientAttestationPopJWTType, typ)
	}
	popPayload, err := popToken.Verify(attestationClaims.CNF.JWK)
	if err != nil {
		return fmt.Errorf("client attestation PoP signature verification failed: %w", err)
	}
	var popClaims struct {
		ISS string `json:"iss"`
		AUD string `json:"aud"`
		JTI string `json:"jti"`
		EXP int64  `json:"exp"`
	}
	if err := json.Unmarshal(popPayload, &popClaims); err != nil {
		return fmt.Errorf("failed to parse the client attestation PoP claims: %w", err)
	}
	if popClaims.ISS != expectedID {
		return fmt.Errorf("client attestation PoP iss must be the registered client_id")
	}
	if popClaims.AUD != is.server.URL() {
		return fmt.Errorf("client attestation PoP aud %q is not this authorization server", popClaims.AUD)
	}
	if strings.TrimSpace(popClaims.JTI) == "" {
		return fmt.Errorf("client attestation PoP jti is required")
	}
	if popClaims.EXP == 0 || popClaims.EXP <= now {
		return fmt.Errorf("client attestation PoP is expired or carries no exp")
	}
	return nil
}

// jwtTypeHeader returns the typ header of a parsed JWS, empty when it carries
// none.
func jwtTypeHeader(token *jose.JSONWebSignature) string {
	if len(token.Signatures) == 0 {
		return ""
	}
	typ, _ := token.Signatures[0].Header.ExtraHeaders[jose.HeaderType].(string)
	return typ
}

// handleNonce handles the nonce endpoint
func (is *OID4VCIIssuerServer) handleNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Only POST method is allowed")
		return
	}

	nonce := "mock-nonce"
	if configuredNonce, ok := is.config.TokenResponse["c_nonce"].(string); ok && configuredNonce != "" {
		nonce = configuredNonce
	}

	is.mu.Lock()
	is.nonceRequests++
	is.issuedCNonce = nonce
	is.mu.Unlock()

	if is.config.NonceDPoPNonce != "" {
		// §7.2: "The Credential Issuer MAY provide a DPoP nonce in an HTTP
		// header as defined in Section 8.2 of [@!RFC9449]."
		w.Header().Set("DPoP-Nonce", is.config.NonceDPoPNonce)
	}
	// §7.2: "the Credential Issuer MUST make the response uncacheable by adding
	// a Cache-Control header field including the value no-store".
	w.Header().Set("Cache-Control", "no-store")

	response := map[string]interface{}{
		"c_nonce": nonce,
	}

	JSONResponse(w, http.StatusOK, response)
}

// handleCredential handles the credential endpoint
func (is *OID4VCIIssuerServer) handleCredential(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Only POST method is allowed")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		ErrorResponse(w, http.StatusBadRequest, "failed to read credential request body")
		return
	}
	contentType := r.Header.Get("Content-Type")
	is.mu.Lock()
	is.credentialRequests = append(is.credentialRequests, CredentialEndpointRequest{
		Authorization: r.Header.Get("Authorization"),
		DPoP:          r.Header.Get("DPoP"),
		ContentType:   contentType,
		Body:          body,
	})
	is.mu.Unlock()

	accessToken, scheme := is.accessTokenAndScheme()
	if accessToken != "" && r.Header.Get("Authorization") != scheme+" "+accessToken {
		// RFC 6750 §2.1 and RFC 9449 §7.1: the token is presented with the
		// scheme the token response named, and no other.
		w.Header().Set("WWW-Authenticate", scheme)
		JSONResponse(w, http.StatusUnauthorized, map[string]interface{}{
			"error":             "invalid_token",
			"error_description": "the access token must be presented with the " + scheme + " scheme",
		})
		return
	}
	// The proof itself is validated when the issuer is configured to require
	// DPoP; the Authorization scheme above is checked in every configuration,
	// because RFC 6750 §2.1 and RFC 9449 §7.1 are not interchangeable.
	if is.config.RequireDPoP {
		if err := is.validateDPoPProof(r, is.server.URL()+"/credential", accessToken, is.config.NonceDPoPNonce); err != nil {
			w.Header().Set("WWW-Authenticate", "DPoP error=\"invalid_dpop_proof\"")
			JSONResponse(w, http.StatusUnauthorized, map[string]interface{}{
				"error":             "invalid_dpop_proof",
				"error_description": err.Error(),
			})
			return
		}
	}
	if proofErr := is.validateCredentialProofs(body, contentType); proofErr != nil {
		JSONResponse(w, http.StatusBadRequest, map[string]interface{}{
			"error":             proofErr.code,
			"error_description": proofErr.description,
		})
		return
	}

	// For simplicity, return a default mock JWT credential
	// In a real implementation, this would process the request and issue appropriate credentials
	defaultCredentialJWT := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6ImRpZDprZXk6ejZNa2lvNFdEbWR0Z0VvNGY5SHE2aTZ0blc4V0Z3a25RUTRLSFVZOTlCR1k0RVZyIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJpYXQiOjE2MjAyMzk4MDB9.mockSignature"

	response := map[string]interface{}{
		"credentials": []map[string]string{{
			"credential": defaultCredentialJWT,
		}},
	}

	JSONResponse(w, http.StatusOK, response)
}

// CreateCredentialJWT creates a signed JWT credential
func (is *OID4VCIIssuerServer) CreateCredentialJWT(subject string, credentialClaims map[string]interface{}) (string, error) {
	issuer := is.server.URL()

	claims := map[string]interface{}{
		"sub": subject,
		"vc": map[string]interface{}{
			"@context": []string{
				"https://www.w3.org/2018/credentials/v1",
			},
			"type":         []string{"VerifiableCredential"},
			"issuer":       issuer,
			"issuanceDate": "2023-01-01T00:00:00Z",
		},
	}

	// Merge with provided credential claims
	maps.Copy(claims, credentialClaims)

	return is.jwtBuilder.CreateSignedJWT(issuer, claims)
}

// SetCustomCredential sets a custom credential response for testing
func (is *OID4VCIIssuerServer) SetCustomCredential(configID string, credentialJWT string) {
	is.config.CustomCredentials[configID] = credentialJWT
}

// URL returns the base URL of the issuer server
func (is *OID4VCIIssuerServer) URL() string {
	return is.server.URL()
}

// Host returns the host of the issuer server
func (is *OID4VCIIssuerServer) Host() string {
	return is.server.Host()
}

// Close shuts down the issuer server
func (is *OID4VCIIssuerServer) Close() {
	is.server.Close()
}

// GetKeyPair returns the key pair used by the issuer
func (is *OID4VCIIssuerServer) GetKeyPair() *KeyPair {
	return is.config.KeyPair
}

// validateDPoPProof applies the RFC 9449 §4.3 checks a resource or
// authorization server performs on a DPoP proof: exactly one JWS signed by the
// key in its own jwk header, typ dpop+jwt, the htm/htu of this request, a jti,
// an iat, the server-supplied nonce when one was issued, and the ath hash of
// the access token when the request presents one (§4.3 point 11: "If presented
// to a protected resource in conjunction with an access token ... the value of
// the ath claim equals the hash of that access token").
func (is *OID4VCIIssuerServer) validateDPoPProof(r *http.Request, endpoint string, accessToken string, nonce string) error {
	proof := strings.TrimSpace(r.Header.Get("DPoP"))
	if proof == "" {
		return fmt.Errorf("DPoP proof is required")
	}
	signed, err := jose.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.ES512, jose.EdDSA, jose.RS256, jose.PS256})
	if err != nil {
		return fmt.Errorf("DPoP proof is not a compact JWS: %w", err)
	}
	if len(signed.Signatures) != 1 {
		return fmt.Errorf("DPoP proof must carry exactly one signature")
	}
	header := signed.Signatures[0].Header
	if typ, _ := header.ExtraHeaders[jose.HeaderType].(string); typ != dpopProofJWTType {
		return fmt.Errorf("DPoP proof typ must be %q, got %q", dpopProofJWTType, typ)
	}
	if header.JSONWebKey == nil {
		return fmt.Errorf("DPoP proof is missing the jwk header")
	}
	payload, err := signed.Verify(header.JSONWebKey)
	if err != nil {
		return fmt.Errorf("DPoP proof signature is invalid: %w", err)
	}
	var claims struct {
		HTM   string `json:"htm"`
		HTU   string `json:"htu"`
		JTI   string `json:"jti"`
		IAT   *int64 `json:"iat"`
		Nonce string `json:"nonce"`
		ATH   string `json:"ath"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("DPoP proof payload is not JSON: %w", err)
	}
	if !strings.EqualFold(claims.HTM, r.Method) {
		return fmt.Errorf("DPoP proof htm %q does not match %s", claims.HTM, r.Method)
	}
	if claims.HTU != endpoint {
		return fmt.Errorf("DPoP proof htu %q does not match %q", claims.HTU, endpoint)
	}
	if claims.JTI == "" {
		return fmt.Errorf("DPoP proof is missing jti")
	}
	if claims.IAT == nil {
		return fmt.Errorf("DPoP proof is missing iat")
	}
	if nonce != "" && claims.Nonce != nonce {
		return fmt.Errorf("DPoP proof nonce %q does not match the issued nonce", claims.Nonce)
	}
	if accessToken != "" {
		digest := sha256.Sum256([]byte(accessToken))
		if claims.ATH != base64.RawURLEncoding.EncodeToString(digest[:]) {
			return fmt.Errorf("DPoP proof ath does not hash the presented access token")
		}
	}
	return nil
}

// validateCredentialProofs applies the OpenID4VCI 1.0 §8.2.1.1 rules to the key
// proofs of a Credential Request: typ openid4vci-proof+jwt, "aud: REQUIRED
// (string). The value of this claim MUST be the Credential Issuer Identifier",
// "iat: REQUIRED (number)", and "nonce ... MUST be present when the issuer has
// a Nonce Endpoint". The proof must be signed by the key its own JOSE header
// names, which is what the same section requires of the issuer: "The Credential
// Issuer MUST validate that the JWT used as a proof is actually signed by a key
// identified in the JOSE Header".
func (is *OID4VCIIssuerServer) validateCredentialProofs(body []byte, contentType string) *oauthError {
	if !strings.Contains(strings.ToLower(contentType), "application/json") {
		// An encrypted request (application/jwt) is opaque to this mock.
		return nil
	}
	var request struct {
		CredentialConfigurationID string `json:"credential_configuration_id"`
		Proofs                    *struct {
			JWT []string `json:"jwt"`
		} `json:"proofs"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		return &oauthError{code: "invalid_credential_request", description: "credential request is not JSON"}
	}
	proofs := []string{}
	if request.Proofs != nil {
		proofs = request.Proofs.JWT
	}
	if len(proofs) == 0 {
		if is.credentialProofRequired(request.CredentialConfigurationID) {
			return &oauthError{code: "invalid_proof", description: "the credential configuration requires a key proof"}
		}
		return nil
	}
	is.mu.Lock()
	expectedNonce := is.issuedCNonce
	is.mu.Unlock()
	for index, proof := range proofs {
		if err := is.validateCredentialProof(proof, expectedNonce); err != nil {
			return &oauthError{code: err.code, description: fmt.Sprintf("proofs.jwt[%d]: %s", index, err.description)}
		}
	}
	return nil
}

// credentialProofRequired reports whether the configuration the request names
// advertises proof_types_supported, which is the issuer's own statement that a
// proof is expected.
func (is *OID4VCIIssuerServer) credentialProofRequired(credentialConfigurationID string) bool {
	if is.config.RequireCredentialProof != nil {
		return *is.config.RequireCredentialProof
	}
	configuration, ok := is.config.CredentialConfigurations[credentialConfigurationID].(map[string]interface{})
	if !ok {
		return false
	}
	_, present := configuration["proof_types_supported"]
	return present
}

func (is *OID4VCIIssuerServer) validateCredentialProof(proof string, expectedNonce string) *oauthError {
	signed, err := jose.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.ES512, jose.EdDSA, jose.RS256, jose.PS256})
	if err != nil {
		return &oauthError{code: "invalid_proof", description: "key proof is not a compact JWS"}
	}
	if len(signed.Signatures) != 1 {
		return &oauthError{code: "invalid_proof", description: "key proof must carry exactly one signature"}
	}
	header := signed.Signatures[0].Header
	if typ, _ := header.ExtraHeaders[jose.HeaderType].(string); typ != credentialProofJWTType {
		return &oauthError{code: "invalid_proof", description: fmt.Sprintf("key proof typ must be %q, got %q", credentialProofJWTType, typ)}
	}
	if header.JSONWebKey == nil {
		return &oauthError{code: "invalid_proof", description: "key proof is missing the jwk header"}
	}
	payload, err := signed.Verify(header.JSONWebKey)
	if err != nil {
		return &oauthError{code: "invalid_proof", description: "key proof signature is invalid"}
	}
	var claims struct {
		Aud   string `json:"aud"`
		IAT   *int64 `json:"iat"`
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return &oauthError{code: "invalid_proof", description: "key proof payload is not JSON"}
	}
	if claims.Aud != is.IssuerIdentifier() {
		return &oauthError{code: "invalid_proof", description: fmt.Sprintf("key proof aud %q is not the credential issuer identifier %q", claims.Aud, is.IssuerIdentifier())}
	}
	if claims.IAT == nil {
		return &oauthError{code: "invalid_proof", description: "key proof is missing iat"}
	}
	// This issuer always advertises a nonce_endpoint, so §8.2.1.1 makes the
	// nonce mandatory and §8.3.1.2 names the error for a stale one.
	if claims.Nonce == "" {
		return &oauthError{code: "invalid_nonce", description: "key proof is missing the c_nonce"}
	}
	if expectedNonce != "" && claims.Nonce != expectedNonce {
		return &oauthError{code: "invalid_nonce", description: "key proof carries a stale c_nonce"}
	}
	return nil
}

// AccessToken is the access token this issuer's token endpoint hands out, which
// the credential endpoint requires. A test that posts to the credential
// endpoint directly presents this value instead of an invented one: an issuer
// that accepted any string would let a wallet bug through.
func (is *OID4VCIIssuerServer) AccessToken() string {
	token, _ := is.accessTokenAndScheme()
	return token
}

// TokenType is the RFC 6749 §7.1 token_type this issuer's token endpoint
// states, which decides the Authorization scheme the credential endpoint
// accepts.
func (is *OID4VCIIssuerServer) TokenType() string {
	_, scheme := is.accessTokenAndScheme()
	return scheme
}

// accessTokenAndScheme reports the access token this issuer hands out and the
// RFC 6750 / RFC 9449 scheme it must be presented with.
func (is *OID4VCIIssuerServer) accessTokenAndScheme() (token string, scheme string) {
	token, _ = is.config.TokenResponse["access_token"].(string)
	scheme, _ = is.config.TokenResponse["token_type"].(string)
	if scheme == "" {
		scheme = "Bearer"
	}
	return token, scheme
}
