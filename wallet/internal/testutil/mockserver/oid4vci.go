package mockserver

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"

	"github.com/go-jose/go-jose/v4"
)

// OID4VCIIssuerConfig holds configuration for an OID4VCI issuer mock server
type OID4VCIIssuerConfig struct {
	KeyPair                     *KeyPair
	IssuerID                    string
	CredentialConfigurations    map[string]interface{}
	TokenResponse               map[string]interface{}
	PreAuthorizedGrantAnonymous bool
	CustomCredentials           map[string]string
	OmitAuthorizationServers    bool

	// TokenEndpointAuthMethodsSupported is advertised in the authorization
	// server metadata. When non-empty it also gates /token: a request must
	// match RequireClientAssertion below.
	TokenEndpointAuthMethodsSupported []string
	TokenEndpointAuthSigningAlgs      []string
	// RequireClientAssertion, when true, makes /token require a valid
	// private_key_jwt client_assertion signed by ClientAuthPublicKey.
	RequireClientAssertion bool
	ClientAuthPublicKey    *jose.JSONWebKey
	ExpectedClientID       string
	// ClientAssertionAudience is the registered aud value. When empty, the
	// authorization server issuer (the mock server base URL) is expected.
	ClientAssertionAudience string
}

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
		PreAuthorizedGrantAnonymous: true,
		CustomCredentials:           make(map[string]string),
	}
}

// OID4VCIIssuerServer is a mock OID4VCI issuer server
type OID4VCIIssuerServer struct {
	server     *MockServer
	config     *OID4VCIIssuerConfig
	jwtBuilder *JWTBuilder
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

// handleCredentialIssuerMetadata handles the credential issuer metadata endpoint
func (is *OID4VCIIssuerServer) handleCredentialIssuerMetadata(w http.ResponseWriter, r *http.Request) {
	baseURL := "http://" + r.Host

	metadata := map[string]interface{}{
		"credential_issuer":                   baseURL,
		"credential_endpoint":                 baseURL + "/credential",
		"nonce_endpoint":                      baseURL + "/nonce",
		"credential_configurations_supported": is.config.CredentialConfigurations,
	}
	if !is.config.OmitAuthorizationServers {
		metadata["authorization_servers"] = []string{baseURL}
	}

	JSONResponse(w, http.StatusOK, metadata)
}

// handleAuthServerMetadata handles the authorization server metadata endpoint
func (is *OID4VCIIssuerServer) handleAuthServerMetadata(w http.ResponseWriter, r *http.Request) {
	baseURL := "http://" + r.Host

	metadata := map[string]interface{}{
		"issuer":         baseURL,
		"token_endpoint": baseURL + "/token",
		"pre-authorized_grant_anonymous_access_supported": is.config.PreAuthorizedGrantAnonymous,
		"response_types_supported":                        []string{"code"},
	}

	if len(is.config.TokenEndpointAuthMethodsSupported) > 0 {
		metadata["token_endpoint_auth_methods_supported"] = is.config.TokenEndpointAuthMethodsSupported
	}
	if len(is.config.TokenEndpointAuthSigningAlgs) > 0 {
		metadata["token_endpoint_auth_signing_alg_values_supported"] = is.config.TokenEndpointAuthSigningAlgs
	}

	JSONResponse(w, http.StatusOK, metadata)
}

// handleToken handles the token endpoint
func (is *OID4VCIIssuerServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Only POST method is allowed")
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

	JSONResponse(w, http.StatusOK, is.config.TokenResponse)
}

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
	expectedID := is.config.ExpectedClientID
	if expectedID == "" {
		expectedID = clientID
	}
	if clientID == "" {
		return fmt.Errorf("client_id is required")
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
	}
	if err := json.Unmarshal(verified, &claims); err != nil {
		return fmt.Errorf("failed to parse client_assertion claims: %w", err)
	}

	if claims.ISS != expectedID || claims.SUB != expectedID {
		return fmt.Errorf("client_assertion iss/sub must match client_id")
	}
	expectedAudience := is.config.ClientAssertionAudience
	if expectedAudience == "" {
		expectedAudience = "http://" + r.Host
	}
	if claims.AUD != expectedAudience {
		return fmt.Errorf("client_assertion aud must match registered authorization server audience")
	}
	if claims.EXP == 0 {
		return fmt.Errorf("client_assertion exp is required")
	}

	return nil
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
