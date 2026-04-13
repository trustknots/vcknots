package mockserver

import (
	"maps"
	"net/http"
)

// OID4VCIIssuerConfig holds configuration for an OID4VCI issuer mock server
type OID4VCIIssuerConfig struct {
	KeyPair                     *KeyPair
	IssuerID                    string
	CredentialConfigurations    map[string]interface{}
	TokenResponse               map[string]interface{}
	PreAuthorizedGrantAnonymous bool
	CustomCredentials           map[string]string
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
		"authorization_servers":               []string{baseURL},
		"credential_configurations_supported": is.config.CredentialConfigurations,
	}

	JSONResponse(w, http.StatusOK, metadata)
}

// handleAuthServerMetadata handles the authorization server metadata endpoint
func (is *OID4VCIIssuerServer) handleAuthServerMetadata(w http.ResponseWriter, r *http.Request) {
	baseURL := "http://" + r.Host

	metadata := map[string]interface{}{
		"issuer":         baseURL,
		"token_endpoint": baseURL + "/token",
		"pre_authorized_grant_anonymous_access_supported": is.config.PreAuthorizedGrantAnonymous,
		"response_types_supported":                        []string{"code"},
	}

	JSONResponse(w, http.StatusOK, metadata)
}

// handleToken handles the token endpoint
func (is *OID4VCIIssuerServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Only POST method is allowed")
		return
	}

	JSONResponse(w, http.StatusOK, is.config.TokenResponse)
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
