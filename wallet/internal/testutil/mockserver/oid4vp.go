package mockserver

import (
	"net/http"
)

// OID4VPVerifierConfig holds configuration for an OID4VP verifier mock server
type OID4VPVerifierConfig struct {
	KeyPair        *KeyPair
	VerifierID     string
	CustomMetadata map[string]interface{}
}

// DefaultOID4VPVerifierConfig creates a default configuration for OID4VP verifier
func DefaultOID4VPVerifierConfig() *OID4VPVerifierConfig {
	return &OID4VPVerifierConfig{
		KeyPair:        MustGenerateKeyPair("verifier-key-id"),
		VerifierID:     "test-verifier",
		CustomMetadata: make(map[string]interface{}),
	}
}

// OID4VPVerifierServer is a mock OID4VP verifier server
type OID4VPVerifierServer struct {
	server     *MockServer
	config     *OID4VPVerifierConfig
	jwtBuilder *JWTBuilder
}

// NewOID4VPVerifierServer creates a new OID4VP verifier mock server
func NewOID4VPVerifierServer(config *OID4VPVerifierConfig) *OID4VPVerifierServer {
	if config == nil {
		config = DefaultOID4VPVerifierConfig()
	}

	server := NewMockServer()
	jwtBuilder := MustNewJWTBuilder(config.KeyPair)

	vs := &OID4VPVerifierServer{
		server:     server,
		config:     config,
		jwtBuilder: jwtBuilder,
	}

	vs.setupRoutes()
	return vs
}

// setupRoutes configures the server routes
func (vs *OID4VPVerifierServer) setupRoutes() {
	// Verifier metadata endpoint
	vs.server.HandleFunc("/.well-known/openid-verifier", vs.handleVerifierMetadata)

	// JWKS endpoint
	vs.server.HandleFunc("/.well-known/jwks.json", vs.handleJWKS)
}

// handleVerifierMetadata handles the verifier metadata endpoint
func (vs *OID4VPVerifierServer) handleVerifierMetadata(w http.ResponseWriter, r *http.Request) {
	baseURL := "http://" + r.Host

	metadata := map[string]interface{}{
		"issuer":   baseURL,
		"jwks_uri": baseURL + "/.well-known/jwks.json",
		"jwks":     vs.config.KeyPair.CreateJWKS(),
	}

	// Add custom metadata
	for k, v := range vs.config.CustomMetadata {
		metadata[k] = v
	}

	JSONResponse(w, http.StatusOK, metadata)
}

// handleJWKS handles the JWKS endpoint
func (vs *OID4VPVerifierServer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	JSONResponse(w, http.StatusOK, vs.config.KeyPair.CreateJWKS())
}

// CreateSignedJWT creates a signed JWT for authentication requests
func (vs *OID4VPVerifierServer) CreateSignedJWT(claims map[string]interface{}) (string, error) {
	issuer := vs.server.URL()
	return vs.jwtBuilder.CreateSignedJWT(issuer, claims)
}

// URL returns the base URL of the verifier server
func (vs *OID4VPVerifierServer) URL() string {
	return vs.server.URL()
}

// Host returns the host of the verifier server
func (vs *OID4VPVerifierServer) Host() string {
	return vs.server.Host()
}

// Close shuts down the verifier server
func (vs *OID4VPVerifierServer) Close() {
	vs.server.Close()
}

// GetKeyPair returns the key pair used by the verifier
func (vs *OID4VPVerifierServer) GetKeyPair() *KeyPair {
	return vs.config.KeyPair
}

// OID4VPPresenterConfig holds configuration for an OID4VP presenter mock server
type OID4VPPresenterConfig struct {
	AcceptAllPresentations bool
	CustomResponses        map[string]interface{}
}

// DefaultOID4VPPresenterConfig creates a default configuration for OID4VP presenter
func DefaultOID4VPPresenterConfig() *OID4VPPresenterConfig {
	return &OID4VPPresenterConfig{
		AcceptAllPresentations: true,
		CustomResponses:        make(map[string]interface{}),
	}
}

// OID4VPPresenterServer is a mock OID4VP presenter server
type OID4VPPresenterServer struct {
	server *MockServer
	config *OID4VPPresenterConfig
}

// NewOID4VPPresenterServer creates a new OID4VP presenter mock server
func NewOID4VPPresenterServer(config *OID4VPPresenterConfig) *OID4VPPresenterServer {
	if config == nil {
		config = DefaultOID4VPPresenterConfig()
	}

	server := NewMockServer()

	ps := &OID4VPPresenterServer{
		server: server,
		config: config,
	}

	ps.setupRoutes()
	return ps
}

// setupRoutes configures the presenter server routes
func (ps *OID4VPPresenterServer) setupRoutes() {
	// Presentation endpoint
	ps.server.HandleFunc("/present", ps.handlePresentation)
}

// handlePresentation handles the presentation endpoint
func (ps *OID4VPPresenterServer) handlePresentation(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Only POST method is allowed")
		return
	}

	if ps.config.AcceptAllPresentations {
		JSONResponse(w, http.StatusOK, map[string]string{"status": "accepted"})
	} else {
		ErrorResponse(w, http.StatusBadRequest, "Presentation rejected")
	}
}

// URL returns the base URL of the presenter server
func (ps *OID4VPPresenterServer) URL() string {
	return ps.server.URL()
}

// Close shuts down the presenter server
func (ps *OID4VPPresenterServer) Close() {
	ps.server.Close()
}
