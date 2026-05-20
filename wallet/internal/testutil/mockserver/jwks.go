package mockserver

import (
	"net/http"

	"github.com/go-jose/go-jose/v4"
)

// JWKSConfig holds configuration for a JWKS mock server
type JWKSConfig struct {
	KeyPairs       []*KeyPair
	CustomJWKS     *jose.JSONWebKeySet
	ErrorResponses map[string]int // path -> status code for error responses
}

// DefaultJWKSConfig creates a default configuration for JWKS server
func DefaultJWKSConfig() *JWKSConfig {
	return &JWKSConfig{
		KeyPairs:       []*KeyPair{MustGenerateKeyPair("default-jwks-key")},
		ErrorResponses: make(map[string]int),
	}
}

// JWKSServer is a mock JWKS server
type JWKSServer struct {
	server *MockServer
	config *JWKSConfig
}

// NewJWKSServer creates a new JWKS mock server
func NewJWKSServer(config *JWKSConfig) *JWKSServer {
	if config == nil {
		config = DefaultJWKSConfig()
	}

	server := NewMockServer()

	js := &JWKSServer{
		server: server,
		config: config,
	}

	js.setupRoutes()
	return js
}

// setupRoutes configures the server routes
func (js *JWKSServer) setupRoutes() {
	// Standard JWKS endpoint
	js.server.HandleFunc("/.well-known/jwks.json", js.handleJWKS)

	// Alternative JWKS endpoint
	js.server.HandleFunc("/jwks", js.handleJWKS)

	// Health check endpoint
	js.server.HandleFunc("/health", js.handleHealth)
}

// handleJWKS handles the JWKS endpoint
func (js *JWKSServer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	// Check for configured error responses
	if statusCode, exists := js.config.ErrorResponses[r.URL.Path]; exists {
		ErrorResponse(w, statusCode, "Mock error response")
		return
	}

	jwks := js.generateJWKS()
	JSONResponse(w, http.StatusOK, jwks)
}

// handleHealth handles the health check endpoint
func (js *JWKSServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	JSONResponse(w, http.StatusOK, map[string]string{"status": "healthy"})
}

// generateJWKS generates the JWKS response
func (js *JWKSServer) generateJWKS() map[string]interface{} {
	if js.config.CustomJWKS != nil {
		return map[string]interface{}{
			"keys": js.config.CustomJWKS.Keys,
		}
	}

	var keys []jose.JSONWebKey
	for _, keyPair := range js.config.KeyPairs {
		keys = append(keys, keyPair.CreatePublicJWK())
	}

	return map[string]interface{}{
		"keys": keys,
	}
}

// AddKeyPair adds a new key pair to the JWKS
func (js *JWKSServer) AddKeyPair(keyPair *KeyPair) {
	js.config.KeyPairs = append(js.config.KeyPairs, keyPair)
}

// SetErrorResponse configures an error response for a specific path
func (js *JWKSServer) SetErrorResponse(path string, statusCode int) {
	js.config.ErrorResponses[path] = statusCode
}

// ClearErrorResponse removes an error response configuration
func (js *JWKSServer) ClearErrorResponse(path string) {
	delete(js.config.ErrorResponses, path)
}

// SetCustomJWKS sets a custom JWKS response
func (js *JWKSServer) SetCustomJWKS(jwks *jose.JSONWebKeySet) {
	js.config.CustomJWKS = jwks
}

// URL returns the base URL of the JWKS server
func (js *JWKSServer) URL() string {
	return js.server.URL()
}

// JWKSEndpoint returns the full URL of the JWKS endpoint
func (js *JWKSServer) JWKSEndpoint() string {
	return js.server.URL() + "/.well-known/jwks.json"
}

// Host returns the host of the JWKS server
func (js *JWKSServer) Host() string {
	return js.server.Host()
}

// Close shuts down the JWKS server
func (js *JWKSServer) Close() {
	js.server.Close()
}

// GetKeyPairs returns all key pairs used by the server
func (js *JWKSServer) GetKeyPairs() []*KeyPair {
	return js.config.KeyPairs
}
