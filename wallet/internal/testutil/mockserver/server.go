package mockserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
)

// MockServer provides common functionality for test servers
type MockServer struct {
	server         *httptest.Server
	mux            *http.ServeMux
	errorResponses map[string]int // path -> status code for error responses
}

// NewMockServer creates a new mock server
func NewMockServer() *MockServer {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	return &MockServer{
		server:         server,
		mux:            mux,
		errorResponses: make(map[string]int),
	}
}

// URL returns the base URL of the mock server
func (ms *MockServer) URL() string {
	return ms.server.URL
}

// Host returns the host of the mock server (host:port format)
func (ms *MockServer) Host() string {
	return ms.server.Listener.Addr().String()
}

// Close shuts down the server
func (ms *MockServer) Close() {
	ms.server.Close()
}

// HandleFunc registers a handler function for the given pattern
func (ms *MockServer) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	ms.mux.HandleFunc(pattern, handler)
}

// JSONResponse is a helper to send JSON responses
func JSONResponse(w http.ResponseWriter, status int, data interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}

// ErrorResponse is a helper to send error responses
func ErrorResponse(w http.ResponseWriter, status int, message string) error {
	return JSONResponse(w, status, map[string]string{"error": message})
}

// CORSHandler adds CORS headers to responses
func CORSHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

// LoggingHandler logs HTTP requests (useful for debugging tests)
func LoggingHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Uncomment for debugging
		// log.Printf("Mock Server: %s %s", r.Method, r.URL.Path)
		next(w, r)
	}
}

// SetErrorResponse configures an error response for a specific path
func (ms *MockServer) SetErrorResponse(path string, statusCode int) {
	ms.errorResponses[path] = statusCode
}

// ClearErrorResponse removes an error response configuration
func (ms *MockServer) ClearErrorResponse(path string) {
	delete(ms.errorResponses, path)
}

// HandleFuncWithErrorCheck handles function with automatic error response checking
func (ms *MockServer) HandleFuncWithErrorCheck(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	ms.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		// Check for configured error responses
		if statusCode, exists := ms.errorResponses[r.URL.Path]; exists {
			ErrorResponse(w, statusCode, "Mock error response")
			return
		}
		handler(w, r)
	})
}

// SetJSONResponse sets a JSON response for a specific path
func (ms *MockServer) SetJSONResponse(path string, statusCode int, data interface{}) {
	ms.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		JSONResponse(w, statusCode, data)
	})
}

// SetTextResponse sets a text response for a specific path
func (ms *MockServer) SetTextResponse(path string, statusCode int, text string) {
	ms.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		w.Write([]byte(text))
	})
}
