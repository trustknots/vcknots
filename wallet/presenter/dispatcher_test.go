package presenter

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/trustknots/vcknots/wallet/presenter/types"
)

func TestNewPresentationDispatcher(t *testing.T) {
	// Test creation with default config
	dispatcher, err := NewPresentationDispatcher(WithDefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create dispatcher with default config: %v", err)
	}

	if dispatcher == nil {
		t.Fatal("Dispatcher should not be nil")
	}

	// Test creation without options
	dispatcher2, err := NewPresentationDispatcher()
	if err != nil {
		t.Fatalf("Failed to create empty dispatcher: %v", err)
	}

	if dispatcher2 == nil {
		t.Fatal("Dispatcher should not be nil")
	}
}

func TestPresentationDispatcher_RegisterPlugin(t *testing.T) {
	dispatcher, err := NewPresentationDispatcher()
	if err != nil {
		t.Fatalf("Failed to create dispatcher: %v", err)
	}

	// Test registering valid plugin - create mock component
	plugin := &mockPresenter{}
	err = dispatcher.registerPlugin(types.Oid4vp, plugin)
	if err != nil {
		t.Fatalf("Failed to register valid plugin: %v", err)
	}

	// Test registering nil plugin
	err = dispatcher.registerPlugin(types.Oid4vp, nil)
	if err == nil {
		t.Fatal("Expected error when registering nil plugin")
	}
}

type mockPresenter struct {
	shouldError         bool
	parseRequestURIFunc func(string) (any, error)
}

func (m *mockPresenter) Present(protocol types.SupportedPresentationProtocol, endpoint url.URL, serializedPresentation []byte, presentationSubmission types.PresentationSubmission) error {
	if m.shouldError {
		return fmt.Errorf("mock error")
	}
	return nil
}

func (m *mockPresenter) ParseRequestURI(uriString string) (any, error) {
	if m.parseRequestURIFunc != nil {
		return m.parseRequestURIFunc(uriString)
	}
	if m.shouldError {
		return nil, fmt.Errorf("mock parse error")
	}
	return map[string]any{"uri": uriString}, nil
}

func TestPresentationDispatcher_Present(t *testing.T) {
	// Use mock plugin for controlled testing environment
	mockPlugin := &mockPresenter{}
	dispatcher, err := NewPresentationDispatcher(WithPlugin(types.Oid4vp, mockPlugin))
	if err != nil {
		t.Fatalf("Failed to create dispatcher: %v", err)
	}

	// Test with empty serialized presentation
	testURL, _ := url.Parse("https://example.com")
	err = dispatcher.Present(types.Oid4vp, *testURL, []byte{}, types.PresentationSubmission{})
	if err == nil {
		t.Fatal("Expected error for empty serialized presentation")
	}

	// Test unsupported presentation protocol
	invalidType := types.SupportedPresentationProtocol(999)
	err = dispatcher.Present(invalidType, *testURL, []byte("test"), types.PresentationSubmission{})
	if err == nil {
		t.Fatal("Expected error for unsupported presentation protocol")
	}

	// Test successful present with OID4VP using mock plugin
	err = dispatcher.Present(types.Oid4vp, *testURL, []byte("valid-presentation"), types.PresentationSubmission{})
	if err != nil {
		t.Errorf("Present returned unexpected error: %v", err)
	}

	// Test error case with mock plugin
	mockPlugin.shouldError = true
	err = dispatcher.Present(types.Oid4vp, *testURL, []byte("valid-presentation"), types.PresentationSubmission{})
	if err == nil {
		t.Fatal("Expected error when mock plugin returns error")
	}
}

func TestPresentationDispatcher_ParseRequestURI(t *testing.T) {
	// Test dispatcher's basic functionality - plugin management and error handling
	// Current implementation always uses OID4VP protocol and casts to specific type

	tests := []struct {
		name        string
		usePlugin   bool
		uriString   string
		expectError bool
		description string
	}{
		{
			name:        "no plugin registered",
			usePlugin:   false,
			uriString:   "openid4vp://present?client_id=test",
			expectError: true,
			description: "should fail when no plugin is registered",
		},
		{
			name:        "with plugin registered - delegation test",
			usePlugin:   true,
			uriString:   "openid4vp://present?client_id=test",
			expectError: true, // Mock plugin doesn't match OID4VP plugin type cast
			description: "should attempt to delegate to plugin but fail type assertion",
		},
		{
			name:        "empty URI",
			usePlugin:   true,
			uriString:   "",
			expectError: true,
			description: "should handle empty URI",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dispatcher *PresentationDispatcher
			var err error

			if tt.usePlugin {
				mockPlugin := &mockPresenter{}
				dispatcher, err = NewPresentationDispatcher(WithPlugin(types.Oid4vp, mockPlugin))
			} else {
				dispatcher, err = NewPresentationDispatcher()
			}

			if err != nil {
				t.Fatalf("Failed to create dispatcher: %v", err)
			}

			result, err := dispatcher.ParseRequestURI(tt.uriString)

			if tt.expectError {
				if err == nil {
					t.Errorf("ParseRequestURI() expected error but got none for %s", tt.description)
				}
				if result != nil {
					t.Errorf("ParseRequestURI() expected nil result on error for %s", tt.description)
				}
			} else {
				if err != nil {
					t.Errorf("ParseRequestURI() returned unexpected error: %v", err)
				}
				if result == nil {
					t.Errorf("ParseRequestURI() expected result but got nil for %s", tt.description)
				}
			}
		})
	}
}

func TestPresentationDispatcher_GetPlugin_ErrorPath(t *testing.T) {
	dispatcher, err := NewPresentationDispatcher() // No default config means no plugins
	if err != nil {
		t.Fatalf("Failed to create dispatcher: %v", err)
	}

	// Test getPlugin with unsupported protocol
	_, err = dispatcher.getPlugin(types.SupportedPresentationProtocol(999))
	if err == nil {
		t.Fatal("Expected error for unsupported protocol")
	}
}

func TestWithPlugin(t *testing.T) {
	plugin := &mockPresenter{}

	dispatcher, err := NewPresentationDispatcher(WithPlugin(types.Oid4vp, plugin))
	if err != nil {
		t.Fatalf("Failed to create dispatcher with plugin: %v", err)
	}

	if dispatcher == nil {
		t.Fatal("Dispatcher should not be nil")
	}

	// Test with nil plugin
	_, err = NewPresentationDispatcher(WithPlugin(types.Oid4vp, nil))
	if err == nil {
		t.Fatal("Expected error when creating dispatcher with nil plugin")
	}
}
