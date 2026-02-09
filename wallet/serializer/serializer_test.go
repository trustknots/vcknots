package serializer

import (
	"errors"
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/keystore"
	"github.com/trustknots/vcknots/wallet/serializer/types"
)

// MockSerializer for testing
type MockSerializer struct {
	shouldError bool
}

func (m *MockSerializer) SerializeCredential(flavor credential.SupportedSerializationFlavor, cred *credential.Credential) ([]byte, error) {
	if m.shouldError {
		return nil, errors.New("mock error")
	}
	return []byte("mock serialized credential"), nil
}

func (m *MockSerializer) DeserializeCredential(flavor credential.SupportedSerializationFlavor, data []byte) (*credential.Credential, error) {
	if m.shouldError {
		return nil, errors.New("mock error")
	}
	return &credential.Credential{}, nil
}

func (m *MockSerializer) SerializePresentation(flavor credential.SupportedSerializationFlavor, presentation *credential.CredentialPresentation, key keystore.KeyEntry, options types.SerializePresentationOptions) ([]byte, *credential.CredentialPresentation, error) {
	if m.shouldError {
		return nil, nil, errors.New("mock error")
	}
	return []byte("mock serialized presentation"), presentation, nil
}

func (m *MockSerializer) DeserializePresentation(flavor credential.SupportedSerializationFlavor, data []byte) (*credential.CredentialPresentation, error) {
	if m.shouldError {
		return nil, errors.New("mock error")
	}
	return &credential.CredentialPresentation{}, nil
}

type MockKeyEntry struct {
	shouldSignError bool
}

func (m *MockKeyEntry) ID() string {
	return "mock"
}

func (m *MockKeyEntry) PublicKey() jose.JSONWebKey {
	return jose.JSONWebKey{}
}

func (m *MockKeyEntry) Sign(binary []byte) ([]byte, error) {
	if m.shouldSignError {
		return nil, fmt.Errorf("error")
	}
	return []byte("signature"), nil
}

func TestNewSerializationDispatcher(t *testing.T) {
	dispatcher, err := NewSerializationDispatcher()
	if err != nil {
		t.Fatalf("Failed to create dispatcher: %v", err)
	}

	if dispatcher == nil {
		t.Fatal("Dispatcher should not be nil")
	}

	if len(dispatcher.plugins) != 0 {
		t.Errorf("Expected empty plugins map, got %d plugins", len(dispatcher.plugins))
	}
}

func TestNewSerializationDispatcherWithDefaultConfig(t *testing.T) {
	dispatcher, err := NewSerializationDispatcher(WithDefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create dispatcher with default config: %v", err)
	}

	formats := dispatcher.GetSupportedFormats()
	if len(formats) != 2 { // WithDefaultConfig supports only jwtvc
		t.Errorf("Expected 1 supported formats, got %d", len(formats))
	}
}

func TestRegisterPlugin(t *testing.T) {
	dispatcher, err := NewSerializationDispatcher()
	if err != nil {
		t.Fatalf("Failed to create dispatcher: %v", err)
	}

	plugin := &MockSerializer{}
	err = dispatcher.RegisterPlugin(credential.JwtVc, plugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	formats := dispatcher.GetSupportedFormats()
	if len(formats) != 1 {
		t.Errorf("Expected 1 supported format, got %d", len(formats))
	}

	if formats[0] != credential.JwtVc {
		t.Errorf("Expected JWT VC format, got %v", formats[0])
	}
}

func TestRegisterPluginNil(t *testing.T) {
	dispatcher, err := NewSerializationDispatcher()
	if err != nil {
		t.Fatalf("Failed to create dispatcher: %v", err)
	}

	err = dispatcher.RegisterPlugin(credential.JwtVc, nil)
	if err == nil {
		t.Fatal("Expected error when registering nil plugin")
	}

	if !errors.Is(err, types.ErrNilPlugin) {
		t.Errorf("Expected ErrNilPlugin, got %v", err)
	}
}

func TestGetPluginNotFound(t *testing.T) {
	dispatcher, err := NewSerializationDispatcher()
	if err != nil {
		t.Fatalf("Failed to create dispatcher: %v", err)
	}

	_, err = dispatcher.getPlugin(credential.JwtVc)
	if err == nil {
		t.Fatal("Expected error when getting non-existent plugin")
	}

	if !errors.Is(err, types.ErrPluginNotFound) {
		t.Errorf("Expected ErrPluginNotFound, got %v", err)
	}
}

func TestSerializeCredential(t *testing.T) {
	t.Run("Normal case", func(t *testing.T) {
		dispatcher, err := NewSerializationDispatcher()
		if err != nil {
			t.Fatalf("Failed to create dispatcher: %v", err)
		}

		plugin := &MockSerializer{}
		err = dispatcher.RegisterPlugin(credential.JwtVc, plugin)
		if err != nil {
			t.Fatalf("Failed to register plugin: %v", err)
		}

		cred := &credential.Credential{}
		result, err := dispatcher.SerializeCredential(credential.JwtVc, cred)
		if err != nil {
			t.Fatalf("Failed to serialize credential: %v", err)
		}

		expected := "mock serialized credential"
		if string(result) != expected {
			t.Errorf("Expected %s, got %s", expected, string(result))
		}
	})

	t.Run("Nil credential", func(t *testing.T) {
		dispatcher, err := NewSerializationDispatcher()
		if err != nil {
			t.Fatalf("Failed to create dispatcher: %v", err)
		}

		plugin := &MockSerializer{}
		err = dispatcher.RegisterPlugin(credential.JwtVc, plugin)
		if err != nil {
			t.Fatalf("Failed to register plugin: %v", err)
		}

		_, err = dispatcher.SerializeCredential(credential.JwtVc, nil)
		if err == nil {
			t.Fatalf("SerializeCredential() should return error if cred is nil")
		}
	})

	t.Run("Empty credential", func(t *testing.T) {
		dispatcher, err := NewSerializationDispatcher()
		if err != nil {
			t.Fatalf("Failed to create dispatcher: %v", err)
		}

		plugin := &MockSerializer{shouldError: true}
		err = dispatcher.RegisterPlugin(credential.JwtVc, plugin)
		if err != nil {
			t.Fatalf("Failed to register plugin: %v", err)
		}

		cred := &credential.Credential{}
		_, err = dispatcher.SerializeCredential(credential.JwtVc, cred)
		if err == nil {
			t.Fatal("Expected error from plugin")
		}
	})

	t.Run("Unsupported flavor", func(t *testing.T) {
		dispatcher, err := NewSerializationDispatcher()
		if err != nil {
			t.Fatalf("Failed to create dispatcher: %v", err)
		}

		cred := &credential.Credential{}
		_, err = dispatcher.SerializeCredential("unsupported flavor", cred)
		if err == nil {
			t.Fatalf("SerializeCredential() should return error if cred is nil")
		}
	})
}

func TestDeserializeCredential(t *testing.T) {

	t.Run("Normal case", func(t *testing.T) {
		dispatcher, err := NewSerializationDispatcher()
		if err != nil {
			t.Fatalf("Failed to create dispatcher: %v", err)
		}

		plugin := &MockSerializer{}
		err = dispatcher.RegisterPlugin(credential.JwtVc, plugin)
		if err != nil {
			t.Fatalf("Failed to register plugin: %v", err)
		}

		data := []byte("test data")
		cred, err := dispatcher.DeserializeCredential(credential.JwtVc, data)
		if err != nil {
			t.Fatalf("Failed to deserialize credential: %v", err)
		}

		if cred == nil {
			t.Fatal("Expected non-nil credential")
		}
	})

	t.Run("Invalid data", func(t *testing.T) {
		dispatcher, err := NewSerializationDispatcher()
		if err != nil {
			t.Fatalf("Failed to create dispatcher: %v", err)
		}

		plugin := &MockSerializer{shouldError: true}
		err = dispatcher.RegisterPlugin(credential.JwtVc, plugin)
		if err != nil {
			t.Fatalf("Failed to register plugin: %v", err)
		}

		data := []byte("test data")
		_, err = dispatcher.DeserializeCredential(credential.JwtVc, data)
		if err == nil {
			t.Fatal("Expected error from plugin")
		}
	})

	t.Run("Empty data", func(t *testing.T) {
		dispatcher, err := NewSerializationDispatcher()
		if err != nil {
			t.Fatalf("Failed to create dispatcher: %v", err)
		}

		plugin := &MockSerializer{shouldError: true}
		err = dispatcher.RegisterPlugin(credential.JwtVc, plugin)
		if err != nil {
			t.Fatalf("Failed to register plugin: %v", err)
		}

		data := []byte("")
		_, err = dispatcher.DeserializeCredential(credential.JwtVc, data)
		if err == nil {
			t.Fatal("Expected error from dispatcher")
		}
	})

	t.Run("Unsupported flavor", func(t *testing.T) {
		dispatcher, err := NewSerializationDispatcher()
		if err != nil {
			t.Fatalf("Failed to create dispatcher: %v", err)
		}

		data := []byte("hogefugapiyo")
		_, err = dispatcher.DeserializeCredential("Unsupported flavor", data)
		if err == nil {
			t.Fatal("Expected error")
		}
	})
}

func TestSerializePresentation(t *testing.T) {
	t.Run("Normal test", func(t *testing.T) {
		dispatcher, err := NewSerializationDispatcher()
		if err != nil {
			t.Fatalf("Failed to initialize SerializationDispatcher: %v", err)
		}
		plugin := &MockSerializer{shouldError: false}
		err = dispatcher.RegisterPlugin(credential.JwtVc, plugin)
		if err != nil {
			t.Fatalf("Failed to register plugin: %v", err)
		}
		presentation := credential.CredentialPresentation{}
		keyEntry := MockKeyEntry{shouldSignError: false}
		_, _, err = dispatcher.SerializePresentation(credential.JwtVc, &presentation, &keyEntry, nil)
		if err != nil {
			t.Fatalf("SerializePresentation failed: error = %v", err)
		}
	})

	t.Run("Invalid argument (presentation == nil)", func(t *testing.T) {
		dispatcher, err := NewSerializationDispatcher()
		if err != nil {
			t.Fatalf("Failed to initialize SerializationDispatcher: %v", err)
		}
		keyEntry := MockKeyEntry{shouldSignError: false}
		_, _, err = dispatcher.SerializePresentation(credential.JwtVc, nil, &keyEntry, nil)
		if err == nil {
			t.Errorf("SerializePresentation() should return error when presentation argument is nil")
		}
	})

	t.Run("Invalid argument (key == nil)", func(t *testing.T) {
		dispatcher, err := NewSerializationDispatcher()
		if err != nil {
			t.Fatalf("Failed to initialize SerializationDispatcher: %v", err)
		}
		presentation := credential.CredentialPresentation{}
		_, _, err = dispatcher.SerializePresentation(credential.JwtVc, &presentation, nil, nil)
		if err == nil {
			t.Errorf("SerializePresentation() should return error when key argument is nil")
		}
	})

	t.Run("Unsupported flavor", func(t *testing.T) {
		dispatcher, err := NewSerializationDispatcher()
		if err != nil {
			t.Fatalf("Failed to initialize SerializationDispatcher: %v", err)
		}
		presentation := credential.CredentialPresentation{}
		keyEntry := MockKeyEntry{shouldSignError: false}
		_, _, err = dispatcher.SerializePresentation("unsupported flavor", &presentation, &keyEntry, nil)
		if err == nil {
			t.Errorf("SerializePresentation() should return error when key argument is nil")
		}
	})

	t.Run("plugin failed", func(t *testing.T) {
		dispatcher, err := NewSerializationDispatcher()
		if err != nil {
			t.Fatalf("Failed to initialize SerializationDispatcher: %v", err)
		}
		plugin := &MockSerializer{shouldError: true}
		err = dispatcher.RegisterPlugin(credential.JwtVc, plugin)
		if err != nil {
			t.Fatalf("Failed to register plugin: %v", err)
		}
		presentation := credential.CredentialPresentation{}
		keyEntry := MockKeyEntry{shouldSignError: false}
		_, _, err = dispatcher.SerializePresentation(credential.JwtVc, &presentation, &keyEntry, nil)
		if err == nil {
			t.Errorf("SerializePresentation should return error when plugin failed")
		}
	})
}

func TestDeserializePresentation(t *testing.T) {
	t.Run("Normal case", func(t *testing.T) {
		dispatcher, err := NewSerializationDispatcher()
		if err != nil {
			t.Fatalf("Failed to initialize SerializationDispatcher: %v", err)
		}
		plugin := &MockSerializer{shouldError: false}
		err = dispatcher.RegisterPlugin(credential.JwtVc, plugin)
		if err != nil {
			t.Fatalf("Failed to register plugin: %v", err)
		}
		presentation, err := dispatcher.DeserializePresentation(credential.JwtVc, []byte("test"))
		if err != nil {
			t.Errorf("DeserializePresentation() return error: %v", err)
		}
		if presentation == nil {
			t.Errorf("DeserializePresentation() return nil presentation")
		}
	})

	t.Run("Empty data", func(t *testing.T) {
		dispatcher, err := NewSerializationDispatcher()
		if err != nil {
			t.Fatalf("Failed to initialize SerializationDispatcher: %v", err)
		}
		plugin := &MockSerializer{shouldError: false}
		err = dispatcher.RegisterPlugin(credential.JwtVc, plugin)
		if err != nil {
			t.Fatalf("Failed to register plugin: %v", err)
		}
		_, err = dispatcher.DeserializePresentation(credential.JwtVc, []byte(""))
		if err == nil {
			t.Errorf("DeserializePresentation() should return error when length of data == 0")
		}
	})

	t.Run("Unsupported plugin", func(t *testing.T) {
		dispatcher, err := NewSerializationDispatcher()
		if err != nil {
			t.Fatalf("Failed to initialize SerializationDispatcher: %v", err)
		}
		_, err = dispatcher.DeserializePresentation("unsupported plugin", []byte("test"))
		if err == nil {
			t.Errorf("DeserializePresentation() should return error when plugin is unsupported")
		}
	})

	t.Run("Plugin failed", func(t *testing.T) {
		dispatcher, err := NewSerializationDispatcher()
		if err != nil {
			t.Fatalf("Failed to initialize SerializationDispatcher: %v", err)
		}
		plugin := &MockSerializer{shouldError: true}
		err = dispatcher.RegisterPlugin(credential.JwtVc, plugin)
		if err != nil {
			t.Fatalf("Failed to register plugin: %v", err)
		}
		_, err = dispatcher.DeserializePresentation(credential.JwtVc, []byte("test"))
		if err == nil {
			t.Errorf("DeserializePresentation() should return error when plugin failed")
		}
	})
}

func TestWithPlugin(t *testing.T) {
	plugin := &MockSerializer{}

	dispatcher, err := NewSerializationDispatcher(
		WithPlugin(credential.JwtVc, plugin),
	)
	if err != nil {
		t.Fatalf("Failed to create dispatcher with plugin: %v", err)
	}

	formats := dispatcher.GetSupportedFormats()
	if len(formats) != 1 {
		t.Errorf("Expected 1 supported format, got %d", len(formats))
	}

	if formats[0] != credential.JwtVc {
		t.Errorf("Expected JWT VC format, got %v", formats[0])
	}
}

func TestGetSupportedFormats(t *testing.T) {
	dispatcher, err := NewSerializationDispatcher()
	if err != nil {
		t.Fatalf("Failed to create dispatcher: %v", err)
	}

	// Empty initially
	formats := dispatcher.GetSupportedFormats()
	if len(formats) != 0 {
		t.Errorf("Expected 0 formats, got %d", len(formats))
	}

	// Add a plugin
	plugin := &MockSerializer{}
	err = dispatcher.RegisterPlugin(credential.JwtVc, plugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	formats = dispatcher.GetSupportedFormats()
	if len(formats) != 1 {
		t.Errorf("Expected 1 format, got %d", len(formats))
	}
}
