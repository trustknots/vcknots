package receiver

import (
	"errors"
	"fmt"
	"testing"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

type mockReceiver struct {
	shouldError bool
}

func (m *mockReceiver) FetchIssuerMetadata(endpoint common.URIField, receivingType types.SupportedReceivingTypes) (*types.CredentialIssuerMetadata, error) {
	if m.shouldError {
		return nil, fmt.Errorf("mock error")
	}
	return &types.CredentialIssuerMetadata{}, nil
}

func (m *mockReceiver) FetchAuthorizationServerMetadata(endpoint common.URIField, receivingType types.SupportedReceivingTypes) (*types.AuthorizationServerMetadata, error) {
	if m.shouldError {
		return nil, fmt.Errorf("mock error")
	}
	return &types.AuthorizationServerMetadata{}, nil
}

func (m *mockReceiver) FetchAccessToken(receivingType types.SupportedReceivingTypes, endpoint common.URIField, authzCode string) (*types.CredentialIssuanceAccessToken, error) {
	if m.shouldError {
		return nil, fmt.Errorf("mock error")
	}
	return &types.CredentialIssuanceAccessToken{}, nil
}

func (m *mockReceiver) ReceiveCredential(
	receivingType types.SupportedReceivingTypes,
	endpoint common.URIField,
	format string,
	accessToken types.CredentialIssuanceAccessToken,
	credentialDefinition *types.CredentialDefinition,
	jwtProof *string,
) (*string, error) {
	if m.shouldError {
		return nil, fmt.Errorf("mock error")
	}
	cred := "mock credential"
	return &cred, nil
}

// Existing tests

func TestNewReceivingDispatcher(t *testing.T) {
	t.Run("With default config", func(t *testing.T) {
		dispatcher, err := NewReceivingDispatcher(WithDefaultConfig())
		if err != nil {
			t.Fatalf("Failed to create dispatcher with default config: %v", err)
		}
		if dispatcher == nil {
			t.Fatal("Dispatcher should not be nil")
		}
	})

	t.Run("With failing option", func(t *testing.T) {
		failingOption := func(d *ReceivingDispatcher) error {
			return errors.New("config error")
		}
		_, err := NewReceivingDispatcher(failingOption)
		if err == nil {
			t.Fatal("Expected error when option function fails")
		}
	})
}

func TestReceivingDispatcher_FetchIssuerMetadata(t *testing.T) {
	mock := &mockReceiver{}
	dispatcher, _ := NewReceivingDispatcher(WithPlugin(types.Oid4vci, mock))

	t.Run("Happy path", func(t *testing.T) {
		_, err := dispatcher.FetchIssuerMetadata(common.URIField{}, types.Oid4vci)
		if err != nil {
			t.Errorf("FetchIssuerMetadata() on happy path should not return error: %v", err)
		}
	})

	t.Run("Plugin returns error", func(t *testing.T) {
		mock.shouldError = true
		_, err := dispatcher.FetchIssuerMetadata(common.URIField{}, types.Oid4vci)
		if err == nil {
			t.Fatal("Expected error when underlying plugin fails")
		}
		mock.shouldError = false
	})

	t.Run("Unsupported receiving type", func(t *testing.T) {
		invalidType := types.SupportedReceivingTypes(999)
		_, err := dispatcher.FetchIssuerMetadata(common.URIField{}, invalidType)
		if err == nil {
			t.Fatal("Expected error for unsupported receiving type")
		}
	})
}

func TestReceivingDispatcher_FetchAuthorizationServerMetadata(t *testing.T) {
	mock := &mockReceiver{}
	dispatcher, _ := NewReceivingDispatcher(WithPlugin(types.Oid4vci, mock))

	t.Run("Happy path", func(t *testing.T) {
		_, err := dispatcher.FetchAuthorizationServerMetadata(common.URIField{}, types.Oid4vci)
		if err != nil {
			t.Errorf("FetchAuthorizationServerMetadata() on happy path should not return error: %v", err)
		}
	})

	t.Run("Plugin returns error", func(t *testing.T) {
		mock.shouldError = true
		_, err := dispatcher.FetchAuthorizationServerMetadata(common.URIField{}, types.Oid4vci)
		if err == nil {
			t.Fatal("Expected error when underlying plugin fails")
		}
		mock.shouldError = false
	})

	t.Run("Unsupported receiving type", func(t *testing.T) {
		invalidType := types.SupportedReceivingTypes(999)
		_, err := dispatcher.FetchAuthorizationServerMetadata(common.URIField{}, invalidType)
		if err == nil {
			t.Fatal("Expected error for unsupported receiving type")
		}
	})
}

func TestReceivingDispatcher_FetchAccessToken(t *testing.T) {
	mock := &mockReceiver{}
	dispatcher, _ := NewReceivingDispatcher(WithPlugin(types.Oid4vci, mock))

	t.Run("Happy path", func(t *testing.T) {
		_, err := dispatcher.FetchAccessToken(types.Oid4vci, common.URIField{}, "test-code")
		if err != nil {
			t.Errorf("FetchAccessToken() on happy path should not return error: %v", err)
		}
	})

	t.Run("Empty authzCode", func(t *testing.T) {
		_, err := dispatcher.FetchAccessToken(types.Oid4vci, common.URIField{}, "")
		if err == nil {
			t.Fatal("Expected error for empty authzCode")
		}
	})

	t.Run("Unsupported receiving type", func(t *testing.T) {
		invalidType := types.SupportedReceivingTypes(999)
		_, err := dispatcher.FetchAccessToken(invalidType, common.URIField{}, "test-code")
		if err == nil {
			t.Fatal("Expected error for unsupported receiving type")
		}
	})
}

func TestReceivingDispatcher_ReceiveCredential(t *testing.T) {
	mock := &mockReceiver{}
	dispatcher, _ := NewReceivingDispatcher(WithPlugin(types.Oid4vci, mock))
	accessToken := types.CredentialIssuanceAccessToken{Token: "test_token"}

	t.Run("Happy path", func(t *testing.T) {
		_, err := dispatcher.ReceiveCredential(types.Oid4vci, common.URIField{}, "jwt_vc_json", accessToken, nil, nil)
		if err != nil {
			t.Errorf("ReceiveCredential() on happy path should not return error: %v", err)
		}
	})

	t.Run("Empty format", func(t *testing.T) {
		_, err := dispatcher.ReceiveCredential(types.Oid4vci, common.URIField{}, "", accessToken, nil, nil)
		if err == nil {
			t.Fatal("Expected error for empty format")
		}
	})

	t.Run("Plugin returns error", func(t *testing.T) {
		mock.shouldError = true
		_, err := dispatcher.ReceiveCredential(types.Oid4vci, common.URIField{}, "jwt_vc_json", accessToken, nil, nil)
		if err == nil {
			t.Fatal("Expected error when underlying plugin fails")
		}
		mock.shouldError = false
	})
}
