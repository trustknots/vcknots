package receiver

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/env"
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

func (m *mockReceiver) FetchAccessToken(receivingType types.SupportedReceivingTypes, endpoint common.URIField, authzCode string, txCode string, opts ...types.TokenRequestOption) (*types.CredentialIssuanceAccessToken, error) {
	if m.shouldError {
		return nil, fmt.Errorf("mock error")
	}
	return &types.CredentialIssuanceAccessToken{}, nil
}

func (m *mockReceiver) FetchNonce(receivingType types.SupportedReceivingTypes, endpoint common.URIField) (*string, error) {
	if m.shouldError {
		return nil, fmt.Errorf("mock error")
	}
	nonce := "mock-nonce"
	return &nonce, nil
}

func (m *mockReceiver) ReceiveCredential(
	receivingType types.SupportedReceivingTypes,
	endpoint common.URIField,
	credentialConfigurationID string,
	credentialIdentifier *string,
	accessToken types.CredentialIssuanceAccessToken,
	credentialDefinition *types.CredentialDefinition,
	jwtProof *string,
	options ...*types.CredentialRequestOptions,
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
		_, err := dispatcher.FetchAccessToken(types.Oid4vci, common.URIField{}, "test-code", "")
		if err != nil {
			t.Errorf("FetchAccessToken() on happy path should not return error: %v", err)
		}
	})

	t.Run("Empty authzCode", func(t *testing.T) {
		_, err := dispatcher.FetchAccessToken(types.Oid4vci, common.URIField{}, "", "")
		if err == nil {
			t.Fatal("Expected error for empty authzCode")
		}
	})

	t.Run("Unsupported receiving type", func(t *testing.T) {
		invalidType := types.SupportedReceivingTypes(999)
		_, err := dispatcher.FetchAccessToken(invalidType, common.URIField{}, "test-code", "")
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
		_, err := dispatcher.ReceiveCredential(types.Oid4vci, common.URIField{}, "jwt_vc_json", nil, accessToken, nil, nil)
		if err != nil {
			t.Errorf("ReceiveCredential() on happy path should not return error: %v", err)
		}
	})

	t.Run("Empty credential configuration ID", func(t *testing.T) {
		_, err := dispatcher.ReceiveCredential(types.Oid4vci, common.URIField{}, "", nil, accessToken, nil, nil)
		if err == nil {
			t.Fatal("Expected error for empty credential configuration ID")
		}
	})

	t.Run("Credential identifier without configuration ID", func(t *testing.T) {
		credentialIdentifier := "cred-id-1"
		_, err := dispatcher.ReceiveCredential(types.Oid4vci, common.URIField{}, "", &credentialIdentifier, accessToken, nil, nil)
		if err != nil {
			t.Errorf("ReceiveCredential() with credential identifier should not return error: %v", err)
		}
	})

	t.Run("Plugin returns error", func(t *testing.T) {
		mock.shouldError = true
		_, err := dispatcher.ReceiveCredential(types.Oid4vci, common.URIField{}, "jwt_vc_json", nil, accessToken, nil, nil)
		if err == nil {
			t.Fatal("Expected error when underlying plugin fails")
		}
		mock.shouldError = false
	})
}

func TestReceivingDispatcher_TransportCapabilities(t *testing.T) {
	dispatcher, err := NewReceivingDispatcher(WithDefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if transport, err := dispatcher.OID4VCITransport(types.Oid4vci); err != nil || transport == nil {
		t.Fatalf("built-in OID4VCI transport: %v, %v", transport, err)
	}
	if transport, err := dispatcher.Draft13Transport(types.Oid4vci); err != nil || transport == nil {
		t.Fatalf("built-in Draft 13 transport: %v, %v", transport, err)
	}
	for _, protocol := range []types.SupportedReceivingTypes{types.Mock, types.SupportedReceivingTypes(999)} {
		transport, err := dispatcher.OID4VCITransport(protocol)
		if transport != nil || !errors.Is(err, types.ErrUnsupportedProtocol) {
			t.Errorf("protocol %v: expected no OID4VCI transport, got %v, %v", protocol, transport, err)
		}
		draft13, err := dispatcher.Draft13Transport(protocol)
		if draft13 != nil || !errors.Is(err, types.ErrUnsupportedProtocol) {
			t.Errorf("protocol %v: expected no Draft 13 transport, got %v, %v", protocol, draft13, err)
		}
	}
}

func TestReceivingDispatcher_DefaultHTTPPolicyIsCaptured(t *testing.T) {
	t.Setenv(env.DEBUG.String(), "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"credential_issuer":"http://%s","credential_endpoint":"http://%s/credential"}`, r.Host, r.Host)
	}))
	defer server.Close()
	endpoint, err := common.ParseURIField(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, allow := range []bool{false, true} {
		t.Run(fmt.Sprintf("allow_%t", allow), func(t *testing.T) {
			t.Setenv(env.HTTP_ALLOWED.String(), fmt.Sprint(allow))
			dispatcher, err := NewReceivingDispatcher(WithDefaultConfig())
			if err != nil {
				t.Fatal(err)
			}
			// Changing the process setting must not mutate an existing receiver policy.
			t.Setenv(env.HTTP_ALLOWED.String(), fmt.Sprint(!allow))
			_, err = dispatcher.FetchIssuerMetadata(*endpoint, types.Oid4vci)
			if allow && err != nil {
				t.Fatalf("explicitly allowed local HTTP: %v", err)
			}
			if !allow && err == nil {
				t.Fatal("HTTP must remain disabled")
			}
		})
	}
}
