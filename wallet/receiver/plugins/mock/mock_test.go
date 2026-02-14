package mock

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

func TestMockReceiver_FetchIssuerMetadata(t *testing.T) {
	receiver := NewMockReceiver("/tmp")
	endpoint, _ := common.ParseURIField("mock://test")

	// Test with correct receiving type
	metadata, err := receiver.FetchIssuerMetadata(*endpoint, types.Mock)
	require.NoError(t, err)
	assert.NotNil(t, metadata)
	assert.Equal(t, "mock://issuer", metadata.CredentialIssuer)

	// Test with incorrect receiving type
	_, err = receiver.FetchIssuerMetadata(*endpoint, types.Oid4vci)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported receiving type")
}

func TestMockReceiver_FetchAuthorizationServerMetadata(t *testing.T) {
	receiver := NewMockReceiver("/tmp")
	endpoint, _ := common.ParseURIField("mock://test")

	// Test with correct receiving type
	metadata, err := receiver.FetchAuthorizationServerMetadata(*endpoint, types.Mock)
	require.NoError(t, err)
	assert.NotNil(t, metadata)
	assert.Equal(t, "mock://issuer", metadata.Issuer.String())

	// Test with incorrect receiving type
	_, err = receiver.FetchAuthorizationServerMetadata(*endpoint, types.Oid4vci)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported receiving type")
}

func TestMockReceiver_FetchAccessToken(t *testing.T) {
	receiver := NewMockReceiver("/tmp")
	endpoint, _ := common.ParseURIField("mock://test")

	// Test with correct receiving type
	token, err := receiver.FetchAccessToken(types.Mock, *endpoint, "test_code")
	require.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, "mock_access_token", token.Token)
	assert.Equal(t, "Bearer", token.TokenType)
	assert.Equal(t, 3600, token.ExpiresIn)

	// Test with incorrect receiving type
	_, err = receiver.FetchAccessToken(types.Oid4vci, *endpoint, "test_code")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported receiving type")
}

func TestMockReceiver_ReceiveCredential(t *testing.T) {
	// Create temporary directory for test files
	tempDir, err := os.MkdirTemp("", "mock_receiver_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create test VC file
	testVC := `{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": ["VerifiableCredential"],
  "issuer": "did:example:issuer",
  "issuanceDate": "2023-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:holder",
    "name": "Test User"
  }
}`
	testFilePath := filepath.Join(tempDir, "test_vc.txt")
	err = os.WriteFile(testFilePath, []byte(testVC), 0644)
	require.NoError(t, err)

	receiver := NewMockReceiver(tempDir)
	endpoint, _ := common.ParseURIField("mock://test_vc")
	accessToken := types.CredentialIssuanceAccessToken{
		Token:     "test_token",
		TokenType: "Bearer",
		ExpiresIn: 3600,
	}

	// Test with correct receiving type
	credential, err := receiver.ReceiveCredential(
		types.Mock,
		*endpoint,
		"jwt_vc_json",
		accessToken,
		nil,
		nil,
	)
	require.NoError(t, err)
	assert.NotNil(t, credential)
	assert.Equal(t, testVC, *credential)

	// Test with incorrect receiving type
	_, err = receiver.ReceiveCredential(
		types.Oid4vci,
		*endpoint,
		"jwt_vc_json",
		accessToken,
		nil,
		nil,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported receiving type")

	// Test with non-existent file
	nonExistentEndpoint, _ := common.ParseURIField("mock://non_existent")
	_, err = receiver.ReceiveCredential(
		types.Mock,
		*nonExistentEndpoint,
		"jwt_vc_json",
		accessToken,
		nil,
		nil,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read VC file")
}

func TestMockReceiver_ReceiveCredential_WithExtension(t *testing.T) {
	// Test that .txt extension is automatically added
	tempDir, err := os.MkdirTemp("", "mock_receiver_test_ext")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	testVC := "test credential content"
	testFilePath := filepath.Join(tempDir, "test.txt")
	err = os.WriteFile(testFilePath, []byte(testVC), 0644)
	require.NoError(t, err)

	receiver := NewMockReceiver(tempDir)
	endpoint, _ := common.ParseURIField("mock://test.txt")
	accessToken := types.CredentialIssuanceAccessToken{
		Token:     "test_token",
		TokenType: "Bearer",
		ExpiresIn: 3600,
	}

	// Test with .txt extension in endpoint
	credential, err := receiver.ReceiveCredential(
		types.Mock,
		*endpoint,
		"jwt_vc_json",
		accessToken,
		nil,
		nil,
	)
	require.NoError(t, err)
	assert.NotNil(t, credential)
	assert.Equal(t, testVC, *credential)
}