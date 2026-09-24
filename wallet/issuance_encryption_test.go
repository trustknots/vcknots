package wallet

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// encryptionTestMetadata is issuer metadata advertising request and response
// encryption as asked.
func encryptionTestMetadata(request bool, response bool, required bool) *receiverTypes.CredentialIssuerMetadata {
	metadata := &receiverTypes.CredentialIssuerMetadata{}
	if request {
		metadata.CredentialRequestEncryption = &receiverTypes.CredentialRequestEncryption{}
	}
	if response {
		metadata.CredentialResponseEncryption = &receiverTypes.CredentialResponseEncryption{EncValuesSupported: []string{"A128GCM"}, EncryptionRequired: &required}
	}
	return metadata
}

// The zero policy follows the issuer metadata, with a fresh ephemeral key per
// issuance.
func TestCredentialEncryptionPolicyFollowsIssuerByDefault(t *testing.T) {
	policy := CredentialEncryptionPolicy{}

	key, err := policy.responseEncryptionKey(encryptionTestMetadata(true, true, false))
	require.NoError(t, err)
	require.NotNil(t, key, "an issuer advertising response encryption gets an ephemeral key")
	require.False(t, key.IsPublic())
	other, err := policy.responseEncryptionKey(encryptionTestMetadata(true, true, false))
	require.NoError(t, err)
	require.NotEqual(t, key.Public(), other.Public(), "each issuance gets its own key")

	key, err = policy.responseEncryptionKey(encryptionTestMetadata(false, false, false))
	require.NoError(t, err)
	require.Nil(t, key, "an issuer advertising no response encryption is not asked for one")

	// Section 8.2: the response key travels only in an encrypted request.
	key, err = policy.responseEncryptionKey(encryptionTestMetadata(false, true, false))
	require.NoError(t, err)
	require.Nil(t, key)
}

// A required encryption the issuer cannot provide is refused.
func TestCredentialEncryptionPolicyRequired(t *testing.T) {
	requestOnly := CredentialEncryptionPolicy{Request: CredentialEncryptionRequired}
	_, err := requestOnly.responseEncryptionKey(encryptionTestMetadata(false, true, false))
	require.ErrorIs(t, err, ErrCredentialEncryptionUnavailable)

	responseOnly := CredentialEncryptionPolicy{Response: CredentialEncryptionRequired}
	_, err = responseOnly.responseEncryptionKey(encryptionTestMetadata(true, false, false))
	require.ErrorIs(t, err, ErrCredentialEncryptionUnavailable)

	// Section 8.2 needs request encryption to carry the response key, so an
	// issuer offering only the response half cannot satisfy the policy.
	_, err = responseOnly.responseEncryptionKey(encryptionTestMetadata(false, true, false))
	require.ErrorIs(t, err, ErrCredentialEncryptionUnavailable)

	key, err := responseOnly.responseEncryptionKey(encryptionTestMetadata(true, true, false))
	require.NoError(t, err)
	require.NotNil(t, key)
}

// A disabled encryption refuses rather than downgrades.
func TestCredentialEncryptionPolicyDisabled(t *testing.T) {
	disabled := CredentialEncryptionPolicy{Response: CredentialEncryptionDisabled}
	_, err := disabled.responseEncryptionKey(encryptionTestMetadata(true, true, true))
	require.ErrorIs(t, err, ErrCredentialEncryptionDisallowed)

	key, err := disabled.responseEncryptionKey(encryptionTestMetadata(false, true, false))
	require.NoError(t, err)
	require.Nil(t, key, "a disabled response encryption asks for no key")

	disabledRequest := CredentialEncryptionPolicy{Request: CredentialEncryptionDisabled}
	_, err = disabledRequest.responseEncryptionKey(encryptionTestMetadata(true, false, false))
	require.ErrorIs(t, err, ErrCredentialEncryptionDisallowed)
}

// The policy is applied at the first stage, before the authorization request
// or the pre-authorized code is spent.
func TestCredentialEncryptionPolicyRequiredFailsBeforeAnyRequest(t *testing.T) {
	requireResponse := func(f *finalIssuanceFixture) {
		f.encryptionPolicy = CredentialEncryptionPolicy{Response: CredentialEncryptionRequired}
	}
	t.Run("authorization code", func(t *testing.T) {
		fixture := newFinalIssuanceFixture(t, requireResponse)
		_, err := fixture.wallet.BeginIssuance(context.Background(), fixture.issuanceRequest())
		require.ErrorIs(t, err, ErrCredentialEncryptionUnavailable)
		require.Equal(t, 0, fixture.parCalls)
		require.Equal(t, 0, fixture.credentialCalls)
	})
	t.Run("pre-authorized code", func(t *testing.T) {
		fixture := newFinalIssuanceFixture(t, requireResponse)
		_, err := fixture.wallet.AuthorizePreAuthorizedIssuance(context.Background(), fixture.tokenTestPreAuthorizedRequest(nil))
		require.ErrorIs(t, err, ErrCredentialEncryptionUnavailable)
		require.Equal(t, 0, fixture.tokenCalls)
	})
}

// An issuer that makes response encryption mandatory is refused by a holder
// who disabled it.
func TestCredentialEncryptionPolicyDisabledAgainstRequiringIssuer(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.responseEncryption = true
		f.encryptionRequired = true
		f.requestEncryption = true
		f.encryptionPolicy = CredentialEncryptionPolicy{Response: CredentialEncryptionDisabled}
	})
	_, err := fixture.wallet.BeginIssuance(context.Background(), fixture.issuanceRequest())
	require.ErrorIs(t, err, ErrCredentialEncryptionDisallowed)
	require.Equal(t, 0, fixture.parCalls)
	require.Equal(t, 0, fixture.credentialCalls)
}

// With the issuer advertising both encryptions the default policy encrypts the
// request and asks for an encrypted response to a fresh key.
func TestCredentialEncryptionFollowsTheIssuerEndToEnd(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.responseEncryption = true
		f.requestEncryption = true
	})
	result, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	require.Contains(t, fixture.lastCredentialBody, "credential_response_encryption")
	require.Contains(t, fixture.credentialHeaders.Get("Content-Type"), "application/jwt")
}

// Response encryption follows what the issuer can decrypt to and the wallet can
// read: an optional one that no listed alg or enc allows is not requested, a
// required one is refused before the grant is spent, and a key-wrapping ECDH
// alg is used when it is the one listed.
func TestCredentialResponseEncryptionNegotiatesTheAlgorithm(t *testing.T) {
	encryption := func(algValues, encValues []string, required bool, policy CredentialEncryptionPolicy) func(*finalIssuanceFixture) {
		return func(f *finalIssuanceFixture) {
			f.responseEncryption = true
			f.requestEncryption = true
			f.encryptionRequired = required
			f.responseAlgValues = algValues
			f.responseEncValues = encValues
			f.encryptionPolicy = policy
		}
	}
	for name, test := range map[string]struct {
		algValues, encValues []string
	}{
		"only an RSA alg":     {algValues: []string{"RSA-OAEP-256"}},
		"only an unknown alg": {algValues: []string{"ECDH-1PU"}},
		"only an unknown enc": {algValues: []string{"ECDH-ES"}, encValues: []string{"XC20P"}},
	} {
		t.Run("optional with "+name+" is not requested", func(t *testing.T) {
			fixture := newFinalIssuanceFixture(t, encryption(test.algValues, test.encValues, false, CredentialEncryptionPolicy{}))
			result, err := fixture.receive(fixture.issuanceRequest())
			require.NoError(t, err)
			require.Len(t, result.Credentials, 1)
			require.NotContains(t, fixture.lastCredentialBody, "credential_response_encryption")
		})
		t.Run("required with "+name+" is refused before the token request", func(t *testing.T) {
			fixture := newFinalIssuanceFixture(t, encryption(test.algValues, test.encValues, true, CredentialEncryptionPolicy{}))
			_, err := fixture.wallet.AuthorizePreAuthorizedIssuance(context.Background(), fixture.tokenTestPreAuthorizedRequest(nil))
			require.ErrorIs(t, err, ErrCredentialEncryptionUnavailable)
			require.Equal(t, 0, fixture.tokenCalls)
		})
		t.Run("required by the holder with "+name+" is refused before the token request", func(t *testing.T) {
			fixture := newFinalIssuanceFixture(t, encryption(test.algValues, test.encValues, false, CredentialEncryptionPolicy{Response: CredentialEncryptionRequired}))
			_, err := fixture.wallet.AuthorizePreAuthorizedIssuance(context.Background(), fixture.tokenTestPreAuthorizedRequest(nil))
			require.ErrorIs(t, err, ErrCredentialEncryptionUnavailable)
			require.Equal(t, 0, fixture.tokenCalls)
		})
	}

	t.Run("required ECDH-ES+A128KW is used end to end", func(t *testing.T) {
		fixture := newFinalIssuanceFixture(t, encryption([]string{"RSA-OAEP-256", "ECDH-ES+A128KW"}, nil, true, CredentialEncryptionPolicy{}))
		result, err := fixture.receive(fixture.issuanceRequest())
		require.NoError(t, err)
		require.Len(t, result.Credentials, 1)
		requested, _ := fixture.lastCredentialBody["credential_response_encryption"].(map[string]any)
		jwk, _ := requested["jwk"].(map[string]any)
		require.Equal(t, "ECDH-ES+A128KW", jwk["alg"])
		require.Contains(t, fixture.credentialHeaders.Get("Content-Type"), "application/jwt")
	})
}
