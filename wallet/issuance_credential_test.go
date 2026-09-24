package wallet

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/attestation"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
)

// credentialTestKeyAttester is a StaticKeyAttester with a fresh key.
func credentialTestKeyAttester(t *testing.T) (*attestation.StaticKeyAttester, jose.JSONWebKey) {
	t.Helper()
	key := newPrivateJWKForFinalVCITest(t, "key-attester-1")
	return &attestation.StaticKeyAttester{Key: testKeyEntry(t, key), Issuer: "https://key-attester.example"}, key
}

// credentialTestAttestedKeys decodes the attested_keys claim of a key
// attestation JWT.
func credentialTestAttestedKeys(t *testing.T, claims map[string]any) []jose.JSONWebKey {
	t.Helper()
	encoded, err := json.Marshal(claims["attested_keys"])
	require.NoError(t, err)
	var keys []jose.JSONWebKey
	require.NoError(t, json.Unmarshal(encoded, &keys))
	return keys
}

// credentialTestDeferredFixture answers the Credential Request with a
// transaction_id.
func credentialTestDeferredFixture(t *testing.T, opts ...func(*finalIssuanceFixture)) *finalIssuanceFixture {
	t.Helper()
	deferred := func(f *finalIssuanceFixture) {
		f.includeDeferredEndpoint = true
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusAccepted, map[string]any{"transaction_id": "tx-1"})
		}
	}
	return newFinalIssuanceFixture(t, append([]func(*finalIssuanceFixture){deferred}, opts...)...)
}

func TestRequestCredential_NoNonceEndpointProofOmitsNonce(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeNonceEndpoint = false
	})
	result, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	require.Equal(t, 0, fixture.nonceCalls)
	claims := finalProofClaims(t, fixture.proofJWTs(t)[0])
	_, hasNonce := claims["nonce"]
	require.False(t, hasNonce)
}

// Section 8.3.1.2: an invalid_nonce refusal fetches a fresh c_nonce and the
// Credential Request is sent once more.
func TestRequestCredential_InvalidNonceRetriedOnce(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.nonceHandler = func(w http.ResponseWriter, r *http.Request) {
			nonce := "credential-nonce-1"
			if f.nonceCalls > 1 {
				nonce = "credential-nonce-2"
			}
			mockserver.JSONResponse(w, http.StatusOK, map[string]string{"c_nonce": nonce})
		}
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			if f.credentialCalls == 1 {
				mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_nonce"})
				return
			}
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"credentials": []any{map[string]any{"credential": f.issuedCredential}}})
		}
	})
	result, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	require.Equal(t, 2, fixture.credentialCalls)
	require.Equal(t, 2, fixture.nonceCalls)
	require.Equal(t, "credential-nonce-2", finalProofClaims(t, fixture.proofJWTs(t)[0])["nonce"])
}

// An issuer that requires response encryption is refused before the
// authorization request when the holder's policy disables encryption.
func TestBeginIssuance_RequiredEncryptionDisabledByPolicy(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.responseEncryption = true
		f.encryptionRequired = true
		f.requestEncryption = true
		f.encryptionPolicy = CredentialEncryptionPolicy{Response: CredentialEncryptionDisabled}
	})
	_, err := fixture.wallet.BeginIssuance(context.Background(), fixture.issuanceRequest())
	require.ErrorIs(t, err, ErrCredentialEncryptionDisallowed)
	require.ErrorContains(t, err, "encryption")
	require.Equal(t, 0, fixture.parCalls)
	require.Equal(t, 0, fixture.credentialCalls)
}

// A Credential Request that asked for an encrypted response refuses a
// plaintext one.
func TestRequestCredential_RequestedEncryptionPlaintextResponseFailsClosed(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.responseEncryption = true
		f.requestEncryption = true
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"credentials": []any{map[string]any{"credential": f.issuedCredential}}})
		}
	})
	_, err := fixture.receive(fixture.issuanceRequest())
	require.ErrorIs(t, err, ErrCredentialResponsePlaintext)
	require.Equal(t, 1, fixture.credentialCalls)
	require.NotNil(t, fixture.lastCredentialBody["credential_response_encryption"])
}

// Section 8.2 lets the wallet send credential_response_encryption only inside
// an encrypted Credential Request. An issuer that offers response encryption
// without requiring it, and offers no request encryption, is served
// plaintext.
func TestRequestCredential_OptionalResponseEncryptionWithoutRequestEncryption(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.responseEncryption = true
		f.encryptionRequired = false
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"credentials": []any{map[string]any{"credential": f.issuedCredential}}})
		}
	})
	result, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	_, requested := fixture.lastCredentialBody["credential_response_encryption"]
	require.False(t, requested)
}

// An issuer that requires response encryption but offers no request
// encryption cannot be served under Section 8.2; the issuance stops before the
// authorization request.
func TestBeginIssuance_RequiredResponseEncryptionWithoutRequestEncryption(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.responseEncryption = true
		f.encryptionRequired = true
	})
	_, err := fixture.wallet.BeginIssuance(context.Background(), fixture.issuanceRequest())
	require.ErrorIs(t, err, ErrCredentialEncryptionUnavailable)
	require.Equal(t, 0, fixture.parCalls)
	require.Equal(t, 0, fixture.credentialCalls)
}

func TestRequestCredential_BatchWithTwoKeys(t *testing.T) {
	secondCredential := ""
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.batchSize = 3
		secondCredential = f.issueCredential(f.additionalKey, map[string]string{"given_name": "Hanako"})
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{
				"credentials": []any{map[string]any{"credential": f.issuedCredential}, map[string]any{"credential": secondCredential}},
			})
		}
	})
	result, err := fixture.receiveWith(fixture.issuanceRequest(), CredentialRequest{HolderKeys: []IKeyEntry{fixture.holderEntry, fixture.additionalEntry}})
	require.NoError(t, err)
	require.Len(t, fixture.proofJWTs(t), 2)
	require.Len(t, result.Credentials, 2)
	require.Equal(t, []byte(fixture.issuedCredential), result.Credentials[0].Entry.Raw)
	require.Equal(t, []byte(secondCredential), result.Credentials[1].Entry.Raw)
}

func TestRequestCredential_BatchExceedsBatchSize(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.batchSize = 1
	})
	_, err := fixture.receiveWith(fixture.issuanceRequest(), CredentialRequest{HolderKeys: []IKeyEntry{fixture.holderEntry, fixture.additionalEntry}})
	require.ErrorIs(t, err, ErrInvalidArgument)
	require.ErrorContains(t, err, "batch_size")
	require.Equal(t, 0, fixture.credentialCalls)
}

func TestRequestCredential_KeyAttestationRequiredWithProvider(t *testing.T) {
	attester, _ := credentialTestKeyAttester(t)
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.keyAttestationsRequired = true
		f.keyAttestation = attester
	})
	result, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)

	proofs := fixture.proofJWTs(t)
	require.Len(t, proofs, 1)
	header := finalProofHeader(t, proofs[0])
	keyAttestationJWT, ok := header["key_attestation"].(string)
	require.True(t, ok, "proof header is missing key_attestation: %#v", header)

	attestationHeader, err := jwsHeader(keyAttestationJWT)
	require.NoError(t, err)
	require.Equal(t, "key-attestation+jwt", attestationHeader["typ"])
	claims, err := jwsClaims(keyAttestationJWT)
	require.NoError(t, err)
	require.Equal(t, "credential-nonce-1", claims["nonce"])
	attested := credentialTestAttestedKeys(t, claims)
	require.Len(t, attested, 1)
	require.NoError(t, requireJWKThumbprint(fixture.holderKey, attested[0]))
}

// Without an attestation source the Credential Request is not sent; the error
// tells the caller what to have signed.
func TestRequestCredential_KeyAttestationRequiredWithoutProvider(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.keyAttestationsRequired = true
	})
	grant, err := fixture.authorize(fixture.issuanceRequest())
	require.NoError(t, err)
	require.True(t, grant.KeyAttestationRequired)

	_, err = fixture.wallet.RequestCredential(context.Background(), grant, fixture.credentialRequest())
	require.ErrorIs(t, err, ErrKeyAttestationRequired)
	var required *KeyAttestationRequiredError
	require.True(t, errors.As(err, &required), "err = %v", err)
	require.True(t, required.IssuerRequired)
	require.False(t, required.NonceRejected)
	require.Equal(t, "credential-nonce-1", required.CNonce)
	require.Equal(t, fixture.server.URL, required.Audience)
	require.Len(t, required.HolderKeys, 1)
	require.NoError(t, requireJWKThumbprint(fixture.holderKey, required.HolderKeys[0]))
	require.Equal(t, 0, fixture.credentialCalls)
	code, _ := ErrorCode(err)
	require.Equal(t, "key_attestation_required", code)
}

func TestRequestCredential_KeyAttestationProviderMissingHolderKey(t *testing.T) {
	attester, attesterKey := credentialTestKeyAttester(t)
	otherKey := newPrivateJWKForFinalVCITest(t, "other-holder-key-1")
	keyAttestation, err := attester.KeyAttestation(context.Background(),
		attestation.KeyRequest{Keys: []jose.JSONWebKey{otherKey}, Nonce: "credential-nonce-1"})
	require.NoError(t, err)
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.keyAttestationsRequired = true
		f.keyAttestation = fixedKeyAttestationProvider{attestation: keyAttestation}
		// The provider is not a bundled attester, so the wallet is told which
		// key signs its attestations.
		f.attestationTrust = attestation.TrustPolicy{ResolveKey: func(attestation.JOSEHeader) (any, error) {
			return attesterKey.Public().Key, nil
		}}
	})

	_, err = fixture.receive(fixture.issuanceRequest())
	require.ErrorContains(t, err, "does not attest the holder key")
	require.Equal(t, 0, fixture.credentialCalls)
}

// An attestation the wallet cannot authenticate (no x5c chain and no
// configured resolver) never reaches the Credential Request.
func TestRequestCredential_KeyAttestationUnauthenticatable(t *testing.T) {
	attester, _ := credentialTestKeyAttester(t)
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.keyAttestationsRequired = true
		keyAttestation, err := attester.KeyAttestation(context.Background(),
			attestation.KeyRequest{Keys: []jose.JSONWebKey{f.holderKey}, Nonce: "credential-nonce-1"})
		require.NoError(t, err)
		f.keyAttestation = fixedKeyAttestationProvider{attestation: keyAttestation}
	})

	_, err := fixture.receive(fixture.issuanceRequest())
	require.ErrorContains(t, err, "cannot be authenticated")
	require.Equal(t, 0, fixture.credentialCalls)
}

func TestRequestCredential_IncludeKeyAttestationWhenNotRequired(t *testing.T) {
	attester, _ := credentialTestKeyAttester(t)
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.keyAttestation = attester
	})
	request := fixture.credentialRequest()
	request.IncludeKeyAttestation = true
	_, err := fixture.receiveWith(fixture.issuanceRequest(), request)
	require.NoError(t, err)

	header := finalProofHeader(t, fixture.proofJWTs(t)[0])
	require.Contains(t, header, "key_attestation")
}

// Section 9.2: issuance_pending leaves the transaction pending with the
// interval the issuer named; the next Deferred Credential Request issues it.
// The library makes one request per call and does not wait.
func TestRequestDeferredCredential_PendingIntervalThenSuccess(t *testing.T) {
	fixture := credentialTestDeferredFixture(t, func(f *finalIssuanceFixture) {
		f.deferredHandler = func(w http.ResponseWriter, r *http.Request) {
			if f.deferredCalls == 1 {
				mockserver.JSONResponse(w, http.StatusBadRequest, map[string]any{"error": "issuance_pending", "interval": 1})
				return
			}
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"credentials": []any{map[string]any{"credential": f.issuedCredential}}})
		}
	})
	ctx := context.Background()
	result, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.NotNil(t, result.Deferred)

	pending, err := fixture.wallet.RequestDeferredCredential(ctx, result.Deferred)
	require.NoError(t, err)
	require.NotNil(t, pending.Deferred)
	require.Empty(t, pending.Credentials)
	require.Equal(t, time.Second, pending.Deferred.Interval)
	require.Equal(t, "tx-1", pending.Deferred.TransactionID)
	require.Equal(t, 1, fixture.deferredCalls)

	issued, err := fixture.wallet.RequestDeferredCredential(ctx, pending.Deferred)
	require.NoError(t, err)
	require.Nil(t, issued.Deferred)
	require.Len(t, issued.Credentials, 1)
	require.Equal(t, 2, fixture.deferredCalls)
	require.Equal(t, "tx-1", fixture.lastDeferredBody["transaction_id"])
}

// A deferred Credential Response returns the transaction to resume later; no
// Deferred Credential Request is sent until the caller asks.
func TestRequestCredential_DeferredPendingThenResume(t *testing.T) {
	fixture := credentialTestDeferredFixture(t)
	result, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.NotNil(t, result.Deferred)
	require.Equal(t, "tx-1", result.Deferred.TransactionID)
	require.NotNil(t, result.Deferred.AccessToken)
	require.Equal(t, "pid", result.Deferred.CredentialConfigurationID)
	require.Equal(t, fixture.server.URL, result.Deferred.CredentialIssuer)
	require.Len(t, result.Deferred.HolderKeys, 1)
	require.Empty(t, result.Credentials)
	require.Equal(t, 0, fixture.deferredCalls)

	resumed, err := fixture.newWallet(t).RequestDeferredCredential(context.Background(), result.Deferred)
	require.NoError(t, err)
	require.Len(t, resumed.Credentials, 1)
	require.Equal(t, 1, fixture.deferredCalls)
	require.Equal(t, "tx-1", fixture.lastDeferredBody["transaction_id"])
}

// Refused credentials come back with the error and the notification, so the
// caller can report credential_failure; the library sends nothing itself.
func TestRequestCredential_NotificationFailureOnInvalidCredential(t *testing.T) {
	otherKey := newPrivateJWKForFinalVCITest(t, "other-holder-key")
	badCredential := buildTestSDJWTVC(t, otherKey, map[string]string{"given_name": "Taro"})
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeNotification = true
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{
				"credentials":     []any{map[string]any{"credential": badCredential}},
				"notification_id": "notification-1",
			})
		}
	})
	result, err := fixture.receive(fixture.issuanceRequest())
	require.Error(t, err)
	require.NotNil(t, result)
	require.Empty(t, result.Credentials)
	require.NotNil(t, result.Notification)
	require.Equal(t, "notification-1", result.Notification.NotificationID)
	require.Empty(t, fixture.notificationEvents)

	require.NoError(t, fixture.wallet.NotifyIssuer(context.Background(), result.Notification, NotificationCredentialFailure, ""))
	require.Equal(t, []string{"credential_failure"}, fixture.notificationEvents)
}

func TestRequestCredential_NotificationAcceptedAfterStoreAndDeleted(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeNotification = true
	})
	ctx := context.Background()
	result, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	require.NotNil(t, result.Notification)
	require.Equal(t, "notification-1", result.Notification.NotificationID)
	require.Empty(t, fixture.notificationEvents)

	require.NoError(t, fixture.wallet.NotifyIssuer(ctx, result.Notification, NotificationCredentialAccepted, ""))
	require.Equal(t, []string{"credential_accepted"}, fixture.notificationEvents)

	require.NoError(t, fixture.wallet.NotifyIssuer(ctx, result.Notification, NotificationCredentialDeleted, ""))
	require.Equal(t, []string{"credential_accepted", "credential_deleted"}, fixture.notificationEvents)
	require.Equal(t, "notification-1", fixture.notificationBodies[1]["notification_id"])
}

// OpenID4VCI 1.0 Section 8.3: each credentials entry is an object whose
// credential member carries the issued credential.
func TestRawCredentialBytesUnwrapsFinalCredentialsEnvelope(t *testing.T) {
	raw, err := rawCredentialBytes(map[string]any{"credential": "eyJ.abc.def~"})
	require.NoError(t, err)
	require.Equal(t, "eyJ.abc.def~", string(raw))

	raw, err = rawCredentialBytes(map[string]any{"credential": map[string]any{"kind": "object"}})
	require.NoError(t, err)
	require.JSONEq(t, `{"kind":"object"}`, string(raw))

	raw, err = rawCredentialBytes(map[string]any{"credential": "x", "other": 1})
	require.NoError(t, err)
	require.JSONEq(t, `{"credential":"x","other":1}`, string(raw))
}

// OpenID4VCI 1.0 Section 8.3 does not fix the order of the credentials array.
// Each credential is matched to the holder key its cnf names.
func TestRequestCredential_BatchCredentialsMayArriveOutOfOrder(t *testing.T) {
	var secondCredential string
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.batchSize = 3
		secondCredential = f.issueCredential(f.additionalKey, map[string]string{"given_name": "Hanako"})
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{
				"credentials": []map[string]any{{"credential": secondCredential}, {"credential": f.issuedCredential}},
			})
		}
	})
	result, err := fixture.receiveWith(fixture.issuanceRequest(), CredentialRequest{HolderKeys: []IKeyEntry{fixture.holderEntry, fixture.additionalEntry}})
	require.NoError(t, err)
	require.Len(t, result.Credentials, 2)
	require.Equal(t, []byte(secondCredential), result.Credentials[0].Entry.Raw)
	require.Equal(t, []byte(fixture.issuedCredential), result.Credentials[1].Entry.Raw)
	require.True(t, result.Credentials[0].Verification.HolderBound)
	require.True(t, result.Credentials[1].Verification.HolderBound)
}

// A credential bound to a key that was not part of the request is refused and
// nothing is stored.
func TestRequestCredential_BatchCredentialForForeignKeyIsRefused(t *testing.T) {
	stranger := newPrivateJWKForFinalVCITest(t, "stranger")
	var strangerCredential string
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.batchSize = 3
		strangerCredential = f.issueCredential(stranger, map[string]string{"given_name": "X"})
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{
				"credentials": []map[string]any{{"credential": f.issuedCredential}, {"credential": strangerCredential}},
			})
		}
	})
	_, err := fixture.receiveWith(fixture.issuanceRequest(), CredentialRequest{HolderKeys: []IKeyEntry{fixture.holderEntry, fixture.additionalEntry}})
	require.ErrorIs(t, err, acceptance.ErrHolderBindingMismatch)
	require.ErrorContains(t, err, "not part of the request")
	entries, total, err := fixture.wallet.GetCredentialEntries(GetCredentialEntriesRequest{})
	require.NoError(t, err)
	require.Empty(t, entries)
	require.Zero(t, total)
}
