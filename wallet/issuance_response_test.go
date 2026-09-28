package wallet

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// responseTestDecode decodes body with the bundled plugin as the transport,
// for a request that sent maxCredentials key proofs.
func responseTestDecode(body []byte, contentType string, key *jose.JSONWebKey, maxCredentials int) (*receiverTypes.CredentialResponse, error) {
	return decodeCredentialResponse(&oid4vci.Oid4vciReceiver{},
		&receiverTypes.CredentialEndpointHTTPResponse{Body: body, ContentType: contentType}, key, maxCredentials)
}

// responseTestEncrypt wraps payload in an application/jwt JWE addressed to key
// with ECDH-ES/A128GCM (OpenID4VCI 1.0 Section 8.3).
func responseTestEncrypt(t *testing.T, key jose.JSONWebKey, payload any) []byte {
	t.Helper()
	plaintext, err := json.Marshal(payload)
	require.NoError(t, err)
	encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: key.Public().Key}, nil)
	require.NoError(t, err)
	jwe, err := encrypter.Encrypt(plaintext)
	require.NoError(t, err)
	serialized, err := jwe.CompactSerialize()
	require.NoError(t, err)
	return []byte(serialized)
}

// responseTestEncryptionKey is an ECDH-ES response decryption key.
func responseTestEncryptionKey(t *testing.T, keyID string) jose.JSONWebKey {
	t.Helper()
	key := newPrivateJWKForFinalVCITest(t, keyID)
	key.Algorithm = "ECDH-ES"
	key.Use = "enc"
	return key
}

// The Section 8.3 credentials array of objects with a credential member is
// accepted, up to one credential per key proof.
func TestDecodeCredentialResponseAcceptsCredentialsArray(t *testing.T) {
	response, err := responseTestDecode([]byte(`{"credentials":[{"credential":"eyJ.abc.def"}]}`), "application/json", nil, 1)
	require.NoError(t, err)
	require.Len(t, response.Credentials, 1)

	response, err = responseTestDecode([]byte(`{"credentials":[{"credential":"eyJ.abc.def"},{"credential":"eyJ.ghi.jkl"}]}`), "application/json", nil, 2)
	require.NoError(t, err)
	require.Len(t, response.Credentials, 2)
}

// Every shape Section 8.3 does not allow is refused with a coded error.
func TestDecodeCredentialResponseRejectsInvalidShapes(t *testing.T) {
	for name, tc := range map[string]struct {
		body     string
		want     error
		contains string
	}{
		// Section 8.3 replaced the draft-era singular member with credentials.
		"removed singular credential": {`{"credential":"eyJ.abc.def"}`, ErrCredentialResponseShape, "singular credential member"},
		// "The elements of the array MUST be objects."
		"bare string element":             {`{"credentials":["eyJ.abc.def"]}`, ErrCredentialResponseShape, "not an object"},
		"element without credential":      {`{"credentials":[{"format":"dc+sd-jwt"}]}`, ErrCredentialResponseShape, "no credential member"},
		"transaction_id with credentials": {`{"transaction_id":"tx-1","credentials":[{"credential":"eyJ.abc.def"}]}`, ErrCredentialResponseShape, "transaction_id and credential content"},
		// One key proof was sent, so a second credential was never requested.
		"more credentials than proofs":           {`{"credentials":[{"credential":"eyJ.abc.def"},{"credential":"eyJ.ghi.jkl"}]}`, ErrCredentialResponseMultipleCredentials, "asked for 1"},
		"neither credentials nor transaction_id": {`{}`, ErrCredentialResponseShape, "neither credentials nor a transaction_id"},
		// "an array of one or more issued Credentials"
		"empty credentials array": {`{"credentials":[]}`, ErrCredentialResponseShape, "neither credentials nor a transaction_id"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := responseTestDecode([]byte(tc.body), "application/json", nil, 1)
			require.ErrorIs(t, err, tc.want)
			require.ErrorContains(t, err, tc.contains)
			code, ok := ErrorCode(err)
			require.True(t, ok)
			require.NotEqual(t, "unclassified", code)
		})
	}
}

// Section 8.2: a requested encryption is not downgraded; the wallet passes its
// JWK and the decoder refuses a plaintext answer.
func TestDecodeCredentialResponseWithKeyRejectsPlaintext(t *testing.T) {
	key := responseTestEncryptionKey(t, "response-enc-key-1")
	_, err := responseTestDecode([]byte(`{"credentials":[{"credential":"eyJ.abc.def"}]}`), "application/json", &key, 1)
	require.ErrorIs(t, err, ErrCredentialResponsePlaintext)
}

// A JWE addressed to another key cannot be decrypted.
func TestDecodeCredentialResponseRejectsUndecryptableJWE(t *testing.T) {
	addressee := responseTestEncryptionKey(t, "response-enc-key-1")
	body := responseTestEncrypt(t, addressee, map[string]any{
		"credentials": []any{map[string]any{"credential": "eyJ.abc.def"}},
	})
	otherKey := responseTestEncryptionKey(t, "response-enc-key-2")

	_, err := responseTestDecode(body, "application/jwt", &otherKey, 1)
	require.ErrorContains(t, err, "failed to decrypt credential response JWE")
	require.ErrorIs(t, err, ErrCredentialResponseDecrypt)
}

// An encrypted response is decrypted with the wallet's JWK and its plaintext
// is held to the same shape rules.
func TestDecodeCredentialResponseDecryptsEncryptedResponse(t *testing.T) {
	key := responseTestEncryptionKey(t, "response-enc-key-1")
	body := responseTestEncrypt(t, key, map[string]any{
		"credentials": []any{map[string]any{"credential": "eyJ.abc.def"}},
	})
	response, err := responseTestDecode(body, "application/jwt", &key, 1)
	require.NoError(t, err)
	require.Len(t, response.Credentials, 1)

	invalid := responseTestEncrypt(t, key, map[string]any{"credential": "eyJ.abc.def"})
	_, err = responseTestDecode(invalid, "application/jwt", &key, 1)
	require.ErrorIs(t, err, ErrCredentialResponseShape)
}

// The Section 9 deferred shape, a transaction_id without credentials, is
// accepted.
func TestValidateCredentialResponseAcceptsDeferredResponse(t *testing.T) {
	require.NoError(t, validateCredentialResponse(&receiverTypes.CredentialResponse{TransactionID: "tx-1", Interval: 5}, 1))
}

func TestValidateCredentialResponseRejectsNil(t *testing.T) {
	require.ErrorIs(t, validateCredentialResponse(nil, 1), ErrCredentialResponseShape)
}

// Section 8.3: notification_id only with credentials, interval only with a
// transaction_id.
func TestValidateCredentialResponseRejectsMembersOfTheOtherShape(t *testing.T) {
	err := validateCredentialResponse(&receiverTypes.CredentialResponse{TransactionID: "tx-1", Interval: 5, NotificationID: "n-1"}, 1)
	require.ErrorIs(t, err, ErrCredentialResponseShape)
	require.ErrorContains(t, err, "notification_id")

	err = validateCredentialResponse(&receiverTypes.CredentialResponse{
		Credentials: []any{map[string]any{"credential": "eyJ.abc.def"}},
		Interval:    5,
	}, 1)
	require.ErrorIs(t, err, ErrCredentialResponseShape)
	require.ErrorContains(t, err, "interval")
}

// A batch the request did not ask for is refused instead of storing a
// credential nobody requested.
func TestRequestCredentialRefusesMoreCredentialsThanHolderKeys(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.batchSize = 3
		secondCredential := f.issueCredential(f.additionalKey, map[string]string{"given_name": "Hanako"})
		f.credentialHandler = func(w http.ResponseWriter, _ *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{
				"credentials": []any{
					map[string]any{"credential": f.issuedCredential},
					map[string]any{"credential": secondCredential},
				},
			})
		}
	})
	_, err := fixture.receive(fixture.issuanceRequest())
	require.ErrorIs(t, err, ErrCredentialResponseMultipleCredentials)
	entries, _, err := fixture.wallet.GetCredentialEntries(GetCredentialEntriesRequest{})
	require.NoError(t, err)
	require.Empty(t, entries)
}

// The Credential Response is read in the strict Section 8.3 shape only.
func TestRequestCredentialRefusesDraftResponseShapes(t *testing.T) {
	for name, payload := range map[string]func(*finalIssuanceFixture) map[string]any{
		"singular credential member": func(f *finalIssuanceFixture) map[string]any {
			return map[string]any{"credential": f.issuedCredential}
		},
		"bare string element": func(f *finalIssuanceFixture) map[string]any {
			return map[string]any{"credentials": []any{f.issuedCredential}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
				f.credentialHandler = func(w http.ResponseWriter, _ *http.Request) {
					mockserver.JSONResponse(w, http.StatusOK, payload(f))
				}
			})
			result, err := fixture.receive(fixture.issuanceRequest())
			require.ErrorIs(t, err, ErrCredentialResponseShape)
			require.Nil(t, result)
		})
	}
}

// A 200 response with neither credentials nor a transaction_id issues
// nothing, on the credential and the deferred credential endpoint alike.
func TestRequestCredentialRefusesEmptySuccessResponse(t *testing.T) {
	for name, body := range map[string]map[string]any{
		"empty":                           {},
		"notification_id without content": {"notification_id": "notification-1"},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
				f.includeNotification = true
				f.credentialHandler = func(w http.ResponseWriter, _ *http.Request) {
					mockserver.JSONResponse(w, http.StatusOK, body)
				}
			})
			result, err := fixture.receive(fixture.issuanceRequest())
			require.ErrorIs(t, err, ErrCredentialResponseShape)
			require.Nil(t, result)
			require.Empty(t, fixture.notificationEvents)
		})
	}

	t.Run("deferred credential response", func(t *testing.T) {
		fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
			f.includeDeferredEndpoint = true
			f.credentialHandler = func(w http.ResponseWriter, _ *http.Request) {
				mockserver.JSONResponse(w, http.StatusAccepted, map[string]any{"transaction_id": "tx-1", "interval": 1})
			}
			f.deferredHandler = func(w http.ResponseWriter, _ *http.Request) {
				mockserver.JSONResponse(w, http.StatusOK, map[string]any{})
			}
		})
		result, err := fixture.receive(fixture.issuanceRequest())
		require.NoError(t, err)
		require.NotNil(t, result.Deferred)
		_, err = fixture.wallet.RequestDeferredCredential(context.Background(), result.Deferred)
		require.ErrorIs(t, err, ErrCredentialResponseShape)
		require.Equal(t, 1, fixture.deferredCalls)
	})
}

// The library reports the interval the issuer named, however long, and leaves
// the schedule to the caller.
func TestRequestCredentialReportsTheDeferredIntervalUnclamped(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeDeferredEndpoint = true
		f.credentialHandler = func(w http.ResponseWriter, _ *http.Request) {
			mockserver.JSONResponse(w, http.StatusAccepted, map[string]any{"transaction_id": "tx-1", "interval": 86400})
		}
	})
	result, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.NotNil(t, result.Deferred)
	require.Equal(t, 24*time.Hour, result.Deferred.Interval)
	require.Equal(t, 0, fixture.deferredCalls)
}
