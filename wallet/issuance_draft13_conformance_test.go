package wallet

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// RFC 6749 Section 7.1: "The client MUST NOT use an access token if it does
// not understand the token type", and Section 5.1 makes token_type REQUIRED.
// A Draft 13 grant is refused unless the token is Bearer, or DPoP with the
// wallet's DPoP key, before any Credential Request presents it.
func TestDraft13RefusesAnAccessTokenOfAnUnknownType(t *testing.T) {
	for name, test := range map[string]struct {
		tokenType any
		want      error
	}{
		"MAC":                     {"MAC", ErrTokenTypeUnsupported},
		"missing":                 {nil, ErrTokenTypeUnsupported},
		"empty":                   {"", ErrTokenTypeUnsupported},
		"DPoP without a DPoP key": {"DPoP", ErrDPoPRequired},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newDraft13Fixture(t)
			fixture.set(func(f *draft13Fixture) {
				f.tokenResponse = func(url.Values) (int, any) {
					body := map[string]any{"access_token": "access-1", "c_nonce": "nonce-1"}
					if test.tokenType != nil {
						body["token_type"] = test.tokenType
					}
					return http.StatusOK, body
				}
			})
			_, err := fixture.wallet.Draft13().AuthorizePreAuthorizedIssuance(context.Background(), fixture.preAuthorizedRequest())
			require.ErrorIs(t, err, test.want)
			require.Empty(t, fixture.credentials())
		})
	}

	fixture := newDraft13Fixture(t)
	grant := fixture.preAuthorize(t, fixture.wallet)
	require.Equal(t, "Bearer", grant.AccessToken.TokenType)
}

// Draft 13 Section 9.3: issuance_pending "SHOULD also contain the interval
// member ... If interval member is not present, the Wallet MUST use 5 as the
// default value." A long interval is kept as the issuer named it.
func TestDraft13IssuancePendingIntervalDefaultsToFiveSeconds(t *testing.T) {
	for name, test := range map[string]struct {
		body map[string]any
		want time.Duration
	}{
		"absent":  {map[string]any{"error": "issuance_pending"}, 5 * time.Second},
		"one day": {map[string]any{"error": "issuance_pending", "interval": 86400}, 24 * time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newDraft13Fixture(t)
			fixture.set(func(f *draft13Fixture) {
				f.credentialResponse = func(int, map[string]any) (int, any) {
					return http.StatusAccepted, map[string]any{"transaction_id": "transaction-1"}
				}
				f.deferredResponse = func(int) (int, any) { return http.StatusBadRequest, test.body }
			})
			result, err := fixture.receivePreAuthorized(t)
			require.NoError(t, err)
			pending, err := fixture.wallet.Draft13().RequestDeferredCredential(context.Background(), result.Deferred)
			require.NoError(t, err)
			require.Equal(t, test.want, pending.Deferred.Interval)
		})
	}
}

// Draft 13 Section 6.1: tx_code "MUST be present if a tx_code object was
// present in the Credential Offer (including if the object was empty)", and
// is only sent then. Both are refused before the pre-authorized code is spent.
func TestDraft13PreAuthorizedCodeChecksTheTransactionCode(t *testing.T) {
	fixture := newDraft13Fixture(t)
	missing := fixture.preAuthorizedRequest()
	missing.TxCode = ""
	_, err := fixture.wallet.Draft13().AuthorizePreAuthorizedIssuance(context.Background(), missing)
	require.ErrorIs(t, err, ErrTransactionCodeRequired)

	unexpected := fixture.preAuthorizedRequest()
	unexpected.CredentialOffer.Grants[string(receiverTypes.PreAuthorizedCode)].TxCode = nil
	_, err = fixture.wallet.Draft13().AuthorizePreAuthorizedIssuance(context.Background(), unexpected)
	require.ErrorIs(t, err, ErrInvalidArgument)
	require.Empty(t, fixture.tokens())
}
