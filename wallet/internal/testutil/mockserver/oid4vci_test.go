package mockserver

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateClientAssertionTimeClaims(t *testing.T) {
	const (
		clientID = "wallet-id"
		audience = "https://authorization-server.example.com"
	)

	keyPair := MustGenerateKeyPair("client-key")
	builder := MustNewJWTBuilder(keyPair)
	publicKey := keyPair.CreatePublicJWK()
	server := &OID4VCIIssuerServer{
		config: &OID4VCIIssuerConfig{
			ClientAuthPublicKey:     &publicKey,
			ExpectedClientID:        clientID,
			ClientAssertionAudience: audience,
		},
	}

	tests := []struct {
		name       string
		expiration int64
		notBefore  int64
		wantErr    string
	}{
		{
			name:       "valid",
			expiration: time.Now().Add(time.Minute).Unix(),
			notBefore:  time.Now().Add(-time.Minute).Unix(),
		},
		{
			name:       "expired",
			expiration: time.Now().Add(-time.Minute).Unix(),
			wantErr:    "client_assertion has expired",
		},
		{
			name:       "expires now",
			expiration: time.Now().Unix(),
			wantErr:    "client_assertion has expired",
		},
		{
			name:       "missing",
			expiration: 0,
			wantErr:    "client_assertion exp is required",
		},
		{
			name:       "not valid yet",
			expiration: time.Now().Add(time.Minute).Unix(),
			notBefore:  time.Now().Add(time.Minute).Unix(),
			wantErr:    "client_assertion is not yet valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertion, err := builder.CreateSignedJWT(clientID, map[string]interface{}{
				"sub": clientID,
				"aud": audience,
				"exp": tt.expiration,
				"nbf": tt.notBefore,
			})
			require.NoError(t, err)

			form := url.Values{
				"client_id":             {clientID},
				"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
				"client_assertion":      {assertion},
			}
			req, err := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			err = server.validateClientAssertion(req)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}
