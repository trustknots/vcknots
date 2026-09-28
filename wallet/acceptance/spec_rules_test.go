package acceptance

import (
	"crypto/ecdsa"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/internal/testutil"
	"github.com/trustknots/vcknots/wallet/profile"
)

// signedClaims is an SD-JWT VC with exactly claims, signed by key with the
// given typ and extra header members, and no Disclosures.
func signedClaims(t *testing.T, key *ecdsa.PrivateKey, typ string, header map[string]any, claims map[string]any) string {
	t.Helper()
	options := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	for name, value := range header {
		options = options.WithHeader(jose.HeaderKey(name), value)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, options)
	require.NoError(t, err)
	signed, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return signed + "~"
}

// baseClaims are the claims of a valid SD-JWT VC bound to holder.
func baseClaims(holder jose.JSONWebKey) map[string]any {
	return map[string]any{
		"iss": "https://issuer.example.test",
		"vct": "urn:test:acceptance",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
		"cnf": map[string]any{"jwk": holder.Public()},
	}
}

// SD-JWT VC -19 §2.2.1: "The typ value MUST use dc+sd-jwt". OpenID4VCI Draft
// 13 issuers use the earlier vc+sd-jwt, which only profile.Draft13 admits.
func TestVerifySDJWTVCTypFollowsTheProfile(t *testing.T) {
	holder := newHolderKey(t)
	issuerKey := testutil.NewP256Key(t)
	for _, test := range []struct {
		profile  profile.Profile
		typ      string
		accepted bool
	}{
		{profile.Final(), "dc+sd-jwt", true},
		{profile.Final(), "vc+sd-jwt", false},
		{profile.HAIP(), "vc+sd-jwt", false},
		{profile.Draft13(), "vc+sd-jwt", true},
		{profile.Draft13(), "dc+sd-jwt", true},
		{profile.Draft13(), "JWT", false},
	} {
		t.Run(test.profile.String()+" "+test.typ, func(t *testing.T) {
			raw := signedClaims(t, issuerKey, test.typ, nil, baseClaims(holder))
			_, _, err := newTestAcceptor(t, test.profile).Parse([]byte(raw), sdJWT(&holder))
			if test.accepted {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrCredentialTypInvalid)
		})
	}
}

// SD-JWT VC -19 §2.2.2.3: "vct: REQUIRED", a string.
func TestVerifySDJWTVCRequiresVCT(t *testing.T) {
	holder := newHolderKey(t)
	issuerKey := testutil.NewP256Key(t)
	for name, vct := range map[string]any{"absent": nil, "empty": "", "not a string": 7} {
		t.Run(name, func(t *testing.T) {
			claims := baseClaims(holder)
			delete(claims, "vct")
			if vct != nil {
				claims["vct"] = vct
			}
			raw := signedClaims(t, issuerKey, "dc+sd-jwt", nil, claims)
			for _, p := range []profile.Profile{profile.Final(), profile.Draft13()} {
				_, _, err := newTestAcceptor(t, p).Parse([]byte(raw), sdJWT(&holder))
				require.ErrorIs(t, err, ErrCredentialTypInvalid)
				require.True(t, strings.Contains(err.Error(), "vct"))
			}
		})
	}
}
