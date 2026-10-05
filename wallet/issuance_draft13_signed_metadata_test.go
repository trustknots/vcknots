package wallet

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/experimental"
	"github.com/trustknots/vcknots/wallet/receiver"
	receiverOid4vci "github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// Draft 13 Section 11.2.3: signed metadata values "MUST take precedence over
// the corresponding values conveyed using plain JSON elements", and an issuer
// that enforces signed metadata omits or misstates them in the unsigned part.
// The Credential Request goes to the signed credential_endpoint.
func TestDraft13IssuanceUsesTheSignedMetadataInTheExchange(t *testing.T) {
	signerKey := newPrivateJWKForFinalVCITest(t, "metadata-signer")
	leaf, anchor := testLeafCertificateAndIssuer(t, signerKey, false)

	fixture := newDraft13Fixture(t)
	fixture.set(func(f *draft13Fixture) {
		f.issuerMetadataExtra = func(base string) map[string]any {
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: signerKey.Key},
				(&jose.SignerOptions{}).WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(leaf.Raw)}))
			require.NoError(t, err)
			compact, err := jwt.Signed(signer).Claims(map[string]any{
				"iss": "https://metadata-signer.example", "sub": base, "iat": time.Now().Add(-time.Minute).Unix(),
				"credential_endpoint": base + "/credential",
			}).Serialize()
			require.NoError(t, err)
			return map[string]any{"credential_endpoint": base + "/unsigned-credential", "signed_metadata": compact}
		}
	})
	plugin := &receiverOid4vci.Oid4vciReceiver{
		HTTPClient:   fixture.server.Client(),
		Experimental: experimental.Transport{AllowHTTP: true},
		IssuerMetadataSigning: &receiverOid4vci.IssuerMetadataSigningOptions{
			TrustAnchors: []*x509.Certificate{anchor}, AllowUnadvertisedRevocation: true,
		},
	}
	receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, plugin))
	require.NoError(t, err)
	w := fixture.newWallet(t, func(config *Config) { config.Receiver = receiving })

	grant := fixture.preAuthorize(t, w)
	result, err := w.Draft13().RequestCredential(context.Background(), grant, fixture.holder())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	require.Len(t, fixture.credentials(), 1, "the request reached the signed credential_endpoint")

	// Without trust anchors the wallet does not support signed metadata and
	// the unsigned credential_endpoint, which this issuer misstates, is used.
	unsigned := fixture.newWallet(t)
	grant = fixture.preAuthorize(t, unsigned)
	_, err = unsigned.Draft13().RequestCredential(context.Background(), grant, fixture.holder())
	require.Error(t, err)
	require.Len(t, fixture.credentials(), 1)
}
