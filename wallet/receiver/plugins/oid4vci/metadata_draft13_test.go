package oid4vci

import (
	"crypto/x509"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// draft13SignedDocument is an unsigned Draft 13 document whose endpoints the
// unsigned part omits or names differently, carrying signed claims.
func draft13SignedDocument(t *testing.T, fixture signedMetadataFixture, typ string, adjust func(identifier string, claims map[string]any)) func(identifier string) (string, string) {
	return func(identifier string) (string, string) {
		claims := map[string]any{
			"iss":                   "https://attester.example",
			"sub":                   identifier,
			"iat":                   time.Now().Add(-time.Minute).Unix(),
			"credential_issuer":     identifier,
			"credential_endpoint":   identifier + "/signed-credential",
			"authorization_servers": []string{identifier + "/signed-as"},
		}
		if adjust != nil {
			adjust(identifier, claims)
		}
		document := map[string]any{
			"credential_issuer": identifier,
			// Section 11.2.3: an issuer enforcing signed metadata omits the
			// parameter from the unsigned part; this one names another value.
			"credential_endpoint":          identifier + "/unsigned-credential",
			"deferred_credential_endpoint": identifier + "/deferred",
			"credential_configurations_supported": map[string]any{
				"degree": map[string]any{"format": "vc+sd-jwt", "vct": "degree"},
			},
			"signed_metadata": fixture.signWithType(t, typ, claims, []*x509.Certificate{fixture.leaf}),
		}
		body, err := json.Marshal(document)
		require.NoError(t, err)
		return "application/json", string(body)
	}
}

// Draft 13 Section 11.2.3: "If the Wallet supports signed metadata, metadata
// values conveyed in the signed JWT MUST take precedence over the
// corresponding values conveyed using plain JSON elements." The endpoints and
// authorization_servers the flow uses are the signed ones; the unsigned values
// stand where no claim overrides them. Draft 13 defines no typ, so a plain JWT
// verifies.
func TestDraft13SignedMetadataTakesPrecedenceInTheReturnedMetadata(t *testing.T) {
	fixture := newSignedMetadataFixture(t)
	serverURL, client, _ := serveIssuerMetadata(t, false, draft13SignedDocument(t, fixture, "JWT", nil))
	receiver := signedMetadataReceiver(client, fixture, nil)

	metadata, err := receiver.DiscoverDraft13CredentialIssuer(t.Context(), mustURIField(t, serverURL))
	require.NoError(t, err)
	require.Equal(t, serverURL+"/signed-credential", metadata.CredentialEndpoint.String())
	require.Len(t, metadata.AuthorizationServers, 1)
	require.Equal(t, serverURL+"/signed-as", metadata.AuthorizationServers[0].String())
	require.Equal(t, serverURL+"/deferred", metadata.DeferredCredentialEndpoint.String(), "an unsigned value no claim overrides stands")
	require.NotNil(t, metadata.MetadataSignature)
	require.NotEmpty(t, metadata.SignedMetadata)

	var document map[string]any
	require.NoError(t, json.Unmarshal(metadata.RawDocument, &document))
	require.Equal(t, serverURL+"/signed-credential", document["credential_endpoint"])
	require.NotContains(t, document, "signed_metadata")
	require.NotContains(t, document, "iat", "the JWT claims that attest the metadata are not metadata")
}

// Section 11.2.3: "The Wallet MUST establish trust in the signer of the
// metadata ... before processing the metadata": a signature the configured
// anchors do not authenticate, a missing iss, a sub for another issuer, or a
// signed_metadata claim inside the JWT stops the discovery.
func TestDraft13SignedMetadataMustVerify(t *testing.T) {
	fixture := newSignedMetadataFixture(t)
	for name, adjust := range map[string]func(identifier string, claims map[string]any){
		"missing iss":            func(_ string, claims map[string]any) { delete(claims, "iss") },
		"missing iat":            func(_ string, claims map[string]any) { delete(claims, "iat") },
		"sub of another issuer":  func(_ string, claims map[string]any) { claims["sub"] = "https://other.example" },
		"nested signed_metadata": func(_ string, claims map[string]any) { claims["signed_metadata"] = "x" },
		"expired":                func(_ string, claims map[string]any) { claims["exp"] = time.Now().Add(-time.Minute).Unix() },
		"credential_issuer of another issuer": func(_ string, claims map[string]any) {
			claims["credential_issuer"] = "https://other.example"
		},
	} {
		t.Run(name, func(t *testing.T) {
			serverURL, client, _ := serveIssuerMetadata(t, false, draft13SignedDocument(t, fixture, "JWT", adjust))
			_, err := signedMetadataReceiver(client, fixture, nil).DiscoverDraft13CredentialIssuer(t.Context(), mustURIField(t, serverURL))
			if name == "credential_issuer of another issuer" {
				require.ErrorIs(t, err, ErrIssuerIdentifierMismatch)
				return
			}
			require.ErrorIs(t, err, ErrIssuerMetadataSignatureInvalid)
		})
	}

	t.Run("signer outside the anchors", func(t *testing.T) {
		other := newSignedMetadataFixture(t)
		serverURL, client, _ := serveIssuerMetadata(t, false, draft13SignedDocument(t, fixture, "JWT", nil))
		_, err := signedMetadataReceiver(client, other, nil).DiscoverDraft13CredentialIssuer(t.Context(), mustURIField(t, serverURL))
		require.ErrorIs(t, err, ErrIssuerMetadataSignatureInvalid)
	})
}

// A wallet without trust anchors does not support signed metadata (Section
// 11.2.3 "If the Wallet supports signed metadata"): the unsigned values stand,
// and nothing claims the metadata was verified. Require makes signed metadata
// mandatory.
func TestDraft13SignedMetadataWithoutTrustAnchors(t *testing.T) {
	fixture := newSignedMetadataFixture(t)
	serverURL, client, _ := serveIssuerMetadata(t, false, draft13SignedDocument(t, fixture, "JWT", nil))
	receiver := signedMetadataReceiver(client, fixture, func(signing *IssuerMetadataSigningOptions) { signing.TrustAnchors = nil })

	metadata, err := receiver.DiscoverDraft13CredentialIssuer(t.Context(), mustURIField(t, serverURL))
	require.NoError(t, err)
	require.Equal(t, serverURL+"/unsigned-credential", metadata.CredentialEndpoint.String())
	require.Nil(t, metadata.MetadataSignature)
	require.Empty(t, metadata.SignedMetadata, "SignedMetadata names only a verified signature")

	required := signedMetadataReceiver(client, fixture, func(signing *IssuerMetadataSigningOptions) { signing.TrustAnchors = nil; signing.Require = true })
	_, err = required.DiscoverDraft13CredentialIssuer(t.Context(), mustURIField(t, serverURL))
	require.ErrorIs(t, err, ErrIssuerMetadataSignatureRequired)
}

func TestDraft13SignedMetadataRequireRefusesAnUnsignedDocument(t *testing.T) {
	fixture := newSignedMetadataFixture(t)
	serverURL, client, _ := serveIssuerMetadata(t, false, func(identifier string) (string, string) {
		body, _ := json.Marshal(map[string]any{"credential_issuer": identifier, "credential_endpoint": identifier + "/credential"})
		return "application/json", string(body)
	})
	receiver := signedMetadataReceiver(client, fixture, func(signing *IssuerMetadataSigningOptions) { signing.Require = true })
	_, err := receiver.DiscoverDraft13CredentialIssuer(t.Context(), mustURIField(t, serverURL))
	require.ErrorIs(t, err, ErrIssuerMetadataSignatureRequired)

	lenient := signedMetadataReceiver(client, fixture, nil)
	metadata, err := lenient.DiscoverDraft13CredentialIssuer(t.Context(), mustURIField(t, serverURL))
	require.NoError(t, err)
	require.Nil(t, metadata.MetadataSignature)
}

// The 1.0 unsigned document is not a Draft 13 one: a signed_metadata member in
// it is not verified, and SignedMetadata stays empty.
func TestFinalUnsignedDocumentDoesNotReportAnUnverifiedSignedMetadata(t *testing.T) {
	fixture := newSignedMetadataFixture(t)
	serverURL, client, _ := serveIssuerMetadata(t, false, draft13SignedDocument(t, fixture, "JWT", nil))
	metadata, err := signedMetadataReceiver(client, fixture, func(signing *IssuerMetadataSigningOptions) { signing.Request = false }).
		DiscoverCredentialIssuer(t.Context(), mustURIField(t, serverURL))
	require.NoError(t, err)
	require.Empty(t, metadata.SignedMetadata)
	require.Nil(t, metadata.MetadataSignature)
	endpoint := url.URL(metadata.CredentialEndpoint)
	require.Equal(t, "/unsigned-credential", endpoint.Path)
}
