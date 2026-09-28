package oid4vci

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// DiscoverDraft13CredentialIssuer resolves the OpenID4VCI Draft 13 Section 11.2
// Credential Issuer Metadata of issuer, a Credential Issuer Identifier. Draft
// 13 Section 11.2.2 forms the metadata URL by appending the well-known path to
// the identifier, after removing a terminating "/" from its path, and answers
// with application/json only. The document's credential_issuer must equal
// issuer. The receiver's OpenID4VCI 1.0 profile options do not apply.
//
// A signed_metadata member (Draft 13 Section 11.2.3) is verified when
// IssuerMetadataSigning configures trust anchors, the wallet's way of
// supporting signed metadata; its values then "MUST take precedence over the
// corresponding values conveyed using plain JSON elements", so the returned
// metadata - its endpoints and authorization_servers included - is the
// unsigned document overlaid with the verified claims. A signed_metadata the
// wallet cannot verify is an error: "The Wallet MUST establish trust in the
// signer of the metadata ... before processing the metadata". Without trust
// anchors the member is ignored and the unsigned values stand, unless
// IssuerMetadataSigning.Require demands signed metadata.
func (o *Oid4vciReceiver) DiscoverDraft13CredentialIssuer(ctx context.Context, issuer common.URIField) (*types.CredentialIssuerMetadata, error) {
	identifier := url.URL(issuer)
	if identifier.RawQuery != "" || identifier.Fragment != "" {
		return nil, stageError(StageIssuerMetadata, fmt.Errorf("%w: a Credential Issuer Identifier has no query or fragment", common.ErrInvalidInput))
	}
	requestURL := draft13IssuerMetadataURL(identifier)
	var metadata types.CredentialIssuerMetadata
	if err := o.fetchIssuerMetadataDocument(ctx, requestURL, identifier.String(), IssuerMetadataSigningOptions{}, profile.Options{}, &metadata); err != nil {
		return nil, stageError(StageIssuerMetadata, fmt.Errorf("failed to fetch issuer metadata: %w", err))
	}
	signing := IssuerMetadataSigningOptions{}
	if o.IssuerMetadataSigning != nil {
		signing = *o.IssuerMetadataSigning
	}
	if err := o.applyDraft13SignedMetadata(ctx, &metadata, identifier.String(), signing); err != nil {
		return nil, stageError(StageIssuerMetadata, fmt.Errorf("signed issuer metadata: %w", err))
	}
	return &metadata, nil
}

// draft13IssuerMetadataURL is the Draft 13 Section 11.2.2 metadata URL of a
// Credential Issuer Identifier: the identifier, without a terminating "/",
// followed by the well-known path.
func draft13IssuerMetadataURL(identifier url.URL) url.URL {
	metadataURL := identifier
	metadataURL.Path = strings.TrimSuffix(identifier.Path, "/") + wellKnownCredentialIssuer
	metadataURL.RawPath = ""
	return metadataURL
}

// draft13SignedMetadataRules: Draft 13 Section 11.2.3 requires iat, iss ("the
// party attesting to the claims") and sub, and defines no typ; the 1.0 typ
// openidvci-issuer-metadata+jwt is not required of a Draft 13 issuer.
var draft13SignedMetadataRules = signedMetadataRules{requireIss: true}

// applyDraft13SignedMetadata verifies the signed_metadata member of the
// unsigned document in metadata and, when it verifies, replaces metadata with
// the document whose values the signed claims take precedence over.
func (o *Oid4vciReceiver) applyDraft13SignedMetadata(ctx context.Context, metadata *types.CredentialIssuerMetadata, identifier string, signing IssuerMetadataSigningOptions) error {
	compact, err := draft13SignedMetadataMember(metadata.RawDocument)
	if err != nil {
		return err
	}
	trustConfigured := len(signing.TrustAnchors) > 0 || signing.RootCAs != nil
	switch {
	case signing.Require && !trustConfigured:
		return fmt.Errorf("%w: no trust anchors are configured", ErrIssuerMetadataSignatureRequired)
	case signing.Require && compact == "":
		return fmt.Errorf("%w: the Credential Issuer publishes no signed_metadata", ErrIssuerMetadataSignatureRequired)
	case compact == "" || !trustConfigured:
		// Section 11.2.3: "If the Wallet supports signed metadata" - a wallet
		// without trust material does not, and the unsigned values stand.
		return nil
	}
	verification, payload, err := o.verifySignedIssuerMetadata(ctx, compact, identifier, signing, profile.Options{}, draft13SignedMetadataRules)
	if err != nil {
		return err
	}
	merged, err := overlayDraft13SignedMetadata(metadata.RawDocument, payload)
	if err != nil {
		return err
	}
	var signed types.CredentialIssuerMetadata
	if err := json.Unmarshal(merged, &signed); err != nil {
		return fmt.Errorf("%w: failed to parse the signed metadata claims: %w", ErrIssuerMetadataSignatureInvalid, err)
	}
	if err := requireMatchingCredentialIssuer(signed.CredentialIssuer, identifier); err != nil {
		return err
	}
	signed.SignedMetadata = compact
	signed.MetadataSignature = verification
	signed.RawDocument = merged
	*metadata = signed
	return nil
}

// draft13SignedMetadataMember returns the signed_metadata member of an
// unsigned Draft 13 document, or "" when it has none. Section 11.2.3 makes it
// a string.
func draft13SignedMetadataMember(document json.RawMessage) (string, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(document, &members); err != nil {
		return "", fmt.Errorf("failed to parse issuer metadata: %w", err)
	}
	raw, ok := members["signed_metadata"]
	if !ok || string(raw) == "null" {
		return "", nil
	}
	var compact string
	if err := json.Unmarshal(raw, &compact); err != nil {
		return "", fmt.Errorf("%w: signed_metadata is not a string", ErrIssuerMetadataSignatureInvalid)
	}
	return strings.TrimSpace(compact), nil
}

// signedMetadataJWTClaims are the JWT claims of a Draft 13 signed_metadata
// that attest the metadata rather than being metadata parameters.
var signedMetadataJWTClaims = map[string]bool{"iss": true, "sub": true, "iat": true, "exp": true, "nbf": true, "jti": true, "aud": true}

// overlayDraft13SignedMetadata returns the unsigned document with each
// metadata parameter of the verified payload in place of the plain JSON value
// (Draft 13 Section 11.2.3: signed values "MUST take precedence"). The
// signed_metadata member is dropped from the result, and a payload that
// carries one is refused: "A signed_metadata metadata value MUST NOT appear
// as a claim in the JWT."
func overlayDraft13SignedMetadata(unsigned json.RawMessage, payload []byte) ([]byte, error) {
	var document, claims map[string]json.RawMessage
	if err := json.Unmarshal(unsigned, &document); err != nil {
		return nil, fmt.Errorf("failed to parse issuer metadata: %w", err)
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: failed to parse the payload: %w", ErrIssuerMetadataSignatureInvalid, err)
	}
	if _, ok := claims["signed_metadata"]; ok {
		return nil, fmt.Errorf("%w: signed_metadata must not appear as a claim in the JWT", ErrIssuerMetadataSignatureInvalid)
	}
	delete(document, "signed_metadata")
	for name, value := range claims {
		if !signedMetadataJWTClaims[name] {
			document[name] = value
		}
	}
	return json.Marshal(document)
}
