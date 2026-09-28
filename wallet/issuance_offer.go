package wallet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/trustknots/vcknots/wallet/common"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// ParseCredentialOfferURL parses a by-value Credential Offer URI
// (credential_offer query parameter). It performs no I/O.
func ParseCredentialOfferURL(rawURL string) (*CredentialOffer, error) {
	offerURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, invalidArgument("failed to parse credential offer URL: %w", err)
	}
	rawOffer := offerURL.Query().Get("credential_offer")
	if rawOffer == "" {
		return nil, invalidArgument("credential_offer query parameter is required")
	}
	offer, err := parseCredentialOfferJSON(rawOffer)
	if err != nil {
		return nil, invalidArgument("%w", err)
	}
	return offer, nil
}

// ResolveCredentialOffer resolves a Credential Offer URI in the by-value
// (credential_offer) or by-reference (credential_offer_uri) form of OpenID4VCI
// 1.0 Section 4.1. A by-reference offer is fetched with the receiver plugin's
// HTTP client; a URI carrying both parameters is refused.
func (w *Wallet) ResolveCredentialOffer(ctx context.Context, raw string) (*CredentialOffer, error) {
	offer, err := w.resolveCredentialOffer(ctx, raw)
	return offer, classify(err)
}

func (w *Wallet) resolveCredentialOffer(ctx context.Context, raw string) (*CredentialOffer, error) {
	offerURL, err := url.Parse(raw)
	if err != nil {
		return nil, invalidArgument("failed to parse credential offer URL: %w", err)
	}
	rawOffer := offerURL.Query().Get("credential_offer")
	rawOfferURI := offerURL.Query().Get("credential_offer_uri")
	switch {
	case rawOffer != "" && rawOfferURI != "":
		return nil, invalidArgument("credential offer must not contain both credential_offer and credential_offer_uri")
	case rawOffer != "":
		offer, err := parseCredentialOfferJSON(rawOffer)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidArgument, err)
		}
		return offer, nil
	case rawOfferURI == "":
		return nil, invalidArgument("credential_offer or credential_offer_uri query parameter is required")
	}
	offerURI, err := common.ParseURIField(rawOfferURI)
	if err != nil {
		return nil, invalidArgument("invalid credential_offer_uri: %w", err)
	}
	transport, err := w.receiver.OID4VCITransport(receiverTypes.Oid4vci)
	if err != nil {
		return nil, err
	}
	body, err := transport.FetchCredentialOffer(ctx, *offerURI)
	if err != nil {
		return nil, withCode(receiverTypes.ErrInvalidMetadata, err)
	}
	offer, err := parseCredentialOfferJSON(string(body))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", receiverTypes.ErrInvalidMetadata, err)
	}
	return offer, nil
}

// parseCredentialOfferJSON decodes a Credential Offer object.
func parseCredentialOfferJSON(rawOffer string) (*CredentialOffer, error) {
	var raw struct {
		CredentialIssuer           string                           `json:"credential_issuer"`
		CredentialConfigurationIDs []string                         `json:"credential_configuration_ids"`
		Grants                     map[string]*CredentialOfferGrant `json:"grants"`
	}
	if err := json.Unmarshal([]byte(rawOffer), &raw); err != nil {
		return nil, fmt.Errorf("failed to parse credential_offer JSON: %w", err)
	}
	issuer, err := url.Parse(raw.CredentialIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential issuer: %w", err)
	}
	return &CredentialOffer{
		CredentialIssuer:           issuer,
		CredentialConfigurationIDs: raw.CredentialConfigurationIDs,
		Grants:                     raw.Grants,
	}, nil
}

// offeredIssuance is what an offer names for one issuance.
type offeredIssuance struct {
	issuer          string
	configurationID string
	grant           *CredentialOfferGrant
	// grantFromMetadata records an offer without grants, whose
	// authorization_code grant is determined from the authorization server
	// metadata (checkOfferedAuthorizationCodeGrant); grant is then empty.
	grantFromMetadata bool
}

// fromOffer resolves the issuer, the selected configuration (requested, which
// must be offered, or the first) and the grant of grantType. An offer whose
// grants are absent or empty leaves the grant type to the metadata
// (OpenID4VCI 1.0 and Draft 13 Section 4.1.1), so it yields an empty
// authorization_code grant marked grantFromMetadata; a pre-authorized_code
// grant can only come from the offer.
func fromOffer(offer *CredentialOffer, requested, grantType string, grantMissing error) (offeredIssuance, error) {
	if offer.CredentialIssuer == nil || offer.CredentialIssuer.String() == "" {
		return offeredIssuance{}, invalidArgument("credential offer names no credential issuer")
	}
	if len(offer.CredentialConfigurationIDs) == 0 {
		return offeredIssuance{}, invalidArgument("credential offer lists no credential configuration")
	}
	configurationID := strings.TrimSpace(requested)
	if configurationID == "" {
		configurationID = offer.CredentialConfigurationIDs[0]
	} else if !slices.Contains(offer.CredentialConfigurationIDs, configurationID) {
		return offeredIssuance{}, fmt.Errorf("%w: credential configuration %q is not offered: %w", ErrInvalidArgument, configurationID, ErrUnknownCredentialConfiguration)
	}
	offered := offeredIssuance{issuer: offer.CredentialIssuer.String(), configurationID: configurationID}
	offered.grant, offered.grantFromMetadata = offerGrant(offer, grantType)
	if offered.grant == nil {
		return offeredIssuance{}, grantMissing
	}
	return offered, nil
}

// offerGrant returns the grant of grantType the offer names. An offer whose
// grants are absent or empty names none, and then OpenID4VCI 1.0 and Draft 13
// Section 4.1.1 say "the Wallet MUST determine the Grant Types the Credential
// Issuer's Authorization Server supports using the respective metadata": for
// the authorization_code grant, which needs no parameter from the offer,
// offerGrant returns an empty grant and fromMetadata. The caller checks the
// metadata with checkOfferedAuthorizationCodeGrant.
func offerGrant(offer *CredentialOffer, grantType string) (grant *CredentialOfferGrant, fromMetadata bool) {
	if len(offer.Grants) == 0 && grantType == string(receiverTypes.AuthorizationCode) {
		return &CredentialOfferGrant{}, true
	}
	return offer.Grants[grantType], false
}

// checkOfferedAuthorizationCodeGrant applies OpenID4VCI 1.0 and Draft 13
// Section 4.1.1 to an offer without grants: the authorization server metadata
// decides, and RFC 8414 Section 2 reads an absent grant_types_supported as
// ["authorization_code", "implicit"].
func checkOfferedAuthorizationCodeGrant(fromMetadata bool, as *receiverTypes.AuthorizationServerMetadata) error {
	if !fromMetadata || as.GrantTypesSupported == nil || slices.Contains(*as.GrantTypesSupported, receiverTypes.AuthorizationCode) {
		return nil
	}
	return fmt.Errorf("%w: the credential offer names no grant and the authorization server grant_types_supported %v lacks authorization_code",
		ErrAuthorizationCodeGrantUnsupported, *as.GrantTypesSupported)
}

// validateCredentialIssuerIdentifier applies the Credential Issuer Identifier
// rules: an https URL with a host and no query or fragment. Plain http is
// accepted only when allowHTTP is set.
func validateCredentialIssuerIdentifier(issuer *url.URL, allowHTTP bool) error {
	if issuer == nil {
		return fmt.Errorf("credential issuer is not included in the offer")
	}
	if issuer.Scheme == "" {
		return fmt.Errorf("credential issuer must include a scheme")
	}
	if !strings.EqualFold(issuer.Scheme, "https") && !(allowHTTP && strings.EqualFold(issuer.Scheme, "http")) {
		return fmt.Errorf("credential issuer must use https scheme")
	}
	if issuer.Host == "" {
		return fmt.Errorf("credential issuer must include a host")
	}
	if issuer.RawQuery != "" || issuer.ForceQuery || issuer.Fragment != "" || issuer.RawFragment != "" {
		return fmt.Errorf("credential issuer must not include query or fragment")
	}
	return nil
}

// validateOfferedConfigurations requires every offered configuration to be
// described by the issuer metadata.
func validateOfferedConfigurations(offer *CredentialOffer, md *receiverTypes.CredentialIssuerMetadata) error {
	if offer == nil {
		return fmt.Errorf("credential offer is required")
	}
	if md == nil {
		return fmt.Errorf("issuer metadata is required")
	}
	if len(md.CredentialConfigurationSupported) == 0 {
		return fmt.Errorf("credential configurations supported are missing in issuer metadata")
	}
	for _, configID := range offer.CredentialConfigurationIDs {
		if _, exists := md.CredentialConfigurationSupported[configID]; !exists {
			return fmt.Errorf("credential configuration %q is not supported by issuer metadata", configID)
		}
	}
	return nil
}
