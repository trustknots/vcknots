package wallet

import (
	"context"
	"fmt"

	"github.com/trustknots/vcknots/wallet/common"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// issuanceDiscovery is the metadata one stage resolved.
type issuanceDiscovery struct {
	issuerMetadata *receiverTypes.CredentialIssuerMetadata
	// asMetadata is nil for a stage that does not talk to the authorization
	// server.
	asMetadata *receiverTypes.AuthorizationServerMetadata
	// authorizationServer is the RFC 8414 issuer identifier of asMetadata, or
	// of the pinned server a credential stage checked.
	authorizationServer string
}

// issuanceMetadataCache keeps the metadata a stage resolved on the state it
// returned, so the next stage in the same process skips the fetch. It is not
// serialized; a state read from JSON re-discovers.
type issuanceMetadataCache struct {
	owner               *Wallet
	credentialIssuer    string
	issuerMetadata      *receiverTypes.CredentialIssuerMetadata
	authorizationServer string
	asMetadata          *receiverTypes.AuthorizationServerMetadata
}

// lookup returns the cached metadata when owner resolved it for
// credentialIssuer and, with needAS, for authorizationServer.
func (c *issuanceMetadataCache) lookup(owner *Wallet, credentialIssuer, authorizationServer string, needAS bool) *issuanceDiscovery {
	if c == nil || c.owner != owner || c.credentialIssuer != credentialIssuer || c.issuerMetadata == nil {
		return nil
	}
	if needAS && (c.asMetadata == nil || c.authorizationServer != authorizationServer) {
		return nil
	}
	discovery := &issuanceDiscovery{issuerMetadata: c.issuerMetadata, authorizationServer: authorizationServer}
	if needAS {
		discovery.asMetadata = c.asMetadata
	}
	return discovery
}

func (w *Wallet) newIssuanceMetadataCache(discovery *issuanceDiscovery) *issuanceMetadataCache {
	return &issuanceMetadataCache{
		owner:               w,
		credentialIssuer:    discovery.issuerMetadata.CredentialIssuer,
		issuerMetadata:      discovery.issuerMetadata,
		authorizationServer: discovery.authorizationServer,
		asMetadata:          discovery.asMetadata,
	}
}

// authorizationServerSelector picks the authorization server from the issuer
// metadata; issuer is the Credential Issuer Identifier.
type authorizationServerSelector func(md *receiverTypes.CredentialIssuerMetadata, issuer common.URIField) (common.URIField, error)

// offeredAuthorizationServer selects by the grant's authorization_server hint,
// which must be listed in authorization_servers (OpenID4VCI 1.0 Section
// 4.1.1); without one it takes the first listed server, or the issuer itself
// when none is listed (Section 12.2.4).
func offeredAuthorizationServer(hint string) authorizationServerSelector {
	return func(md *receiverTypes.CredentialIssuerMetadata, issuer common.URIField) (common.URIField, error) {
		if hint != "" {
			for _, server := range md.AuthorizationServers {
				if server.String() == hint {
					return server, nil
				}
			}
			return common.URIField{}, invalidMetadata("authorization_server %q is not listed in the issuer metadata authorization_servers", hint)
		}
		if len(md.AuthorizationServers) > 0 {
			return md.AuthorizationServers[0], nil
		}
		return issuer, nil
	}
}

// pinnedAuthorizationServer selects the server a state recorded; it must
// still be one the issuer delegates to.
func pinnedAuthorizationServer(authorizationServer string) authorizationServerSelector {
	return func(md *receiverTypes.CredentialIssuerMetadata, issuer common.URIField) (common.URIField, error) {
		if len(md.AuthorizationServers) == 0 && authorizationServer == issuer.String() {
			return issuer, nil
		}
		for _, server := range md.AuthorizationServers {
			if server.String() == authorizationServer {
				return server, nil
			}
		}
		return common.URIField{}, fmt.Errorf("authorization server %q is not one the credential issuer delegates to: %w", authorizationServer, ErrIssuanceStateMismatch)
	}
}

// discoverIssuance resolves the Credential Issuer metadata of issuer, whose
// credential_issuer must equal it (Section 12.2.4), and selects the
// authorization server. With needAS it also resolves the server's metadata,
// whose issuer must equal the selected identifier (RFC 8414 Section 3.3).
func (w *Wallet) discoverIssuance(
	ctx context.Context,
	transport receiverTypes.IssuerDiscovery,
	cache *issuanceMetadataCache,
	issuer string,
	selectServer authorizationServerSelector,
	needAS bool,
) (*issuanceDiscovery, error) {
	issuerEndpoint, err := common.ParseURIField(issuer)
	if err != nil {
		return nil, invalidArgument("credential issuer %q: %w", issuer, err)
	}
	var issuerMetadata *receiverTypes.CredentialIssuerMetadata
	if cached := cache.lookup(w, issuer, "", false); cached != nil {
		issuerMetadata = cached.issuerMetadata
	} else {
		issuerMetadata, err = transport.DiscoverCredentialIssuer(ctx, *issuerEndpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch issuer metadata: %w", err)
		}
		if issuerMetadata == nil {
			return nil, invalidMetadata("issuer metadata is nil")
		}
	}
	if issuerMetadata.CredentialIssuer != issuer {
		return nil, fmt.Errorf("credential issuer metadata identifier %q does not match the credential issuer %q: %w",
			issuerMetadata.CredentialIssuer, issuer, ErrIssuerIdentifierMismatch)
	}
	server, err := selectServer(issuerMetadata, *issuerEndpoint)
	if err != nil {
		return nil, err
	}
	discovery := &issuanceDiscovery{issuerMetadata: issuerMetadata, authorizationServer: server.String()}
	if !needAS {
		return discovery, nil
	}
	if cached := cache.lookup(w, issuer, discovery.authorizationServer, true); cached != nil {
		return cached, nil
	}
	asMetadata, err := transport.DiscoverAuthorizationServer(ctx, server)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch authorization server metadata: %w", err)
	}
	if asMetadata == nil {
		return nil, invalidMetadata("authorization server metadata is nil")
	}
	if asMetadata.Issuer.String() != discovery.authorizationServer {
		return nil, invalidMetadata("authorization server metadata issuer %q does not match the selected authorization server %q",
			asMetadata.Issuer.String(), discovery.authorizationServer)
	}
	discovery.asMetadata = asMetadata
	return discovery, nil
}

// credentialConfiguration returns the configuration id names; Section 12.2.4
// makes credential_configurations_supported the complete list.
func credentialConfiguration(md *receiverTypes.CredentialIssuerMetadata, id string) (receiverTypes.CredentialConfiguration, error) {
	config, ok := md.CredentialConfigurationSupported[id]
	if !ok {
		return receiverTypes.CredentialConfiguration{}, fmt.Errorf(
			"credential issuer %q does not offer credential_configuration_id %q: %w",
			md.CredentialIssuer, id, ErrUnknownCredentialConfiguration)
	}
	return config, nil
}
