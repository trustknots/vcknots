package oid4vci

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/trustknots/vcknots/wallet/profile"

	"github.com/trustknots/vcknots/wallet/common"
)

// dpopNonceServerKey identifies the server an RFC 9449 Section 8.2 DPoP nonce
// belongs to. Section 8.2 scopes a nonce to the server ("Clients should expect
// that a server will use the same nonce for all requests to that server"), not
// to a single endpoint path, so the key is the scheme and authority only. Both
// are compared case insensitively, as RFC 3986 Section 6.2.2.1 requires.
func dpopNonceServerKey(endpointURL url.URL) string {
	return strings.ToLower(endpointURL.Scheme) + "://" + strings.ToLower(endpointURL.Host)
}

// maxDPoPNonceServers bounds the servers a receiver keeps a DPoP nonce for.
const maxDPoPNonceServers = 32

type dpopNonceEntry struct {
	nonce    string
	lastUsed uint64
}

// dpopNonceCache holds the latest RFC 9449 Section 8.2 DPoP nonce of each
// server, keyed by scheme and authority, bounded to maxDPoPNonceServers
// entries (least recently used evicted).
type dpopNonceCache struct {
	entries map[string]dpopNonceEntry
	clock   uint64
}

// rememberDPoPNonce records the DPoP-Nonce a server sent (RFC 9449 Section
// 8.2) so the next proof for that server carries it. An empty value is
// ignored: a response without the header does not revoke a known nonce.
func (o *Oid4vciReceiver) rememberDPoPNonce(endpointURL url.URL, nonce string) {
	nonce = strings.TrimSpace(nonce)
	if nonce == "" {
		return
	}
	o.dpopNonceMu.Lock()
	defer o.dpopNonceMu.Unlock()
	o.storeDPoPNonceLocked(dpopNonceServerKey(endpointURL), nonce)
}

// dpopNonceFor returns the latest DPoP nonce held for the server endpointURL
// addresses, or "" when none is held.
func (o *Oid4vciReceiver) dpopNonceFor(endpointURL url.URL) string {
	o.dpopNonceMu.Lock()
	defer o.dpopNonceMu.Unlock()
	if o.dpopNonces == nil {
		return ""
	}
	cache := o.dpopNonces
	server := dpopNonceServerKey(endpointURL)
	entry, found := cache.entries[server]
	if !found {
		return ""
	}
	cache.clock++
	entry.lastUsed = cache.clock
	cache.entries[server] = entry
	return entry.nonce
}

// storeDPoPNonceLocked stores a nonce as the most recently used entry and
// evicts the least recently used one beyond maxDPoPNonceServers.
func (o *Oid4vciReceiver) storeDPoPNonceLocked(server, nonce string) {
	if o.dpopNonces == nil {
		o.dpopNonces = &dpopNonceCache{entries: make(map[string]dpopNonceEntry)}
	}
	cache := o.dpopNonces
	cache.clock++
	cache.entries[server] = dpopNonceEntry{nonce: nonce, lastUsed: cache.clock}
	if len(cache.entries) <= maxDPoPNonceServers {
		return
	}
	oldest := ""
	for candidate, entry := range cache.entries {
		if oldest == "" || entry.lastUsed < cache.entries[oldest].lastUsed {
			oldest = candidate
		}
	}
	delete(cache.entries, oldest)
}

// requireDPoPTokenType applies HAIP Section 4 (sender-constrained access
// tokens): under HAIP a token_type other than DPoP is ErrDPoPRequired.
func requireDPoPTokenType(normalized profile.Profile, tokenType string) error {
	if normalized.IsHAIP() && !strings.EqualFold(strings.TrimSpace(tokenType), dpopAuthorizationScheme) {
		return fmt.Errorf(
			"%w: HAIP requires a DPoP-bound access token, the token endpoint issued token_type %q",
			ErrDPoPRequired, tokenType)
	}
	return nil
}

// ErrDPoPRequired reports that a DPoP proof is required (RFC 9449) and the
// wallet cannot send one: a Bearer-token request answered with a DPoP
// challenge, a DPoP-bound token without a proof factory, or a non-DPoP token
// under HAIP.
var ErrDPoPRequired = common.NewCodedError("dpop_required", "credential endpoint requires DPoP")

// dpopAuthorizationScheme is the RFC 9449 Section 7.1 authentication scheme for
// a DPoP-bound access token.
const dpopAuthorizationScheme = "DPoP"

// authorizationScheme returns the Authorization scheme for token_type: DPoP
// (RFC 9449 Section 7.1) for a DPoP token, Bearer (RFC 6750) otherwise.
func authorizationScheme(tokenType string) string {
	if strings.EqualFold(strings.TrimSpace(tokenType), dpopAuthorizationScheme) {
		return dpopAuthorizationScheme
	}
	return "Bearer"
}
