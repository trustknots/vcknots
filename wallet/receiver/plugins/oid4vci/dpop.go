package oid4vci

import (
	"fmt"
	"strings"

	"github.com/trustknots/vcknots/wallet/profile"

	"github.com/trustknots/vcknots/wallet/common"
)

// dpopNonceKey identifies the nonces an RFC 9449 DPoP proof may carry: the
// server, its role and the proof key.
//
//   - Section 8.2 scopes a nonce to the server ("Clients should expect that a
//     server will use the same nonce for all requests to that server"), not to
//     an endpoint path, so the server is the scheme and authority, compared
//     case insensitively (RFC 3986 Section 6.2.2.1).
//   - Section 9: "the nonces provided by an authorization server and a
//     resource server are different and should not be confused with one
//     another", which holds even when both share an origin.
//   - A nonce is sent with one key only: a server that saw two keys answer the
//     same nonce could link them.
//
// An empty keyThumbprint marks an unattributed nonce: one a response carried
// before any key asked for it, such as the DPoP-Nonce of an OpenID4VCI 1.0
// Section 7.2 Nonce Response. The first key that asks the same server role
// claims it, in place of any older nonce that key held, and no other key sees
// it afterwards.
type dpopNonceKey struct {
	server         string
	resourceServer bool
	keyThumbprint  string
}

// dpopNonceKey is the key of the nonces ex's proofs carry. ok is false when ex
// has neither a keyed prover nor is a nonce source, so nothing is kept for it.
func (ex exchange) dpopNonceKey() (key dpopNonceKey, ok bool) {
	key = dpopNonceKey{
		server:         strings.ToLower(ex.url.Scheme) + "://" + strings.ToLower(ex.url.Host),
		resourceServer: ex.resourceServer,
	}
	if ex.dpop.Proof != nil && ex.dpop.KeyThumbprint != "" {
		key.keyThumbprint = ex.dpop.KeyThumbprint
		return key, true
	}
	return key, ex.dpopNonceSource
}

// maxDPoPNonceServers bounds the (server, role, key) entries a receiver keeps
// a DPoP nonce for.
const maxDPoPNonceServers = 32

// rememberDPoPNonce records the DPoP-Nonce a response to ex carried (RFC 9449
// Section 8.2) so the next proof ex's key builds for the same server role
// carries it. An empty value is ignored: a response without the header does
// not revoke a known nonce. A response to an exchange without a keyed prover
// is kept only when the exchange is a nonce source, as an unattributed nonce.
func (o *Oid4vciReceiver) rememberDPoPNonce(ex exchange, nonce string) {
	nonce = strings.TrimSpace(nonce)
	key, ok := ex.dpopNonceKey()
	if nonce == "" || !ok {
		return
	}
	o.dpopNonceMu.Lock()
	defer o.dpopNonceMu.Unlock()
	if o.dpopNonces == nil {
		o.dpopNonces = newRecentValues[dpopNonceKey](maxDPoPNonceServers)
	}
	o.dpopNonces.put(key, nonce)
}

// dpopNonceFor returns the latest DPoP nonce for ex's key, or "" when none
// is held. An unattributed nonce of the same server role is newer than the
// key's own: it was issued after the key's last exchange with that role (any
// exchange of the key would have claimed it), such as the DPoP-Nonce of the
// Nonce Response fetched after an invalid_nonce. The key claims it, in place
// of its own, and it is then no longer offered to another key. OpenID4VCI 1.0
// Section 7.2: "the Wallet uses the new nonce value in the DPoP proof".
func (o *Oid4vciReceiver) dpopNonceFor(ex exchange) string {
	key, ok := ex.dpopNonceKey()
	if !ok || key.keyThumbprint == "" {
		return ""
	}
	o.dpopNonceMu.Lock()
	defer o.dpopNonceMu.Unlock()
	if o.dpopNonces == nil {
		return ""
	}
	unattributed := key
	unattributed.keyThumbprint = ""
	if nonce, found := o.dpopNonces.take(unattributed); found {
		o.dpopNonces.put(key, nonce)
		return nonce
	}
	nonce, _ := o.dpopNonces.get(key)
	return nonce
}

// recentValues holds the latest value of each key, bounded to limit entries
// with the least recently used evicted first. It is not safe for concurrent
// use; the receiver guards it with a mutex.
type recentValues[K comparable] struct {
	entries map[K]recentValue
	clock   uint64
	limit   int
}

type recentValue struct {
	value    string
	lastUsed uint64
}

func newRecentValues[K comparable](limit int) *recentValues[K] {
	return &recentValues[K]{entries: make(map[K]recentValue), limit: limit}
}

// get returns the value of key and marks it used.
func (c *recentValues[K]) get(key K) (string, bool) {
	entry, found := c.entries[key]
	if !found {
		return "", false
	}
	c.clock++
	entry.lastUsed = c.clock
	c.entries[key] = entry
	return entry.value, true
}

// take returns the value of key and removes it.
func (c *recentValues[K]) take(key K) (string, bool) {
	entry, found := c.entries[key]
	if found {
		delete(c.entries, key)
	}
	return entry.value, found
}

// put stores value as the most recently used entry and evicts the least
// recently used one beyond the limit.
func (c *recentValues[K]) put(key K, value string) {
	c.clock++
	c.entries[key] = recentValue{value: value, lastUsed: c.clock}
	if len(c.entries) <= c.limit {
		return
	}
	var oldest K
	found := false
	for candidate, entry := range c.entries {
		if !found || entry.lastUsed < c.entries[oldest].lastUsed {
			oldest, found = candidate, true
		}
	}
	delete(c.entries, oldest)
}

// requireDPoPTokenType applies Options.RequireDPoP (HAIP Section 4,
// sender-constrained access tokens): a token_type other than DPoP is
// ErrDPoPRequired.
func requireDPoPTokenType(options profile.Options, tokenType string) error {
	if options.RequireDPoP && !strings.EqualFold(strings.TrimSpace(tokenType), dpopAuthorizationScheme) {
		return fmt.Errorf(
			"%w: %w requires a DPoP-bound access token, the token endpoint issued token_type %q",
			ErrDPoPRequired, profile.Refused("RequireDPoP"), tokenType)
	}
	return nil
}

// ErrDPoPRequired reports that a DPoP proof is required (RFC 9449) and the
// wallet cannot send one: a Bearer-token request answered with a DPoP
// challenge, a DPoP-bound token without a proof factory, or a non-DPoP token
// under Options.RequireDPoP.
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
