// Package statuslist checks a credential's status against an IETF Token Status
// List (draft-ietf-oauth-status-list).
//
// A credential that supports this mechanism carries a `status` claim with a
// `status_list` member naming a URI and an index. The URI serves a Status List
// Token: a signed JWT whose payload holds a compressed bit string, one entry
// per referenced credential. Checking a credential therefore means four
// separate things, and this package keeps them separate because each can fail
// for its own reason and a caller usually wants to treat the failures
// differently:
//
//  1. reading the reference out of the credential (ParseReference),
//  2. fetching the Status List Token from the URI it names,
//  3. authenticating that token — its type, its `iss` bound to the credential's
//     issuer, its signature under a key of that issuer, and the claims
//     Section 5.1 makes REQUIRED,
//  4. reading the one entry the index points at (ReadValue).
//
// The meaning of an entry's value is deliberately not interpreted here.
// Section 7.1 assigns 0x00 "VALID", 0x01 "INVALID" and 0x02 "SUSPENDED", and
// leaves the rest to the application; a wallet that surfaces a verdict to a
// person decides what to do with the number, while this package's contract is
// that the number it reports is the one the issuer signed.
//
// Key resolution is a hook rather than a policy. Which keys speak for a Status
// List Token issuer is a trust decision — issuer metadata, a JWKS, an x5c chain
// to a configured anchor — and it belongs to the integrator that knows which
// issuers it trusts and how. The Checker only insists that whatever the hook
// returns is a public key the signature actually verifies under.
package statuslist

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	commonjose "github.com/trustknots/vcknots/wallet/common/jose"
	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
)

const (
	// statusListTokenType is the `typ` header value
	// draft-ietf-oauth-status-list Section 5.1 assigns to a Status List Token,
	// so that a JWT issued for another purpose can never be read as one.
	statusListTokenType = "statuslist+jwt"
	// statusListTokenMediaType is the media type Section 10.1 registers for a
	// Status List Token. It is both what the wallet asks for and what the
	// response must be typed as.
	statusListTokenMediaType = "application/statuslist+jwt"
)

// DefaultStatusListSigningAlgorithms is the JWS signature algorithm set a
// Status List Token may be signed with when a Checker names none of its own:
// the library's accepted asymmetric algorithms (common/jose
// AcceptedSignatureAlgorithms). MAC algorithms and `none` are never included.
//
// Callers must not modify this slice; assign a copy to Checker.SigningAlgorithms
// to narrow or widen the set for one checker.
var DefaultStatusListSigningAlgorithms = commonjose.AcceptedSignatureAlgorithms()

// Reference is a parsed `status.status_list` credential claim: the Status List
// Token URI and the index of this credential's entry within the list that token
// carries (draft-ietf-oauth-status-list Section 7.1).
type Reference struct {
	// URI is the `uri` member: where the Status List Token is fetched from.
	URI string
	// Index is the `idx` member: the zero-based position of this credential's
	// entry in the status list.
	Index int
}

// Status is the outcome of one status check: the value the issuer published for
// the referenced index, together with the evidence the check rests on. A caller
// that records why it believed a credential valid at a point in time keeps the
// token's issuer, subject, hash and validity window, not only Value.
type Status struct {
	// URI is the Status List Token URI the check used, exactly as the
	// credential's `uri` member spelled it. It is the value the token's `sub`
	// was required to equal.
	URI string
	// Index is the index that was read.
	Index int
	// Bits is the entry width of the list, one of 1, 2, 4 or 8.
	Bits int
	// Value is the entry at Index. draft-ietf-oauth-status-list Section 7.1
	// assigns 0x00 "VALID", 0x01 "INVALID" and 0x02 "SUSPENDED"; other values
	// are application specific and are reported unchanged.
	Value int
	// TokenIssuer is the token's `iss` claim: the credential issuer, or the
	// Status Issuer Checker.AcceptStatusIssuer accepted.
	TokenIssuer string
	// TokenSubject is the token's `sub` claim, which equals URI.
	TokenSubject string
	// TokenSHA256 is the unpadded base64url SHA-256 digest of the compact JWT
	// that was verified. It identifies the exact token a verdict came from
	// across a log, a cache or an audit trail without retaining the token.
	TokenSHA256 string
	// TokenIssuedAt is the token's `iat` claim (RFC 7519 Section 4.1.6), which
	// Section 5.1 makes REQUIRED: it is how old the verdict is.
	TokenIssuedAt time.Time
	// TokenExpiresAt is the token's `exp` claim (RFC 7519 Section 4.1.4), or
	// the zero time when the token carries none.
	TokenExpiresAt time.Time
	// TTLSeconds is the token's `ttl` claim: the maximum time, in seconds, a
	// caller should cache this verdict before fetching the token again. It is
	// zero when the token carries no `ttl`, and may be fractional.
	TTLSeconds float64
	// IssuerKeyID is the `kid` of the resolved key whose signature verified, or
	// empty when that key carried none. It is the key a caller pins, revokes or
	// reports, and is read from the key itself rather than from the token's
	// header, which is unauthenticated until the signature verifies.
	IssuerKeyID string
	// CheckedAt is the Checker's clock reading for this check.
	CheckedAt time.Time
}

// ResolveIssuerKeysFunc returns the candidate public keys of a Status List
// Token issuer. issuer is the credential issuer the caller passed to Check, or
// the Status Issuer that Checker.AcceptStatusIssuer accepted; the token's `iss`
// already equals it. header is the token's decoded protected header (JSON
// numbers appear as float64); it is unauthenticated at the time of the call and
// must be treated as a hint for selecting keys, never as a fact. Returning no
// key, or an error, makes the check fail with ErrStatusListIssuerKeyUnresolved.
type ResolveIssuerKeysFunc func(ctx context.Context, issuer string, header map[string]any) ([]jose.JSONWebKey, error)

// Checker fetches and verifies Status List Tokens. The zero value is usable
// except for ResolveIssuerKeys, without which no token can be authenticated and
// therefore no status can be read; a Checker is safe for concurrent use as long
// as its fields are not mutated after the first check.
type Checker struct {
	// HTTPClient performs the Status List Token request. A nil client means a
	// client with a 30 second timeout. The client's redirect policy is never
	// used: the checker copies the client for each request and refuses
	// redirects itself, so a caller-owned client is not mutated.
	HTTPClient *http.Client
	// Now reads the clock the check is evaluated against. A nil value means
	// time.Now.
	Now func() time.Time
	// ClockSkew is how far the local clock may disagree with a token issuer's
	// before a token is judged expired (`exp`) or not yet valid (`nbf`). It is
	// not applied to `iat`, which is reported rather than judged.
	ClockSkew time.Duration
	// MaxTokenBytes bounds the Status List Token response body. A value of zero
	// or less means 64 KiB.
	MaxTokenBytes int64
	// MaxDecompressedBytes bounds the inflated status list. A value of zero or
	// less means 1 MiB.
	MaxDecompressedBytes int
	// SigningAlgorithms bounds the Status List Token JWS "alg". Empty means
	// DefaultStatusListSigningAlgorithms.
	SigningAlgorithms []jose.SignatureAlgorithm
	// ResolveIssuerKeys returns the candidate public keys of the Status List
	// Token issuer (see ResolveIssuerKeysFunc). A nil hook means no token can
	// be authenticated. Every key it returns must be a valid public key; a
	// private or symmetric key fails the check with
	// ErrStatusListIssuerKeyUnresolved.
	ResolveIssuerKeys ResolveIssuerKeysFunc
	// AcceptStatusIssuer decides whether a Status List Token whose `iss` is
	// tokenIssuer may speak for a credential issued by credentialIssuer. It is
	// called only when the two differ, before any key is resolved; returning
	// nil accepts the delegation, and the token must then verify under a key
	// of tokenIssuer. A nil hook means the token's `iss` must equal the
	// credential issuer, and any other token fails with
	// ErrStatusListIssuerMismatch.
	AcceptStatusIssuer func(ctx context.Context, credentialIssuer, tokenIssuer string) error
	// AllowHTTP permits a cleartext Status List endpoint for a local test.
	// Status List Tokens are signed, so cleartext does not let a network
	// attacker forge a verdict, but it does let one observe which credential is
	// being checked; it stays off outside a test.
	AllowHTTP bool
}

// ParseReference reads the `status_list` member of a credential's `status`
// claim (draft-ietf-oauth-status-list Section 7.1).
//
// status is the decoded `status` claim. The member must be a JSON object: an
// array or a null is not a reference, and neither is a `status` claim that
// carries only another status mechanism. `idx` must be an exactly representable
// non-negative integer — it is accepted as json.Number, float64, int or int64,
// because which of those a JSON decoder produces depends on how the credential
// was decoded — and `uri` must be a non-empty string. Nothing else in the claim
// is read, so a credential carrying additional status mechanisms alongside this
// one is parsed rather than refused.
func ParseReference(status map[string]any) (*Reference, error) {
	if status == nil {
		return nil, fmt.Errorf("%w: credential carries no status claim", ErrStatusReferenceInvalid)
	}
	raw, present := status["status_list"]
	if !present {
		return nil, fmt.Errorf("%w: status claim carries no status_list member", ErrStatusReferenceInvalid)
	}
	member, isObject := raw.(map[string]any)
	if !isObject || member == nil {
		return nil, fmt.Errorf("%w: status_list must be a JSON object", ErrStatusReferenceInvalid)
	}
	index, isInteger := integerValue(member["idx"])
	if !isInteger || index < 0 || index > int64(math.MaxInt) {
		return nil, fmt.Errorf("%w: status_list idx must be an exactly representable non-negative integer", ErrStatusReferenceInvalid)
	}
	uri, isString := member["uri"].(string)
	if !isString || uri == "" {
		return nil, fmt.Errorf("%w: status_list uri must be a non-empty string", ErrStatusReferenceInvalid)
	}
	return &Reference{URI: uri, Index: int(index)}, nil
}

// Check performs the whole check for one credential `status` claim: it parses
// the reference, fetches and authenticates the Status List Token it names, and
// reads the referenced entry.
//
// credentialIssuer is the `iss` of the credential that carries status. The
// token must be issued by it (or by a Status Issuer that
// Checker.AcceptStatusIssuer accepts): a token of another issuer, however
// trusted, says nothing about this credential.
func (c *Checker) Check(ctx context.Context, credentialIssuer string, status map[string]any) (*Status, error) {
	reference, err := ParseReference(status)
	if err != nil {
		return nil, err
	}
	return c.CheckReference(ctx, credentialIssuer, *reference)
}

// CheckReference is Check for an already parsed reference.
//
// The order of the steps is part of the contract, because each one bounds what
// the next may do: the URI is validated before anything is fetched, the
// response is bounded before it is read, the `typ` and `alg` headers are
// checked before any key is resolved, the signature is verified before any
// claim is believed, and the status list is inflated under a cap before an
// index is read out of it. A caller therefore never pays for work that a later
// step would have rejected anyway, and a hostile endpoint never reaches a stage
// its token had not yet earned.
func (c *Checker) CheckReference(ctx context.Context, credentialIssuer string, reference Reference) (*Status, error) {
	if credentialIssuer == "" {
		return nil, fmt.Errorf("%w: the credential issuer is empty", ErrStatusListIssuerMismatch)
	}
	endpoint, err := parseStatusListURI(reference.URI, c.AllowHTTP)
	if err != nil {
		return nil, err
	}
	if reference.Index < 0 || int64(reference.Index) > maxExactInteger {
		return nil, fmt.Errorf("%w: status_list idx must be an exactly representable non-negative integer, got %d", ErrStatusReferenceInvalid, reference.Index)
	}
	now := c.now()

	token, err := c.fetchToken(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	header, err := decodeProtectedHeader(token)
	if err != nil {
		return nil, err
	}
	if typ, _ := header["typ"].(string); typ != statusListTokenType {
		return nil, fmt.Errorf("%w: typ must be %q, got %q", ErrStatusListTokenTypInvalid, statusListTokenType, header["typ"])
	}
	algorithms := c.signingAlgorithms()
	algorithm, _ := header["alg"].(string)
	if !slices.Contains(algorithms, jose.SignatureAlgorithm(algorithm)) {
		return nil, fmt.Errorf("%w: alg %q is not one of %v", ErrStatusListAlgorithmUnsupported, algorithm, algorithms)
	}

	keyID, _ := header["kid"].(string)

	signed, err := jose.ParseSignedCompact(token, algorithms)
	if err != nil {
		return nil, fmt.Errorf("%w: token is not a compact JWS: %w", ErrStatusListTokenInvalid, err)
	}
	// The header above was decoded by this package and the one below by the
	// JOSE library. They are the same bytes, so they can only disagree when the
	// header repeats a member; such a header means different things to
	// different readers and is refused rather than resolved in either's favour.
	if len(signed.Signatures) != 1 || string(signed.Signatures[0].Protected.Algorithm) != algorithm || signed.Signatures[0].Protected.KeyID != keyID {
		return nil, fmt.Errorf("%w: protected header is ambiguous", ErrStatusListTokenInvalid)
	}
	// The `iss` read here comes from an unverified payload. It is bound to the
	// credential issuer before any key is resolved, and the keys are then
	// resolved for that issuer, so a signature can only verify under a key of
	// the issuer the credential names (or of an accepted Status Issuer).
	issuer, err := unverifiedIssuer(signed)
	if err != nil {
		return nil, err
	}
	if err := c.bindIssuer(ctx, credentialIssuer, issuer); err != nil {
		return nil, err
	}
	keys, err := c.resolveIssuerKeys(ctx, issuer, header)
	if err != nil {
		return nil, err
	}
	payload, verifiedKeyID, err := verifySignature(signed, keys, keyID)
	if err != nil {
		return nil, err
	}

	// `sub` is compared with the `uri` member exactly as the credential spelled
	// it: draft-ietf-oauth-status-list Section 5.1 requires the two to be equal,
	// and comparing the spelling rather than a normalized rendering keeps the
	// comparison independent of any one URL parser's normal form.
	claims, err := parseTokenClaims(payload, reference.URI)
	if err != nil {
		return nil, err
	}
	// RFC 7519 Section 4.1.4: the token is usable only while the current time is
	// before `exp`, so a token whose `exp` equals the (skewed) current time has
	// already expired.
	if !claims.expiresAt.IsZero() && !now.Add(-c.ClockSkew).Before(claims.expiresAt) {
		return nil, fmt.Errorf("%w: exp %s is not after %s", ErrStatusListTokenExpired, claims.expiresAt.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	if !claims.notBefore.IsZero() && now.Add(c.ClockSkew).Before(claims.notBefore) {
		return nil, fmt.Errorf("%w: nbf %s is after %s", ErrStatusListTokenInvalid, claims.notBefore.Format(time.RFC3339), now.Format(time.RFC3339))
	}

	value, err := ReadValue(claims.bits, claims.encodedList, reference.Index, c.MaxDecompressedBytes)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(token))
	return &Status{
		URI:            reference.URI,
		Index:          reference.Index,
		Bits:           claims.bits,
		Value:          value,
		TokenIssuer:    claims.issuer,
		TokenSubject:   claims.subject,
		TokenSHA256:    base64.RawURLEncoding.EncodeToString(digest[:]),
		TokenIssuedAt:  claims.issuedAt,
		TokenExpiresAt: claims.expiresAt,
		TTLSeconds:     claims.ttlSeconds,
		IssuerKeyID:    verifiedKeyID,
		CheckedAt:      now,
	}, nil
}

// bindIssuer refuses a token whose `iss` is not the credential issuer, unless
// AcceptStatusIssuer accepts tokenIssuer as a Status Issuer for it.
func (c *Checker) bindIssuer(ctx context.Context, credentialIssuer, tokenIssuer string) error {
	if tokenIssuer == credentialIssuer {
		return nil
	}
	if c.AcceptStatusIssuer == nil {
		return fmt.Errorf("%w: token iss %q is not the credential issuer %q", ErrStatusListIssuerMismatch, tokenIssuer, credentialIssuer)
	}
	if err := c.AcceptStatusIssuer(ctx, credentialIssuer, tokenIssuer); err != nil {
		return fmt.Errorf("%w: token iss %q is not accepted for the credential issuer %q: %w", ErrStatusListIssuerMismatch, tokenIssuer, credentialIssuer, err)
	}
	return nil
}

func (c *Checker) now() time.Time {
	if c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

func (c *Checker) signingAlgorithms() []jose.SignatureAlgorithm {
	if len(c.SigningAlgorithms) == 0 {
		return DefaultStatusListSigningAlgorithms
	}
	return c.SigningAlgorithms
}

func (c *Checker) maxTokenBytes() int64 {
	if c.MaxTokenBytes <= 0 {
		return httpfetch.DefaultBodyLimit
	}
	return c.MaxTokenBytes
}

// parseStatusListURI validates the `uri` member as a Status List endpoint.
//
// The URI must be absolute and https — http is permitted only for a local test
// through Checker.AllowHTTP — and must carry neither a query nor a fragment.
// Both restrictions come from what the URI is for: draft-ietf-oauth-status-list
// Section 5.1 requires the token's `sub` to equal it, so it is an identifier
// that is compared for equality, and a query or fragment makes two spellings of
// the same endpoint that no longer compare equal. A fragment additionally never
// reaches the server at all. User information is refused because it would be
// sent to the endpoint as credentials the wallet never meant to present.
func parseStatusListURI(raw string, allowHTTP bool) (*url.URL, error) {
	if raw == "" {
		return nil, fmt.Errorf("%w: status_list uri is empty", ErrStatusReferenceInvalid)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: status_list uri is not a URI: %w", ErrStatusReferenceInvalid, err)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("%w: status_list uri must be an absolute URL", ErrStatusReferenceInvalid)
	}
	switch {
	case strings.EqualFold(parsed.Scheme, "https"):
	case allowHTTP && strings.EqualFold(parsed.Scheme, "http"):
	default:
		return nil, fmt.Errorf("%w: status_list uri must use the https scheme, got %q", ErrStatusReferenceInvalid, parsed.Scheme)
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("%w: status_list uri must carry no user information", ErrStatusReferenceInvalid)
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		return nil, fmt.Errorf("%w: status_list uri must carry no query", ErrStatusReferenceInvalid)
	}
	if parsed.Fragment != "" || parsed.RawFragment != "" {
		return nil, fmt.Errorf("%w: status_list uri must carry no fragment", ErrStatusReferenceInvalid)
	}
	return parsed, nil
}

// fetchToken retrieves the Status List Token.
//
// The request is a GET that asks for the media type Section 10.1 registers, and
// the response must be typed with it: an endpoint that answers a Status List
// URI with HTML or a JSON error document has not served a Status List Token,
// and saying so here keeps that failure out of the JWS parser, where it would
// have surfaced as an unrelated syntax complaint.
func (c *Checker) fetchToken(ctx context.Context, endpoint *url.URL) (string, error) {
	request, err := http.NewRequestWithContext(observe.WithEndpoint(ctx, observe.EndpointStatusList), http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrStatusListFetchFailed, err)
	}
	request.Header.Set("Accept", statusListTokenMediaType)

	// Redirects are refused: the token's `sub` must equal the URI the
	// credential named, so a token served from elsewhere cannot be the one
	// asked for.
	response, err := httpfetch.NoRedirect(c.HTTPClient).Do(request)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrStatusListFetchFailed, err)
	}
	defer response.Body.Close()

	switch {
	case response.StatusCode >= 300 && response.StatusCode < 400:
		return "", fmt.Errorf("%w: status list endpoint answered with redirect status %d", ErrStatusListFetchFailed, response.StatusCode)
	case response.StatusCode < 200 || response.StatusCode >= 300:
		return "", fmt.Errorf("%w: status list endpoint answered with status %d", ErrStatusListFetchFailed, response.StatusCode)
	}
	if !httpfetch.MediaTypeIs(response.Header, statusListTokenMediaType) {
		return "", fmt.Errorf("%w: response content type %q is not %s", ErrStatusListFetchFailed, response.Header.Get("Content-Type"), statusListTokenMediaType)
	}

	body, err := httpfetch.ReadLimited(response, c.maxTokenBytes())
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrStatusListFetchFailed, err)
	}
	// A compact JWS carries no whitespace, so trimming the surrounding bytes
	// accepts an endpoint that serves the token as a text file with a trailing
	// newline without accepting anything the parser would otherwise have taken.
	// The trimmed form is what is parsed and what TokenSHA256 digests.
	token := strings.TrimSpace(string(body))
	if token == "" {
		return "", fmt.Errorf("%w: status list endpoint answered with an empty body", ErrStatusListFetchFailed)
	}
	return token, nil
}
