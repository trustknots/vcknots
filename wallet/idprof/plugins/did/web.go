package did

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/idprof/types"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
)

// Sentinel errors the did:web method plugin returns. A caller branches on the
// condition with errors.Is, or reads the stable code with common.CodeOf,
// instead of matching message text.
var (
	// ErrDIDWebIdentifierInvalid reports that the method-specific identifier
	// does not name a document URL under the rules of the did:web method
	// specification: an empty domain, an empty path segment, a segment that
	// carries a path separator, or a percent-escape that does not decode.
	ErrDIDWebIdentifierInvalid = common.NewCodedError("did_web_identifier_invalid", "did:web identifier does not name a DID document URL")
	// ErrDIDWebDocumentFetchFailed reports that the DID document could not be
	// retrieved: the request failed, the origin answered a redirect or a
	// non-2xx status, it did not label the body as a DID document, or the body
	// exceeded the configured cap.
	ErrDIDWebDocumentFetchFailed = common.NewCodedError("did_web_document_fetch_failed", "did:web document could not be retrieved")
	// ErrDIDWebDocumentInvalid reports that the retrieved body is not a usable
	// DID document: not a JSON object, or without an `id` string equal to the
	// DID being resolved (W3C DID Core, section 5.1.1).
	ErrDIDWebDocumentInvalid = common.NewCodedError("did_web_document_invalid", "did:web document is not a usable DID document")
	// ErrDIDWebNoAssertionKey reports that the DID document declares no
	// assertion key this plugin can use. W3C DID Core makes `assertionMethod`
	// the verification relationship for expressing claims, so a document that
	// declares none - or declares only relationships such as `authentication` -
	// resolves to no key rather than to a key used outside its relationship.
	ErrDIDWebNoAssertionKey = common.NewCodedError("did_web_no_assertion_key", "did:web document declares no usable assertionMethod key")
	// ErrDIDWebOperationUnsupported reports an operation the did:web method
	// does not give a resolver: creating or updating the document is the
	// controller's own publication step on their web origin, not something a
	// resolving party can perform.
	ErrDIDWebOperationUnsupported = common.NewCodedError("did_web_operation_unsupported", "did:web profiles cannot be created or updated through this plugin")
)

const (
	// didWebPrefix is the DID scheme and method name of the did:web method.
	didWebPrefix = "did:web:"
	// didWebWellKnownPath is the path the did:web method specification gives a
	// DID whose method-specific identifier is a bare domain.
	didWebWellKnownPath = "/.well-known/did.json"
	// didWebDocumentFilename terminates the path of every other did:web DID.
	didWebDocumentFilename = "did.json"
	// didWebAcceptHeader asks for the representations W3C DID Core registers
	// for a JSON DID document, and for plain JSON, which is what most did:web
	// origins actually serve.
	didWebAcceptHeader = "application/did+json, application/json"
)

// didWebDocumentContentTypes are the media types a did:web origin may label a
// DID document with. The first two are the representations W3C DID Core
// registers for JSON and JSON-LD; the third is the plain JSON type origins
// serving a did.json file usually send.
var didWebDocumentContentTypes = []string{"application/did+json", "application/did+ld+json", "application/json"}

// DIDWebPlugin resolves did:web identifiers by retrieving the DID document the
// method specification places on the identified web origin, and returns the
// document's assertion keys as the profile's verification keys.
//
// The document URL follows the did:web method specification
// (https://w3c-ccg.github.io/did-method-web/): a bare domain resolves to
// https://<domain>/.well-known/did.json, a path to
// https://<domain>/<segment>/.../did.json. Only verification methods of the
// assertionMethod relationship are returned (W3C DID Core Section 5.3), each
// with the verification method id as its KeyID. Resolving a DID does not make
// it trusted for an issuer.
type DIDWebPlugin struct {
	// HTTPClient retrieves the DID document. A nil value uses a client with a
	// 30 second timeout. The client's redirect policy is never used: this
	// plugin refuses redirects, so that the origin the identifier names is the
	// only origin that can answer for it. Which hosts may be reached is the
	// client's decision.
	HTTPClient *http.Client
	// MaxDocumentBytes bounds the retrieved document. A value of zero or less
	// uses 64 KiB.
	MaxDocumentBytes int64
}

// Create reports that did:web profiles cannot be created by a resolving party.
// Creating one means publishing a document on the web origin the identifier
// names, which happens outside this library.
func (p *DIDWebPlugin) Create(opts ...types.CreateOption) (*types.IdentityProfile, error) {
	return nil, fmt.Errorf("%w: did:web documents are published by their controller", ErrDIDWebOperationUnsupported)
}

// Update reports that did:web profiles cannot be updated by a resolving party,
// for the same reason Create cannot create one.
func (p *DIDWebPlugin) Update(profile *types.IdentityProfile, opts ...types.UpdateOption) (*types.IdentityProfile, error) {
	return nil, fmt.Errorf("%w: did:web documents are updated by their controller", ErrDIDWebOperationUnsupported)
}

// Resolve is ResolveContext with context.Background. It exists to satisfy
// DIDMethodPlugin; callers that have a context use ResolveContext.
func (p *DIDWebPlugin) Resolve(id string) (*types.IdentityProfile, error) {
	return p.ResolveContext(context.Background(), id)
}

// ResolveContext retrieves the DID document of id within ctx and returns its
// assertion keys.
//
// The request is a GET that asks for a DID document; redirects are refused so
// that only the origin named by the identifier can answer, the response must
// be labelled as a DID document or as JSON, and the body is bounded. The
// document's `id` must be a string equal to id (W3C DID Core section 5.1.1).
func (p *DIDWebPlugin) ResolveContext(ctx context.Context, id string) (*types.IdentityProfile, error) {
	documentURL, err := WebDocumentURL(id)
	if err != nil {
		return nil, err
	}

	body, err := p.fetchDocument(ctx, documentURL)
	if err != nil {
		return nil, err
	}

	var document map[string]json.RawMessage
	if err := json.Unmarshal(body, &document); err != nil || document == nil {
		return nil, fmt.Errorf("%w: body is not a JSON object", ErrDIDWebDocumentInvalid)
	}
	var documentID string
	if err := json.Unmarshal(document["id"], &documentID); err != nil || documentID != id {
		return nil, fmt.Errorf("%w: document id must be the DID being resolved", ErrDIDWebDocumentInvalid)
	}

	keys := assertionMethodKeys(document, id)
	if len(keys) == 0 {
		return nil, ErrDIDWebNoAssertionKey
	}

	return &types.IdentityProfile{
		ID:     id,
		TypeID: IDProfileTypeID,
		Keys:   &jose.JSONWebKeySet{Keys: keys},
	}, nil
}

// Validate reports whether profile is a well-formed did:web profile.
//
// It checks the shape only. Unlike did:key, whose key material is carried by
// the identifier itself and can therefore be re-derived offline, a did:web
// profile can only be confirmed against its origin, and a validation call is
// not the place to make a network request: a caller that wants the current
// document calls Resolve.
func (p *DIDWebPlugin) Validate(profile *types.IdentityProfile) error {
	if profile == nil {
		return fmt.Errorf("%w: profile cannot be nil", types.ErrProfileValidation)
	}
	if profile.TypeID != IDProfileTypeID {
		return fmt.Errorf("%w: invalid type ID for did:web profile: %s", types.ErrProfileValidation, profile.TypeID)
	}
	if _, err := WebDocumentURL(profile.ID); err != nil {
		return err
	}
	if profile.Keys == nil || len(profile.Keys.Keys) == 0 {
		return fmt.Errorf("%w: did:web profile must have at least one key", types.ErrInvalidKeys)
	}
	for index := range profile.Keys.Keys {
		key := profile.Keys.Keys[index]
		if !key.Valid() || !key.IsPublic() {
			return fmt.Errorf("%w: key at index %d is not a valid public key", types.ErrInvalidKeys, index)
		}
	}
	return nil
}

// WebDocumentURL reports the URL the did:web method specification derives from
// a did:web identifier, without retrieving anything.
//
// It is exported because the URL is a decision in its own right: a caller that
// will only accept a DID document served by a particular origin - for example
// one that requires the DID to be hosted by the party it is already talking to
// - has to learn the host before a request is made, so that a mismatch costs no
// outbound request at all.
//
// The method-specific identifier is split on ":" and every part is
// percent-decoded, which is how a port reaches the domain part
// (did:web:example.com%3A8443). A part that is empty, that does not decode, or
// that carries a path separator makes the identifier unusable: those are the
// shapes that would let an identifier reach a path other than the one its
// segments spell out.
func WebDocumentURL(did string) (*url.URL, error) {
	if !strings.HasPrefix(did, didWebPrefix) {
		return nil, fmt.Errorf("%w: %q is not a did:web identifier", ErrDIDWebIdentifierInvalid, did)
	}
	methodSpecific := strings.TrimPrefix(did, didWebPrefix)
	if methodSpecific == "" {
		return nil, fmt.Errorf("%w: method-specific identifier is empty", ErrDIDWebIdentifierInvalid)
	}

	parts := strings.Split(methodSpecific, ":")
	for index, part := range parts {
		decoded, err := url.PathUnescape(part)
		if err != nil {
			decoded = ""
		}
		if decoded == "" || strings.ContainsAny(decoded, `/\`) {
			return nil, fmt.Errorf("%w: part %d is empty or carries a path separator", ErrDIDWebIdentifierInvalid, index)
		}
		parts[index] = decoded
	}

	domain := parts[0]
	authority, err := url.Parse("https://" + domain)
	if err != nil || !strings.EqualFold(authority.Host, domain) {
		return nil, fmt.Errorf("%w: domain part is not a usable host", ErrDIDWebIdentifierInvalid)
	}

	path := didWebWellKnownPath
	if segments := parts[1:]; len(segments) > 0 {
		encoded := make([]string, 0, len(segments)+1)
		for _, segment := range segments {
			encoded = append(encoded, encodePathSegment(segment))
		}
		encoded = append(encoded, didWebDocumentFilename)
		path = "/" + strings.Join(encoded, "/")
	}

	documentURL, err := url.Parse("https://" + domain + path)
	if err != nil {
		return nil, fmt.Errorf("%w: identifier does not form a URL", ErrDIDWebIdentifierInvalid)
	}
	return documentURL, nil
}

// pathSegmentUnreserved are the non-alphanumeric characters a did:web path
// segment keeps literally. The set is the one RFC 3986 calls unreserved plus
// the sub-delimiters that need no escaping in a path segment, which is what
// the method specification's reference URL construction leaves untouched.
const pathSegmentUnreserved = "-_.!~*'()"

// encodePathSegment percent-encodes one decoded did:web identifier part for use
// as a path segment, byte by byte over its UTF-8 encoding.
func encodePathSegment(segment string) string {
	var encoded strings.Builder
	for index := 0; index < len(segment); index++ {
		character := segment[index]
		switch {
		case character >= 'A' && character <= 'Z',
			character >= 'a' && character <= 'z',
			character >= '0' && character <= '9',
			strings.IndexByte(pathSegmentUnreserved, character) >= 0:
			encoded.WriteByte(character)
		default:
			fmt.Fprintf(&encoded, "%%%02X", character)
		}
	}
	return encoded.String()
}

// fetchDocument retrieves documentURL and returns the response body, bounded by
// the configured cap.
func (p *DIDWebPlugin) fetchDocument(ctx context.Context, documentURL *url.URL) ([]byte, error) {
	request, err := http.NewRequestWithContext(observe.WithEndpoint(ctx, observe.EndpointIssuerKeyMaterial), http.MethodGet, documentURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: request could not be built", ErrDIDWebDocumentFetchFailed)
	}
	request.Header.Set("Accept", didWebAcceptHeader)

	response, err := httpfetch.NoRedirect(p.HTTPClient).Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed", ErrDIDWebDocumentFetchFailed)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("%w: origin returned HTTP %d", ErrDIDWebDocumentFetchFailed, response.StatusCode)
	}
	if !httpfetch.MediaTypeIs(response.Header, didWebDocumentContentTypes...) {
		return nil, fmt.Errorf("%w: response is not labelled as a DID document", ErrDIDWebDocumentFetchFailed)
	}
	body, err := httpfetch.ReadLimited(response, p.maxDocumentBytes())
	if errors.Is(err, httpfetch.ErrBodyTooLarge) {
		return nil, fmt.Errorf("%w: document exceeds the %d byte cap", ErrDIDWebDocumentFetchFailed, p.maxDocumentBytes())
	}
	if err != nil {
		return nil, fmt.Errorf("%w: body could not be read", ErrDIDWebDocumentFetchFailed)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("%w: document is empty", ErrDIDWebDocumentFetchFailed)
	}
	return body, nil
}

func (p *DIDWebPlugin) maxDocumentBytes() int64 {
	if p.MaxDocumentBytes > 0 {
		return p.MaxDocumentBytes
	}
	return httpfetch.DefaultBodyLimit
}

// assertionMethodKeys returns the public keys the DID document declares through
// its `assertionMethod` relationship, in the order W3C DID Core allows them to
// be written: verification methods embedded in `assertionMethod` itself first,
// then the entries of `verificationMethod` that `assertionMethod` refers to.
//
// A document with no `assertionMethod` yields nothing, even when it carries
// verification methods under another relationship.
func assertionMethodKeys(document map[string]json.RawMessage, did string) []jose.JSONWebKey {
	assertionMethods := rawArray(document["assertionMethod"])
	if len(assertionMethods) == 0 {
		return nil
	}

	referenced := make(map[string]struct{}, len(assertionMethods))
	for _, entry := range assertionMethods {
		if id := absoluteDIDURL(verificationMethodReference(entry), did); id != "" {
			referenced[id] = struct{}{}
		}
	}

	keys := make([]jose.JSONWebKey, 0, len(assertionMethods))
	for _, entry := range assertionMethods {
		if key, ok := verificationMethodKey(entry, did); ok {
			keys = append(keys, key)
		}
	}
	for _, entry := range rawArray(document["verificationMethod"]) {
		id := absoluteDIDURL(verificationMethodReference(entry), did)
		if id == "" {
			continue
		}
		if _, wanted := referenced[id]; !wanted {
			continue
		}
		if key, ok := verificationMethodKey(entry, did); ok {
			keys = append(keys, key)
		}
	}
	return keys
}

// verificationMethodReference reports the verification method identifier an
// `assertionMethod` or `verificationMethod` entry carries, whether the entry is
// the bare identifier string W3C DID Core allows as a reference or an embedded
// verification method object.
func verificationMethodReference(entry json.RawMessage) string {
	var id string
	if err := json.Unmarshal(entry, &id); err == nil {
		return id
	}
	var method struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(entry, &method); err != nil {
		return ""
	}
	return method.ID
}

// absoluteDIDURL resolves a verification method identifier against did: a
// relative DID URL made of a fragment ("#key-1") becomes did + fragment (W3C
// DID Core section 3.2.2); an absolute one is returned unchanged. Any other
// relative reference yields "".
func absoluteDIDURL(reference, did string) string {
	switch {
	case strings.HasPrefix(reference, "#") && len(reference) > 1:
		return did + reference
	case strings.HasPrefix(reference, "did:"):
		return reference
	default:
		return ""
	}
}

// verificationMethodKey reports the public key an embedded verification method
// carries, when the method belongs to did and publishes its key as a JWK.
//
// The identifier, resolved against did, must be a DID URL of did itself
// (`<did>#<fragment>`), so a document cannot hand out a key of another DID. The
// key keeps the absolute identifier as its KeyID so a caller can match it
// against a JWS `kid`. A method that publishes its key in another format, such
// as publicKeyMultibase, is skipped.
func verificationMethodKey(entry json.RawMessage, did string) (jose.JSONWebKey, bool) {
	var method struct {
		ID           string          `json:"id"`
		PublicKeyJWK json.RawMessage `json:"publicKeyJwk"`
	}
	if err := json.Unmarshal(entry, &method); err != nil {
		return jose.JSONWebKey{}, false
	}
	id := absoluteDIDURL(method.ID, did)
	if !strings.HasPrefix(id, did+"#") || len(id) == len(did)+1 {
		return jose.JSONWebKey{}, false
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(method.PublicKeyJWK, &probe); err != nil || probe == nil {
		return jose.JSONWebKey{}, false
	}
	var key jose.JSONWebKey
	if err := key.UnmarshalJSON(method.PublicKeyJWK); err != nil {
		return jose.JSONWebKey{}, false
	}
	if !key.Valid() || !key.IsPublic() {
		return jose.JSONWebKey{}, false
	}
	key.KeyID = id
	return key, true
}

// rawArray reports the elements of a JSON array member, or nothing when the
// member is absent or is not an array.
func rawArray(raw json.RawMessage) []json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var elements []json.RawMessage
	if err := json.Unmarshal(raw, &elements); err != nil {
		return nil
	}
	return elements
}
