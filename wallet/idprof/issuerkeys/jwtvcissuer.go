package issuerkeys

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

// jwtVCIssuerWellKnownPath is the well-known path prefix the IETF SD-JWT VC
// specification defines for JWT VC Issuer Metadata.
const jwtVCIssuerWellKnownPath = "/.well-known/jwt-vc-issuer"

// jwtVCIssuerMetadata is the JWT VC Issuer Metadata document of the IETF
// SD-JWT VC specification's JWT VC Issuer Metadata section.
type jwtVCIssuerMetadata struct {
	// Issuer is the Issuer identifier the document speaks for. The
	// specification requires it to be identical to the Issuer identifier the
	// document was retrieved for.
	Issuer string `json:"issuer"`
	// JWKS is the Issuer's public keys, carried inline.
	JWKS json.RawMessage `json:"jwks"`
	// JWKSURI locates the Issuer's public keys at a separate URL. The
	// specification lets a document use either form, not both.
	JWKSURI string `json:"jwks_uri"`
}

// jwtVCIssuerRung is rung 2: the key resolution mechanism the IETF SD-JWT VC
// specification defines for the SD-JWT VC format family.
//
// It is the standard answer to "which key signed this credential" for that
// family, which is why it outranks every binding the wallet has to infer.
func (r *Resolver) jwtVCIssuerRung(ctx context.Context, request Request) ([]Candidate, MechanismDiagnostic) {
	diagnostic := MechanismDiagnostic{Mechanism: RungJWTVCIssuerMetadata}
	if !isSDJWTVC(request.CredentialFormat) {
		diagnostic.Failure = "not applicable for this credential format"
		return nil, diagnostic
	}
	if !r.Mechanisms.JWTVCIssuerMetadata {
		diagnostic.Failure = failureDisabled
		diagnostic.DisabledBy = []string{SwitchJWTVCIssuerMetadata}
		return nil, diagnostic
	}
	diagnostic.Attempted = true
	if request.Issuer == "" {
		diagnostic.Failure = "credential carries no issuer"
		return nil, diagnostic
	}

	keys, remoteSkipped, err := r.jwtVCIssuerKeys(ctx, request)
	if err != nil {
		diagnostic.Failure = failureReason(err)
		if remoteSkipped {
			// The document pointed at its keys and the configuration kept the
			// resolver from following the pointer; that, not the issuer, is
			// why the rung has nothing.
			diagnostic.DisabledBy = []string{SwitchRemoteJWKS}
		}
		return nil, diagnostic
	}

	ordered := orderByKeyID(keys, request.KeyID)
	candidates := make([]Candidate, 0, len(ordered))
	for _, key := range ordered {
		candidates = append(candidates, Candidate{
			Key:       key,
			Issuer:    request.Issuer,
			Mechanism: MechanismJWTVCIssuerMetadata,
		})
	}
	diagnostic.CandidateCount = len(candidates)
	return candidates, diagnostic
}

// jwtVCIssuerKeys retrieves the Issuer's JWT VC Issuer Metadata and returns the
// keys in it that could have signed this credential. remoteSkipped reports that
// the document named a `jwks_uri` the configuration kept the resolver from
// following.
func (r *Resolver) jwtVCIssuerKeys(ctx context.Context, request Request) (keys []jose.JSONWebKey, remoteSkipped bool, err error) {
	issuerURL, err := r.allowedURL(request.Issuer)
	if err != nil {
		return nil, false, err
	}
	document, err := r.fetchJSONObject(ctx, jwtVCIssuerMetadataURL(issuerURL))
	if err != nil {
		return nil, false, err
	}

	var metadata jwtVCIssuerMetadata
	if err := json.Unmarshal(document, &metadata); err != nil {
		return nil, false, newMechanismError(ErrIssuerMetadataInvalid, "jwt-vc-issuer metadata is not usable")
	}
	// The `issuer` member is the document's claim about whom it speaks for. An
	// origin that serves a document for another issuer has not authorised this
	// credential's `iss`, whatever keys the document carries.
	if metadata.Issuer != request.Issuer {
		return nil, false, newMechanismError(ErrJWTVCIssuerMismatch, "jwt-vc-issuer metadata names another issuer")
	}

	remoteSkipped = metadata.JWKSURI != "" && !r.Mechanisms.RemoteJWKS
	set, err := r.jwtVCIssuerJWKS(ctx, metadata)
	if err != nil {
		return nil, remoteSkipped, err
	}
	keys, err = algCompatibleKeys(set, request.Algorithm)
	return keys, remoteSkipped, err
}

// jwtVCIssuerJWKS returns the key set of a JWT VC Issuer Metadata document.
//
// A `jwks_uri` is followed only when Mechanisms.RemoteJWKS allows it. When it
// does not, the member is ignored rather than refused: the document may also
// carry an inline `jwks`, and the point of the switch is that no second request
// is made, not that the document is rejected for offering one.
func (r *Resolver) jwtVCIssuerJWKS(ctx context.Context, metadata jwtVCIssuerMetadata) (*jose.JSONWebKeySet, error) {
	if metadata.JWKSURI != "" && r.Mechanisms.RemoteJWKS {
		jwksURL, err := r.allowedURL(metadata.JWKSURI)
		if err != nil {
			return nil, err
		}
		document, err := r.fetchJSONObject(ctx, jwksURL)
		if err != nil {
			return nil, err
		}
		return parseJWKSet(document)
	}
	if len(metadata.JWKS) == 0 {
		return nil, newMechanismError(ErrIssuerMetadataInvalid, "jwt-vc-issuer metadata carries no inline jwks")
	}
	return parseJWKSet(metadata.JWKS)
}

// jwtVCIssuerMetadataURL returns the JWT VC Issuer Metadata location of an
// Issuer identifier.
//
// The IETF SD-JWT VC specification inserts the well-known path segment between
// the host and the Issuer identifier's path, rather than appending it: an
// Issuer identified by https://issuer.example/tenant publishes its metadata at
// https://issuer.example/.well-known/jwt-vc-issuer/tenant. That is what lets
// one host serve many issuers without each of them owning a well-known path of
// its own.
func jwtVCIssuerMetadataURL(issuer *url.URL) *url.URL {
	metadata := &url.URL{Scheme: issuer.Scheme, Host: issuer.Host, Path: jwtVCIssuerWellKnownPath}
	if path := strings.TrimRight(issuer.Path, "/"); path != "" {
		metadata.Path += "/" + strings.TrimLeft(path, "/")
	}
	return metadata
}
