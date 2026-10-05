package oid4vp

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/profile"
)

// ErrProtocolVersionMismatch reports an Authorization Request that an entry
// point of one OpenID4VP version refused because it is written for the other
// version. The error in the chain is a *VersionMismatchError.
var ErrProtocolVersionMismatch = common.NewCodedError("oid4vp_version_mismatch", "the authorization request is written for another OpenID4VP version")

// VersionMismatchError reports an Authorization Request an entry point
// refused as written for another OpenID4VP version. errors.Is(err,
// ErrProtocolVersionMismatch) holds. A caller that serves both versions hands
// the error to AdmitUnderVersion, which admits the same request under Version
// without fetching its request_uri again.
//
// OpenID4VP 1.0 and Draft 24 share one Authorization Request syntax, so a
// Wallet that serves both learns which version a request is written for only
// from what it carries. The entry points decide by the query language, before
// any rule only one of the two versions has:
//
//   - A request with presentation_definition or presentation_definition_uri
//     and no dcql_query is a Draft 24 (DIF Presentation Exchange) request.
//     OpenID4VP 1.0 has no Presentation Exchange; its entry points refuse it
//     naming VersionDraft24.
//   - A request with dcql_query and no Presentation Exchange parameter that
//     reaches a Draft 24 entry point is refused naming VersionFinal. This
//     library answers dcql_query only under OpenID4VP 1.0: it does not
//     implement the Draft 24 DCQL response (Draft 24 §8.1, a vp_token whose
//     values are single presentations). A caller that knows the Verifier
//     speaks Draft 24 refuses such a request instead of re-admitting it.
//   - A request with both is not a mismatch: an OpenID4VP 1.0 entry point
//     ignores the unrecognized Presentation Exchange parameters (§5: "The
//     Wallet MUST ignore any unrecognized parameters"), and a Draft 24 entry
//     point refuses it with invalid_request (Draft 24 §5.1: "Exactly one of
//     the following parameters MUST be present").
//   - A Digital Credentials API request has no Draft 24 counterpart and is
//     never a mismatch.
//
// The decision reads the parameters before the Request Object is
// authenticated, because authentication is itself version specific (the
// Client Identifier syntax, aud, the response encryption rules). It admits
// nothing: AdmitUnderVersion authenticates the request again under every rule
// of the version it names. Only what precedes reading the parameters comes
// first: the outer client_id syntax of the entry point, the request_uri
// fetch (and RequestURIPolicy), and the Request Object's typ and bounds.
type VersionMismatchError struct {
	// Parsed is the version of the entry point that refused the request.
	Parsed profile.Version
	// Version is the version whose entry point admits the request in this
	// library: VersionDraft24 for a Presentation Exchange request,
	// VersionFinal for a dcql_query request.
	Version profile.Version
	// Parameter is the Authorization Request parameter that decided:
	// "presentation_definition", "presentation_definition_uri" or
	// "dcql_query".
	Parameter string

	// retry is what the refusing parse received, for AdmitUnderVersion.
	retry *versionRetry
}

func (e *VersionMismatchError) Error() string {
	if e.Version == profile.VersionFinal {
		return fmt.Sprintf("%s: the %s entry point does not answer %s; this library answers it as OpenID4VP 1.0 only (the Draft 24 DCQL response is not implemented)", ErrProtocolVersionMismatch, e.Parsed, e.Parameter)
	}
	return fmt.Sprintf("%s: %s is a %s parameter, which the %s entry point does not process", ErrProtocolVersionMismatch, e.Parameter, e.Version, e.Parsed)
}

// Unwrap returns ErrProtocolVersionMismatch.
func (e *VersionMismatchError) Unwrap() error { return ErrProtocolVersionMismatch }

// versionRetry is the input of a parse that ended in a VersionMismatchError:
// the plain parameters, or the Request Object and how it arrived.
type versionRetry struct {
	presenter              *Oid4vpPresenter
	source                 requestSource
	query                  url.Values
	requestObject          string
	requestURI             string
	walletNonce            string
	expectedClientID       string
	expectedClientIDAbsent bool
}

// versionMismatch returns the refusal of a request whose query language
// belongs to the other version, or nil. parsed is the version of the entry
// point reading params.
func versionMismatch(parsed profile.Version, params map[string]any) error {
	_, hasDCQL := params["dcql_query"]
	definition := ""
	for _, name := range []string{"presentation_definition", "presentation_definition_uri"} {
		if _, present := params[name]; present {
			definition = name
			break
		}
	}
	switch {
	case parsed == profile.VersionFinal && definition != "" && !hasDCQL:
		return &VersionMismatchError{Parsed: parsed, Version: profile.VersionDraft24, Parameter: definition}
	case parsed == profile.VersionDraft24 && hasDCQL && definition == "":
		return &VersionMismatchError{Parsed: parsed, Version: profile.VersionFinal, Parameter: "dcql_query"}
	}
	return nil
}

// recordVersionRetry attaches to a VersionMismatchError in err what core had
// received, so AdmitUnderVersion can parse it again without a new fetch.
func (p *Oid4vpPresenter) recordVersionRetry(core *requestCore, err error) {
	var mismatch *VersionMismatchError
	if !errors.As(err, &mismatch) {
		return
	}
	mismatch.retry = &versionRetry{
		presenter:              p,
		source:                 core.requestSource,
		query:                  core.queryParams,
		requestObject:          core.requestObject,
		requestURI:             core.requestURI,
		walletNonce:            core.sentWalletNonce,
		expectedClientID:       core.expectedClientID,
		expectedClientIDAbsent: core.expectedClientIDAbsent,
	}
}

// ErrVersionRetryUnavailable reports an error AdmitUnderVersion cannot act
// on: no *VersionMismatchError in its chain, one another presenter produced,
// or one built by the caller rather than by a parse.
var ErrVersionRetryUnavailable = common.NewCodedError("oid4vp_version_retry_unavailable", "the error is not a protocol version refusal of this presenter")

var _ types.VersionAdmitter = (*Oid4vpPresenter)(nil)

// AdmitUnderVersion admits, under the entry point of the version a
// *VersionMismatchError in refused names, the request the refusing parse of
// this presenter received. Plain parameters are parsed again, a Request
// Object passed by value is authenticated again by value, and a Request
// Object this presenter fetched from request_uri is authenticated as
// delivered by reference - with the request_uri and the wallet_nonce of that
// fetch - without fetching it again. Every rule of the target version applies,
// including the presenter's profile Options on the OpenID4VP 1.0 path. The
// result is an *AdmittedRequest; a Request Object fetched by reference can be
// sealed and re-admitted (ReadmitDraft24Request or ReadmitRequest).
func (p *Oid4vpPresenter) AdmitUnderVersion(ctx context.Context, refused error) (types.AdmittedRequest, error) {
	return asAdmitted(p.admitUnderVersion(ctx, refused))
}

func (p *Oid4vpPresenter) admitUnderVersion(ctx context.Context, refused error) (*AdmittedRequest, error) {
	var mismatch *VersionMismatchError
	if !errors.As(refused, &mismatch) || mismatch.retry == nil || mismatch.retry.presenter != p {
		return nil, ErrVersionRetryUnavailable
	}
	retry := mismatch.retry
	if retry.expectedClientID != "" {
		// The outer client_id passed the refusing version's syntax; it must
		// also be a Client Identifier of the version admitting the request.
		parse := parseOID4VPClientID
		if mismatch.Version == profile.VersionDraft24 {
			parse = parseDraft24ClientID
		}
		if _, err := parse(retry.expectedClientID); err != nil {
			return nil, fmt.Errorf("invalid client_id in initial request: %w", err)
		}
	}
	switch mismatch.Version {
	case profile.VersionDraft24:
		builder, err := p.newDraft24RequestBuilder(ctx)
		if err != nil {
			return nil, err
		}
		retry.replay(&builder.requestCore)
		switch retry.source {
		case sourceQuery:
			builder.WithQueryParams(retry.query)
		case sourceValue:
			builder.WithRequestObject(retry.requestObject)
		default:
			builder.withRequestObject(retry.requestObject)
		}
		return p.finishParse(&builder.requestCore, builder.Build, wireDraft24)
	case profile.VersionFinal:
		builder, err := p.newRequestBuilder(ctx)
		if err != nil {
			return nil, err
		}
		retry.replay(&builder.requestCore)
		switch retry.source {
		case sourceQuery:
			builder.WithQueryParams(retry.query)
		case sourceValue:
			if builder.options.RequireSignedRequestByReference {
				return nil, errRequestURIRequired()
			}
			builder.WithRequestObject(retry.requestObject)
		default:
			builder.withRequestObject(retry.requestObject)
		}
		return p.finishParse(&builder.requestCore, builder.Build, wireOpenID4VP1)
	default:
		return nil, ErrVersionRetryUnavailable
	}
}

// replay sets up core to parse again what the refusing parse received.
func (r *versionRetry) replay(core *requestCore) {
	core.expectedClientID = r.expectedClientID
	core.expectedClientIDAbsent = r.expectedClientIDAbsent
	if r.source == sourceReference {
		core.requestSource = sourceReference
		core.requestURI = r.requestURI
		core.sentWalletNonce = r.walletNonce
	}
}
