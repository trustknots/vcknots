package wallet

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/trustknots/vcknots/wallet/credential"
	credstoreTypes "github.com/trustknots/vcknots/wallet/credstore/types"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/jwtvc"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/ldpvc"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
	serializerTypes "github.com/trustknots/vcknots/wallet/serializer/types"
)

// CredentialSelection is one credential a presentation answers with.
type CredentialSelection struct {
	// CredentialID names a stored credential. It is ignored when Credential
	// is set.
	CredentialID string
	// Credential carries the credential by value and wins over CredentialID.
	// It is required on a wallet built with Config.Storeless.
	Credential *credstoreTypes.CredentialEntry
	// QueryIDs are the DCQL credential query ids the credential answers, or
	// the Presentation Exchange input_descriptor ids on a Draft 24 request.
	// At least one is required.
	QueryIDs []string
	// DisclosedClaims are the disclosure names the Holder kept. Nil keeps
	// every claim the request asks for. On a DCQL request the first claim
	// set, in the Verifier's order, whose claims were all kept is disclosed
	// (OID4VP 1.0 Section 6.4.1); on a Draft 24 SD-JWT VC request exactly
	// these disclosures are.
	DisclosedClaims []string
	// Key is the holder key for this credential. Nil uses Presentation.Key.
	Key IKeyEntry
}

// Presentation is what SubmitPresentation sends for an admitted request.
type Presentation struct {
	// Key is the holder key of every selection that names none.
	Key IKeyEntry
	// Credentials are the credentials presented. None answers a DCQL request
	// whose credential_sets are all optional with the empty vp_token object
	// (OID4VP 1.0 Section 8.1); a Draft 24 request needs at least one.
	Credentials []CredentialSelection
	// SerializeOptions are passed to the serializer, such as the ldp_vp
	// context pins. Nil uses the serializer's default for each format.
	SerializeOptions serializerTypes.SerializePresentationOptions
}

// ParsePresentationRequest parses and admits an OpenID4VP 1.0 Authorization
// Request URI under the presenter plugin's trust policy.
func (w *Wallet) ParsePresentationRequest(ctx context.Context, uri string) (*oid4vp.AdmittedRequest, error) {
	return admittedOID4VPRequest(w.presenter.ParseRequest(ctx, presenterTypes.Oid4vp, uri))
}

// ParsePresentationRequestObject authenticates a Request Object the caller
// already holds, such as one kept from an earlier ParsePresentationRequest,
// and admits the OpenID4VP 1.0 request it carries.
func (w *Wallet) ParsePresentationRequestObject(ctx context.Context, requestObject string, src presenterTypes.RequestObjectSource) (*oid4vp.AdmittedRequest, error) {
	return admittedOID4VPRequest(w.presenter.ParseRequestObject(ctx, presenterTypes.Oid4vp, requestObject, src))
}

// ParseDCAPIRequest parses and admits an OpenID4VP 1.0 request delivered
// through the Digital Credentials API (Appendix A). SubmitPresentation answers
// it with SubmitResult.DCAPIResponse instead of an HTTP call.
func (w *Wallet) ParseDCAPIRequest(ctx context.Context, invocation presenterTypes.DCAPIInvocation) (*oid4vp.AdmittedRequest, error) {
	return admittedOID4VPRequest(w.presenter.ParseDCAPIRequest(ctx, presenterTypes.Oid4vp, invocation))
}

// SelectCredentials returns the library's own choice of stored credentials
// for h: on a DCQL request the first satisfiable claim set of every required
// credential query, on a Draft 24 request the newest credential for every
// input descriptor. Passing the result to SubmitPresentation presents exactly
// what a consent screen built from it shows. A request the store cannot
// answer is an *oid4vp.AuthorizationRequestError with code access_denied.
func (w *Wallet) SelectCredentials(ctx context.Context, h *oid4vp.AdmittedRequest) ([]CredentialSelection, error) {
	if err := w.checkPresentationHandle(ctx, h); err != nil {
		return nil, err
	}
	req := h.Request()
	var (
		selections []CredentialSelection
		err        error
	)
	if h.Draft24() {
		selections, err = w.selectDraft24Credentials(&req)
	} else {
		selections, err = w.selectDCQLCredentials(ctx, h, &req)
	}
	return selections, classify(err)
}

// SubmitPresentation checks p against h, serializes the presentations and
// sends the response to the endpoint h was admitted with: a DCQL response
// for an OpenID4VP 1.0 request (encrypted under direct_post.jwt, or returned
// as SubmitResult.DCAPIResponse for the DC API) or a Presentation Exchange
// response for a Draft 24 request. Nothing is sent when p does not answer
// the request.
func (w *Wallet) SubmitPresentation(ctx context.Context, h *oid4vp.AdmittedRequest, p Presentation) (*presenterTypes.SubmitResult, error) {
	if err := w.checkPresentationHandle(ctx, h); err != nil {
		return nil, err
	}
	var (
		result *presenterTypes.SubmitResult
		err    error
	)
	if h.Draft24() {
		result, err = w.submitPresentationExchange(ctx, h, p)
	} else {
		result, err = w.submitDCQLPresentation(ctx, h, p)
	}
	return result, classify(err)
}

// DeclinePresentation answers an admitted request with an OpenID4VP error
// response (OID4VP 1.0 Section 8.5), such as access_denied when the Holder
// refuses consent.
func (w *Wallet) DeclinePresentation(ctx context.Context, h *oid4vp.AdmittedRequest, code, description string) (*presenterTypes.SubmitResult, error) {
	if err := w.checkPresentationHandle(ctx, h); err != nil {
		return nil, err
	}
	result, err := w.presenter.SubmitErrorResponse(ctx, h, code, description)
	return result, classify(err)
}

// admittedOID4VPRequest converts a dispatcher parse result to the OpenID4VP
// handle the presentation methods answer.
func admittedOID4VPRequest(admitted presenterTypes.AdmittedRequest, err error) (*oid4vp.AdmittedRequest, error) {
	if err != nil {
		return nil, classify(fmt.Errorf("failed to parse request URI: %w", err))
	}
	handle, ok := admitted.(*oid4vp.AdmittedRequest)
	if !ok || handle == nil {
		return nil, fmt.Errorf("%w: the OpenID4VP presenter returned a foreign request handle", presenterTypes.ErrUnsupportedProtocol)
	}
	return handle, nil
}

// checkPresentationHandle refuses a nil handle, a canceled ctx and, under
// HAIP, a Draft 24 handle.
func (w *Wallet) checkPresentationHandle(ctx context.Context, h *oid4vp.AdmittedRequest) error {
	if h == nil {
		return fmt.Errorf("%w: an admitted presentation request is required", ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return classify(err)
	}
	if h.Draft24() && w.profile.IsHAIP() {
		return ErrProfileForbidsDraft
	}
	return nil
}

// resolvedCredential is one resolved selection: the credential and the key
// that signs its presentation.
type resolvedCredential struct {
	id    string
	saved *SavedCredential
	key   IKeyEntry
}

// resolveSelections resolves every selection's credential and key, reading
// the store only for selections that name a stored credential.
func (w *Wallet) resolveSelections(selections []CredentialSelection, key IKeyEntry) ([]resolvedCredential, error) {
	stored := map[string]*SavedCredential{}
	if selectionsNeedTheStore(selections) {
		entries, _, err := w.GetCredentialEntries(GetCredentialEntriesRequest{})
		if err != nil {
			return nil, fmt.Errorf("failed to get credential entries: %w", err)
		}
		for _, entry := range entries {
			if entry != nil && entry.Entry != nil {
				stored[entry.Entry.Id] = entry
			}
		}
	}
	resolved := make([]resolvedCredential, 0, len(selections))
	seen := map[string]bool{}
	for _, selection := range selections {
		id := selection.CredentialID
		if selection.Credential != nil && selection.Credential.Id != "" {
			id = selection.Credential.Id
		}
		if id == "" {
			return nil, fmt.Errorf("%w: every credential selection must identify its credential", ErrInvalidArgument)
		}
		if seen[id] {
			return nil, fmt.Errorf("%w: credential %q appears in more than one selection", ErrInvalidArgument, id)
		}
		seen[id] = true
		selectionKey := selection.Key
		if selectionKey == nil {
			selectionKey = key
		}
		if selectionKey == nil {
			return nil, fmt.Errorf("%w: no holder key for credential %q", ErrInvalidArgument, id)
		}
		var saved *SavedCredential
		if selection.Credential != nil {
			entry := *selection.Credential
			entry.Id = id
			converted, err := w.convertEntryToSavedCredential(entry)
			if err != nil {
				return nil, fmt.Errorf("selected credential %q cannot be presented: %w", id, err)
			}
			saved = converted
		} else {
			found, ok := stored[id]
			if !ok {
				return nil, fmt.Errorf("%w: selected credential %s is not stored in this wallet", ErrInvalidArgument, id)
			}
			saved = found
		}
		resolved = append(resolved, resolvedCredential{id: id, saved: saved, key: selectionKey})
	}
	return resolved, nil
}

// selectionsNeedTheStore reports whether a selection names a credential by
// id only.
func selectionsNeedTheStore(selections []CredentialSelection) bool {
	for _, selection := range selections {
		if selection.Credential == nil {
			return true
		}
	}
	return false
}

// buildPresentation builds the presentation of credentials for req, held by
// the did:key of key.
func (w *Wallet) buildPresentation(credentials []*SavedCredential, key IKeyEntry, req *oid4vp.CredentialPresentationRequest) (*credential.CredentialPresentation, error) {
	did, err := w.GenerateDID(DIDCreateOptions{
		TypeID:    "did:key",
		PublicKey: key.PublicKey(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate DID: %w", err)
	}

	var serializedCredentials [][]byte
	for _, entry := range credentials {
		serializedCredentials = append(serializedCredentials, entry.Entry.Raw)
	}

	return &credential.CredentialPresentation{
		ID:          "urn:uuid:" + uuid.New().String(),
		Types:       []string{"VerifiablePresentation"},
		Credentials: serializedCredentials,
		Holder:      did.ID,
		Nonce:       &req.Nonce,
	}, nil
}

// presentationOptions returns a copy of options, or the serializer default
// for flavor when options is nil, bound to req's audience and nonce. The
// copy keeps one presentation's settings out of the next and out of the
// caller's value.
func (w *Wallet) presentationOptions(req *oid4vp.CredentialPresentationRequest, options serializerTypes.SerializePresentationOptions, flavor credential.SupportedSerializationFlavor) (serializerTypes.SerializePresentationOptions, error) {
	switch typed := options.(type) {
	case *sdjwtvc.SdJwtVcPresentationOptions:
		options = nil
		if typed != nil {
			clone := *typed
			options = &clone
		}
	case *ldpvc.LdpVcPresentationOptions:
		options = nil
		if typed != nil {
			clone := *typed
			options = &clone
		}
	case *jwtvc.JwtVcPresentationOptions:
		options = nil
		if typed != nil {
			clone := *typed
			options = &clone
		}
	}
	if options == nil {
		defaultOptions, err := w.serializer.GetDefaultOption(flavor)
		if err != nil {
			return nil, err
		}
		options = defaultOptions
	}
	applyOID4VPRequestOptions(presentationAudience(req), options)
	return options, nil
}

// presentationAudience returns req with the client identifier the
// presentation is bound to: origin:<origin> for a DC API request (OID4VP 1.0
// Appendix A.4), client_id otherwise.
func presentationAudience(req *oid4vp.CredentialPresentationRequest) *oid4vp.CredentialPresentationRequest {
	if req == nil || req.OAuthAuthzRequest == nil || req.ResponseAudience == "" || req.ResponseAudience == req.ClientID {
		return req
	}
	copied := *req
	oauth := *req.OAuthAuthzRequest
	oauth.ClientID = req.ResponseAudience
	copied.OAuthAuthzRequest = &oauth
	return &copied
}

// applyOID4VPRequestOptions binds options to req's client_id and nonce.
func applyOID4VPRequestOptions(req *oid4vp.CredentialPresentationRequest, options serializerTypes.SerializePresentationOptions) {
	if options == nil || req == nil || req.OAuthAuthzRequest == nil {
		return
	}
	options.SetAudience(req.ClientID)
	options.SetNonce(req.Nonce)
}

// validateSerializationFlavor returns the one serialization flavor every
// credential shares.
func (w *Wallet) validateSerializationFlavor(credentials []*SavedCredential) (*credential.SupportedSerializationFlavor, error) {
	var serializationFlavor *credential.SupportedSerializationFlavor
	for _, cred := range credentials {
		sf, err := cred.Entry.SerializationFlavor()
		if err != nil {
			return nil, fmt.Errorf("credential entry has no serialization flavor information")
		}
		if serializationFlavor == nil {
			serializationFlavor = &sf
		} else if *serializationFlavor != sf {
			return nil, fmt.Errorf("%w: credentials have different serialization flavors", ErrInvalidArgument)
		}
	}
	if serializationFlavor == nil {
		return nil, fmt.Errorf("failed to detect serialization flavor")
	}
	return serializationFlavor, nil
}
