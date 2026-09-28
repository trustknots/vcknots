package wallet

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"slices"
	"sort"

	"github.com/google/uuid"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
)

// Draft24Presentation parses OpenID4VP Draft 24 requests, which answer with
// DIF Presentation Exchange. Its handles are answered with
// Wallet.SubmitPresentation and Wallet.DeclinePresentation. Every method
// returns ErrProfileForbidsDraft unless Config.Profiles enables
// profile.Draft24.
type Draft24Presentation struct {
	w *Wallet
}

// Draft24 returns the OpenID4VP Draft 24 view of w.
func (w *Wallet) Draft24() *Draft24Presentation {
	return &Draft24Presentation{w: w}
}

// ParsePresentationRequest parses and admits an OpenID4VP Draft 24
// Authorization Request URI.
func (d *Draft24Presentation) ParsePresentationRequest(ctx context.Context, uri string) (*oid4vp.AdmittedRequest, error) {
	if err := d.w.requireDraft24(); err != nil {
		return nil, err
	}
	return admittedOID4VPRequest(d.w.presenter.ParseDraft24Request(ctx, presenterTypes.Oid4vp, uri))
}

// ParsePresentationRequestObject authenticates a Draft 24 Request Object the
// caller already holds and admits the request it carries.
func (d *Draft24Presentation) ParsePresentationRequestObject(ctx context.Context, requestObject string, src presenterTypes.RequestObjectSource) (*oid4vp.AdmittedRequest, error) {
	if err := d.w.requireDraft24(); err != nil {
		return nil, err
	}
	return admittedOID4VPRequest(d.w.presenter.ParseDraft24RequestObject(ctx, presenterTypes.Oid4vp, requestObject, src))
}

// ReadmitPresentationRequest re-admits a Draft 24 request from a sealed
// admission, as Wallet.ReadmitPresentationRequest does for OpenID4VP 1.0.
func (d *Draft24Presentation) ReadmitPresentationRequest(ctx context.Context, sealed presenterTypes.SealedAdmission, key []byte) (*oid4vp.AdmittedRequest, error) {
	if err := d.w.requireDraft24(); err != nil {
		return nil, err
	}
	return admittedOID4VPRequest(d.w.presenter.ReadmitDraft24Request(ctx, presenterTypes.Oid4vp, sealed, key))
}

// ErrDraft24ResponseTransformFailed reports that
// Config.Experimental.Hooks.PresentationExchangeResponse refused the response
// it was given.
var ErrDraft24ResponseTransformFailed = common.NewCodedError("draft24_response_transform_failed", "response transform failed")

// selectDraft24Credentials is the library's choice for a Presentation
// Exchange request: the newest stored credential, answering every input
// descriptor of the definition.
func (w *Wallet) selectDraft24Credentials(req *oid4vp.CredentialPresentationRequest) ([]CredentialSelection, error) {
	descriptorIDs, err := inputDescriptorIDs(req)
	if err != nil {
		return nil, err
	}
	entries, _, err := w.GetCredentialEntries(GetCredentialEntriesRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to get credential entries: %w", err)
	}
	newest := newestCredentials(entries, 1)
	if len(newest) == 0 || newest[0] == nil || newest[0].Entry == nil {
		return nil, newAccessDeniedError("no credentials available for presentation")
	}
	return []CredentialSelection{{CredentialID: newest[0].Entry.Id, QueryIDs: descriptorIDs}}, nil
}

// inputDescriptorIDs returns the input_descriptor ids of req's
// presentation_definition.
func inputDescriptorIDs(req *oid4vp.CredentialPresentationRequest) ([]string, error) {
	if req.PresentationDefinition == nil || req.PresentationDefinition.ID == "" {
		return nil, fmt.Errorf("%w: presentation_definition is not specified", ErrInvalidArgument)
	}
	var definition struct {
		InputDescriptors []struct {
			ID string `json:"id"`
		} `json:"input_descriptors"`
	}
	if len(req.RawPresentationDefinition) > 0 {
		if err := json.Unmarshal(req.RawPresentationDefinition, &definition); err != nil {
			return nil, fmt.Errorf("%w: presentation_definition: %w", ErrInvalidArgument, err)
		}
	}
	ids := []string{}
	for _, descriptor := range definition.InputDescriptors {
		if descriptor.ID != "" {
			ids = append(ids, descriptor.ID)
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("%w: presentation_definition names no input descriptor", ErrInvalidArgument)
	}
	return ids, nil
}

// newestCredentials returns up to limit entries, most recently received first.
func newestCredentials(entries []*SavedCredential, limit int) []*SavedCredential {
	if len(entries) == 0 || limit <= 0 {
		return nil
	}
	sorted := append([]*SavedCredential(nil), entries...)
	sort.SliceStable(sorted, func(i, j int) bool {
		left, right := sorted[i], sorted[j]
		if left == nil || left.Entry == nil {
			return false
		}
		if right == nil || right.Entry == nil {
			return true
		}
		return left.Entry.ReceivedAt.After(right.Entry.ReceivedAt)
	})
	return sorted[:min(limit, len(sorted))]
}

// submitPresentationExchange answers a Draft 24 request with a Presentation
// Exchange vp_token and presentation_submission.
func (w *Wallet) submitPresentationExchange(ctx context.Context, h *oid4vp.AdmittedRequest, p Presentation) (*presenterTypes.SubmitResult, error) {
	req := h.Request()
	if req.PresentationDefinition == nil || req.PresentationDefinition.ID == "" {
		return nil, fmt.Errorf("%w: presentation_definition is not specified", ErrInvalidArgument)
	}
	// A Presentation Exchange vp_token is a presentation, which cannot say
	// "no credential"; only the DCQL response object can.
	if len(p.Credentials) == 0 {
		return nil, fmt.Errorf("%w: at least one credential selection is required to present a Draft 24 request", ErrInvalidArgument)
	}
	descriptorIDs := make([][]string, len(p.Credentials))
	for index, selection := range p.Credentials {
		if len(selection.QueryIDs) == 0 {
			return nil, fmt.Errorf("%w: every Draft 24 selection must name its input descriptors", ErrInvalidArgument)
		}
		descriptorIDs[index] = selection.QueryIDs
	}
	credentials, err := w.resolveSelections(p.Credentials, p.Key)
	if err != nil {
		return nil, err
	}
	saved := make([]*SavedCredential, len(credentials))
	for index, presented := range credentials {
		saved[index] = presented.saved
	}
	flavor, err := w.validateSerializationFlavor(saved)
	if err != nil {
		return nil, err
	}
	// Presentation Exchange limit_disclosure "required" bounds what each
	// presentation discloses, decided before anything is serialized.
	limits, err := draft24DisclosureLimits(req.RawPresentationDefinition, p.Credentials, credentials)
	if err != nil {
		return nil, err
	}
	descriptorMap, err := buildDraft24DescriptorMap(len(saved), *flavor, descriptorIDs)
	if err != nil {
		return nil, err
	}
	vpToken, err := w.serializeDraft24Presentation(&req, p, credentials, limits, *flavor)
	if err != nil {
		return nil, err
	}
	submission := presenterTypes.PresentationSubmission{
		ID:            uuid.New().String(),
		DefinitionID:  req.PresentationDefinition.ID,
		DescriptorMap: descriptorMap,
	}
	if w.testHooks != nil && w.testHooks.PresentationExchangeResponse != nil {
		vpToken, submission, err = w.testHooks.PresentationExchangeResponse(vpToken, submission)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrDraft24ResponseTransformFailed, err)
		}
	}
	return w.presenter.SubmitPresentationExchangeResponse(ctx, h, vpToken, submission)
}

// buildDraft24DescriptorMap renders the descriptor_map for count credentials,
// descriptorIDs[i] naming the input descriptors credential i answers. An
// SD-JWT VC presentation holds one credential, so several travel as a JSON
// array indexed by path; a JWT or LDP Verifiable Presentation holds them all
// at "$" and path_nested tells them apart.
func buildDraft24DescriptorMap(count int, flavor credential.SupportedSerializationFlavor, descriptorIDs [][]string) ([]presenterTypes.DescriptorMapItem, error) {
	vcFormat, vpFormat, err := flavor.OID4VPFormatIdentifier()
	if err != nil {
		return nil, fmt.Errorf("unsupported serialization format: %w", err)
	}
	var descriptorMap []presenterTypes.DescriptorMapItem
	for i := range count {
		for _, descriptorID := range descriptorIDs[i] {
			if flavor == credential.SDJwtVC {
				path := "$"
				if count > 1 {
					path = fmt.Sprintf("$[%d]", i)
				}
				descriptorMap = append(descriptorMap, presenterTypes.DescriptorMapItem{ID: descriptorID, Format: vpFormat, Path: path})
				continue
			}
			// jwt_vp_json carries the presentation under the vp claim; an
			// ldp_vp is the presentation itself (OpenID4VP Appendix B.1.3.1).
			nestedPath := fmt.Sprintf("$.vp.verifiableCredential[%d]", i)
			if flavor == credential.LdpVc {
				nestedPath = fmt.Sprintf("$.verifiableCredential[%d]", i)
			}
			descriptorMap = append(descriptorMap, presenterTypes.DescriptorMapItem{
				ID:     descriptorID,
				Format: vpFormat,
				Path:   "$",
				PathNested: &presenterTypes.DescriptorMapItem{
					ID:     descriptorID,
					Format: vcFormat,
					Path:   nestedPath,
				},
			})
		}
	}
	return descriptorMap, nil
}

// serializeDraft24Presentation renders the Presentation Exchange vp_token.
// Each SD-JWT VC gets its own presentation with a Key Binding JWT; every
// other format is one presentation of all credentials under one key.
//
// Each transaction_data entry is carried by the credential it is assigned to
// (Draft 24 Section 5.1, assignTransactionData), and only an SD-JWT VC Key
// Binding JWT can carry it (Appendix A.4.5). limits[i], when not nil, holds
// the claims path pointers credential i discloses under limit_disclosure
// (draft24DisclosureLimits) and replaces its DisclosedClaims.
func (w *Wallet) serializeDraft24Presentation(req *oid4vp.CredentialPresentationRequest, p Presentation, credentials []resolvedCredential, limits [][]string, flavor credential.SupportedSerializationFlavor) ([]byte, error) {
	transactionData, err := assignTransactionData(req.TransactionData, p.Credentials)
	if err != nil {
		return nil, err
	}
	if flavor != credential.SDJwtVC && len(req.TransactionData) > 0 {
		return nil, fmt.Errorf("transaction_data requires an SD-JWT VC presentation, not %s (invalid_transaction_data)", flavor)
	}
	if flavor != credential.SDJwtVC {
		key := credentials[0].key
		saved := make([]*SavedCredential, len(credentials))
		for index, presented := range credentials {
			if !sameHolderKey(presented.key, key) {
				return nil, fmt.Errorf("%w: one %s presentation cannot be signed with several holder keys", ErrInvalidArgument, flavor)
			}
			saved[index] = presented.saved
		}
		options, err := w.presentationOptions(req, p.SerializeOptions, flavor)
		if err != nil {
			return nil, err
		}
		presentation, err := w.buildPresentation(saved, key, req)
		if err != nil {
			return nil, err
		}
		serialized, _, err := w.serializer.SerializePresentation(flavor, presentation, key, options)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize presentation: %w", err)
		}
		return serialized, nil
	}

	tokens := make([]string, 0, len(credentials))
	for index, presented := range credentials {
		options, err := w.presentationOptions(req, p.SerializeOptions, flavor)
		if err != nil {
			return nil, err
		}
		if sdOpts, ok := options.(*sdjwtvc.SdJwtVcPresentationOptions); ok {
			// Draft 24 has no require_cryptographic_holder_binding, so the
			// Verifier cannot waive the Key Binding JWT.
			sdOpts.RequireKeyBinding = true
			if index < len(limits) && limits[index] != nil {
				sdOpts.SelectedClaims = slices.Clone(limits[index])
				sdOpts.LimitDisclosureToSelectedClaims = true
				sdOpts.RequireRootClaimMatch = true
			} else if disclosed := p.Credentials[index].DisclosedClaims; disclosed != nil {
				sdOpts.SelectedClaims = append([]string(nil), disclosed...)
				sdOpts.LimitDisclosureToSelectedClaims = true
			}
			if owned := transactionData.selectionEntries(index, req.TransactionData); len(owned) > 0 {
				sdOpts.TransactionData = owned
				sdOpts.TransactionDataHashesAlg = req.TransactionDataHashesAlg
				if sdOpts.TransactionDataHashesAlg == "" {
					sdOpts.TransactionDataHashesAlg = "sha-256"
				}
			}
		}
		presentation, err := w.buildPresentation([]*SavedCredential{presented.saved}, presented.key, req)
		if err != nil {
			return nil, err
		}
		serialized, _, err := w.serializer.SerializePresentation(flavor, presentation, presented.key, options)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize selected credential %s: %w", presented.id, err)
		}
		// Draft 24 Appendix B.4.2: "If present, the alg JOSE header ... MUST
		// match one of the array values" of sd-jwt_alg_values and
		// kb-jwt_alg_values.
		if err := req.ClientMetadata.CheckSDJWTPresentationAlgorithms(string(serialized)); err != nil {
			return nil, fmt.Errorf("credential %s: %w", presented.id, err)
		}
		if err := checkDraft24DescriptorAlgorithms(req, p.Credentials[index].QueryIDs, string(serialized)); err != nil {
			return nil, fmt.Errorf("credential %s: %w", presented.id, err)
		}
		tokens = append(tokens, string(serialized))
	}
	if len(tokens) == 1 {
		return []byte(tokens[0]), nil
	}
	return json.Marshal(tokens)
}

// sameHolderKey reports whether a and b have the same public key.
func sameHolderKey(a, b IKeyEntry) bool {
	publicA, publicB := a.PublicKey(), b.PublicKey()
	thumbprintA, errA := publicA.Thumbprint(crypto.SHA256)
	thumbprintB, errB := publicB.Thumbprint(crypto.SHA256)
	return errA == nil && errB == nil && bytes.Equal(thumbprintA, thumbprintB)
}

// checkDraft24DescriptorAlgorithms applies the SD-JWT VC algorithm lists of
// the format member of the input descriptors a presentation answers (or of
// the definition, for a descriptor without one) to it, the way the Verifier's
// vp_formats applies. Draft 24 §5.4: "The Wallet MUST ignore any format
// property inside a presentation_definition object if that format was not
// included in the vp_formats property of the metadata".
func checkDraft24DescriptorAlgorithms(req *oid4vp.CredentialPresentationRequest, descriptorIDs []string, presentation string) error {
	if len(req.RawPresentationDefinition) == 0 {
		return nil
	}
	var definition struct {
		Format           map[string]json.RawMessage `json:"format"`
		InputDescriptors []struct {
			ID     string                     `json:"id"`
			Format map[string]json.RawMessage `json:"format"`
		} `json:"input_descriptors"`
	}
	if err := json.Unmarshal(req.RawPresentationDefinition, &definition); err != nil {
		return fmt.Errorf("%w: presentation_definition: %w", ErrInvalidArgument, err)
	}
	var verifierFormats map[string]json.RawMessage
	if req.ClientMetadata != nil {
		verifierFormats = req.ClientMetadata.VPFormats
	}
	for _, descriptor := range definition.InputDescriptors {
		if !slices.Contains(descriptorIDs, descriptor.ID) {
			continue
		}
		formats := descriptor.Format
		if len(formats) == 0 {
			formats = definition.Format
		}
		applied := map[string]json.RawMessage{}
		for name, value := range formats {
			if _, listed := verifierFormats[name]; len(verifierFormats) == 0 || listed {
				applied[name] = value
			}
		}
		if err := (&oid4vp.VerifierMetadata{VPFormats: applied}).CheckSDJWTPresentationAlgorithms(presentation); err != nil {
			return fmt.Errorf("input descriptor %q: %w", descriptor.ID, err)
		}
	}
	return nil
}
