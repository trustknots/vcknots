package wallet

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
)

// selectDCQLCredentials is the library's choice among the stored credentials,
// one selection per credential. DisclosedClaims names the claim sets the
// choice resolved to, so SubmitPresentation resolves the same sets again.
func (w *Wallet) selectDCQLCredentials(ctx context.Context, h *oid4vp.AdmittedRequest, req *oid4vp.CredentialPresentationRequest) ([]CredentialSelection, error) {
	if req.DcqlQuery == nil {
		return nil, fmt.Errorf("%w: dcql_query is not specified", ErrInvalidArgument)
	}
	entries, _, err := w.GetCredentialEntries(GetCredentialEntriesRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to get credential entries: %w", err)
	}
	candidates := make([]oid4vp.DCQLCredentialCandidate, 0, len(entries))
	for _, entry := range entries {
		// A credential the matcher cannot describe cannot be presented, so it
		// is skipped rather than failing the request.
		if candidate, err := dcqlCandidateFromSavedCredential(entry); err == nil {
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) == 0 {
		return nil, newAccessDeniedError("no credentials available for presentation")
	}
	if err := h.ResolveFederationTrustedAuthorities(ctx, candidates); err != nil {
		return nil, err
	}
	matches, err := oid4vp.ResolveSatisfiableDCQLCredentials(req.DcqlQuery, candidates)
	if err != nil {
		// OID4VP 1.0 Section 8.5: the Wallet does not hold the requested
		// credentials.
		return nil, newAccessDeniedError("%v", err)
	}
	if len(matches) == 0 {
		return nil, newAccessDeniedError("dcql_query cannot be satisfied by stored credentials")
	}
	selections := []CredentialSelection{}
	index := map[string]int{}
	for _, match := range matches {
		position, seen := index[match.CandidateID]
		if !seen {
			position = len(selections)
			index[match.CandidateID] = position
			selections = append(selections, CredentialSelection{CredentialID: match.CandidateID, DisclosedClaims: []string{}})
		}
		selection := &selections[position]
		selection.QueryIDs = append(selection.QueryIDs, match.QueryID)
		for _, claim := range match.Claims {
			if name := dcqlClaimDisclosureName(claim); !slices.Contains(selection.DisclosedClaims, name) {
				selection.DisclosedClaims = append(selection.DisclosedClaims, name)
			}
		}
	}
	return selections, nil
}

// submitDCQLPresentation answers an OpenID4VP 1.0 request with a DCQL
// vp_token built from p.
func (w *Wallet) submitDCQLPresentation(ctx context.Context, h *oid4vp.AdmittedRequest, p Presentation) (*presenterTypes.SubmitResult, error) {
	req := h.Request()
	if req.DcqlQuery == nil {
		return nil, fmt.Errorf("%w: dcql_query is not specified", ErrInvalidArgument)
	}
	if err := validateTransactionDataHolderBinding(&req); err != nil {
		return nil, err
	}
	vpToken, err := w.buildDCQLVPToken(ctx, h, &req, p)
	if err != nil {
		return nil, err
	}
	return w.presenter.SubmitDCQLResponse(ctx, h, vpToken)
}

// dcqlAnswer is one (credential query, credential) pair of a vp_token.
type dcqlAnswer struct {
	match      oid4vp.DCQLMatch
	credential resolvedCredential
}

// buildDCQLVPToken checks p against the query and serializes every answer
// before anything is sent.
func (w *Wallet) buildDCQLVPToken(ctx context.Context, h *oid4vp.AdmittedRequest, req *oid4vp.CredentialPresentationRequest, p Presentation) (map[string][]string, error) {
	credentials, err := w.resolveSelections(p.Credentials, p.Key)
	if err != nil {
		return nil, err
	}
	candidates := make([]oid4vp.DCQLCredentialCandidate, 0, len(credentials))
	for index, selection := range p.Credentials {
		if len(selection.QueryIDs) == 0 {
			// The vp_token is keyed by credential query id (Section 8.1).
			return nil, fmt.Errorf("%w: the selection for credential %q names no credential query", ErrInvalidArgument, credentials[index].id)
		}
		candidate, err := dcqlCandidateFromSavedCredential(credentials[index].saved)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, candidate)
	}
	if err := h.ResolveFederationTrustedAuthorities(ctx, candidates); err != nil {
		return nil, err
	}
	answers := []dcqlAnswer{}
	for index, selection := range p.Credentials {
		presented, candidate := credentials[index], candidates[index]
		for _, queryID := range selection.QueryIDs {
			claimSets, err := oid4vp.ResolveDCQLClaimSets(req.DcqlQuery, queryID, candidate)
			if err != nil {
				return nil, fmt.Errorf("the credential chosen for credential query %q cannot answer it: %w", queryID, err)
			}
			claims, ok := holderClaimSet(claimSets, selection.DisclosedClaims)
			if !ok {
				return nil, fmt.Errorf("%w: the claims kept for credential query %q do not cover any claim set it offers",
					oid4vp.ErrDCQLSelectionUnsatisfied, queryID)
			}
			answers = append(answers, dcqlAnswer{
				match:      oid4vp.DCQLMatch{QueryID: queryID, CandidateID: presented.id, Claims: claims},
				credential: presented,
			})
		}
	}
	matches := make([]oid4vp.DCQLMatch, 0, len(answers))
	for _, answer := range answers {
		matches = append(matches, answer.match)
	}
	if err := oid4vp.ValidateDCQLMatches(req.DcqlQuery, candidates, matches); err != nil {
		return nil, err
	}
	return w.serializeDCQLAnswers(req, p, answers)
}

// serializeDCQLAnswers renders one presentation per answer, applying the
// transaction_data assignment, disclosure limits and key binding rules.
func (w *Wallet) serializeDCQLAnswers(req *oid4vp.CredentialPresentationRequest, p Presentation, answers []dcqlAnswer) (map[string][]string, error) {
	presentedQueries := make([]string, 0, len(answers))
	for _, answer := range answers {
		presentedQueries = append(presentedQueries, answer.match.QueryID)
	}
	// OID4VP 1.0 Section 5.1: each transaction_data entry is authorized by
	// one presented credential, decided before anything is serialized.
	transactionDataOwners, err := assignTransactionDataOwners(req.TransactionData, presentedQueries)
	if err != nil {
		return nil, err
	}
	queries := make(map[string]oid4vp.CredentialQuery, len(req.DcqlQuery.Credentials))
	for _, query := range req.DcqlQuery.Credentials {
		queries[query.ID] = query
	}
	vpToken := make(map[string][]string, len(answers))
	for _, answer := range answers {
		saved, key, queryID := answer.credential.saved, answer.credential.key, answer.match.QueryID
		flavor, err := saved.Entry.SerializationFlavor()
		if err != nil {
			return nil, fmt.Errorf("failed to detect selected credential format: %w", err)
		}
		options, err := w.presentationOptions(req, p.SerializeOptions, flavor)
		if err != nil {
			return nil, err
		}
		// Section 8.4: the presentation carries every entry this query owns.
		// Only an SD-JWT VC Key Binding JWT carries transaction_data_hashes.
		owned, err := ownedTransactionData(req.TransactionData, queryID, transactionDataOwners)
		if err != nil {
			return nil, err
		}
		sdOpts, sdJWT := options.(*sdjwtvc.SdJwtVcPresentationOptions)
		if len(owned) > 0 && (!sdJWT || flavor != credential.SDJwtVC) {
			return nil, fmt.Errorf("transaction_data for credential query %q requires an SD-JWT VC with key binding (invalid_transaction_data)", queryID)
		}
		if sdJWT {
			if sdOpts.LimitDisclosureToSelectedClaims || len(sdOpts.SelectedClaims) > 0 {
				for _, name := range answer.match.Claims {
					if !slices.Contains(sdOpts.SelectedClaims, name) {
						return nil, fmt.Errorf("requested claim %q is not allowed by caller disclosure selection", name)
					}
				}
			}
			sdOpts.SelectedClaims = slices.Clone(answer.match.Claims)
			sdOpts.LimitDisclosureToSelectedClaims = true
			sdOpts.RequireRootClaimMatch = true
			sdOpts.RequireKeyBinding = sdOpts.RequireKeyBinding || queries[queryID].RequiresHolderBinding()
			// HAIP 1.0 Section 6.1.1.1: a credential with cryptographic holder
			// binding is always presented with a KB-JWT, even when the
			// Verifier waived the requirement.
			if w.profile.IsHAIP() && flavor == credential.SDJwtVC && sdJWTCarriesConfirmation(saved.Entry.Raw) {
				sdOpts.RequireKeyBinding = true
			}
			sdOpts.TransactionData = owned
			if len(owned) > 0 {
				sdOpts.RequireKeyBinding = true
			}
			sdOpts.TransactionDataHashesAlg = req.TransactionDataHashesAlg
			if sdOpts.TransactionDataHashesAlg == "" {
				sdOpts.TransactionDataHashesAlg = "sha-256"
			}
		}
		presentation, err := w.buildPresentation([]*SavedCredential{saved}, key, req)
		if err != nil {
			return nil, err
		}
		serialized, _, err := w.serializer.SerializePresentation(flavor, presentation, key, options)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize selected credential %s: %w", answer.credential.id, err)
		}
		vpToken[queryID] = append(vpToken[queryID], string(serialized))
	}
	return vpToken, nil
}

// newAccessDeniedError returns the OID4VP 1.0 Section 8.5 access_denied error.
func newAccessDeniedError(format string, args ...any) *oid4vp.AuthorizationRequestError {
	return &oid4vp.AuthorizationRequestError{Code: oid4vp.AccessDeniedError, Err: fmt.Errorf(format, args...)}
}

// holderClaimSet picks the claim set to disclose: the Verifier's preferred
// set when kept is nil, otherwise the first set, in the Verifier's order,
// whose every claim was kept (OID4VP 1.0 Section 6.4.1 returns a set whole).
func holderClaimSet(claimSets [][]string, kept []string) ([]string, bool) {
	if kept == nil {
		return claimSets[0], true
	}
	for _, claims := range claimSets {
		complete := true
		for _, claim := range claims {
			if !slices.Contains(kept, dcqlClaimDisclosureName(claim)) {
				complete = false
				break
			}
		}
		if complete {
			return claims, true
		}
	}
	return nil, false
}

// dcqlCandidateFromSavedCredential describes one credential the way the DCQL
// matcher reads it.
func dcqlCandidateFromSavedCredential(saved *SavedCredential) (oid4vp.DCQLCredentialCandidate, error) {
	flavor, err := saved.Entry.SerializationFlavor()
	if err != nil {
		return oid4vp.DCQLCredentialCandidate{}, fmt.Errorf("failed to detect the format of credential %q: %w", saved.Entry.Id, err)
	}
	vcFormat, _, err := flavor.OID4VPFormatIdentifier()
	if err != nil {
		return oid4vp.DCQLCredentialCandidate{}, fmt.Errorf("credential %q has no OID4VP format identifier: %w", saved.Entry.Id, err)
	}
	claimNames := []string{}
	claimValues := map[string]any{}
	claimObject := map[string]any{}
	if saved.Credential != nil && saved.Credential.Claims != nil {
		for name, value := range *saved.Credential.Claims {
			claimNames = append(claimNames, name)
			claimValues[name] = value
			claimObject[name] = value
		}
	}
	switch flavor {
	case credential.SDJwtVC:
		if reconstructed, reconstructErr := sdjwtvc.ReconstructClaimsObject(string(saved.Entry.Raw)); reconstructErr == nil {
			claimObject = reconstructed
		}
	case credential.JwtVc, credential.LdpVc:
		// OID4VP 1.0 Appendix B.1: a claims path pointer into a W3C
		// Verifiable Credential starts at the credential, not its subject.
		if root, ok := w3cCredentialObject(flavor, saved.Entry.Raw); ok {
			claimObject = root
		}
	}
	vct, issuer := "", ""
	var types []string
	if saved.Credential != nil {
		issuer = saved.Credential.Issuer
		if len(saved.Credential.Types) > 0 {
			vct = saved.Credential.Types[0]
			types = saved.Credential.Types
		}
	}
	holderBound := credentialHasHolderBinding(flavor, saved)
	return oid4vp.DCQLCredentialCandidate{
		ID:              saved.Entry.Id,
		Format:          vcFormat,
		VCT:             vct,
		Types:           types,
		Claims:          claimNames,
		ClaimValues:     claimValues,
		ClaimObject:     claimObject,
		HolderBound:     &holderBound,
		AuthorityKeyIDs: oid4vp.AuthorityKeyIdentifiersFromCredential(string(saved.Entry.Raw)),
		Issuer:          issuer,
	}, nil
}

// w3cCredentialObject decodes the Verifiable Credential a claims path pointer
// is applied to: the vc claim of a jwt_vc_json payload, or the ldp_vc
// document itself.
func w3cCredentialObject(flavor credential.SupportedSerializationFlavor, raw []byte) (map[string]any, bool) {
	document := raw
	if flavor == credential.JwtVc {
		parts := strings.Split(string(raw), ".")
		if len(parts) != 3 {
			return nil, false
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, false
		}
		document = payload
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, false
	}
	if flavor == credential.JwtVc {
		vc, ok := object["vc"].(map[string]any)
		return vc, ok
	}
	return object, true
}

// dcqlClaimDisclosureName is the disclosure name an encoded DCQL claim path
// ends in: a bare name is its own, and a JSON array path yields its last string
// component, so ["nationalities",1] is named "nationalities". Anything else is
// returned unchanged so it matches no kept name.
func dcqlClaimDisclosureName(encoded string) string {
	if !strings.HasPrefix(encoded, "[") {
		return encoded
	}
	var path []any
	if err := json.Unmarshal([]byte(encoded), &path); err != nil {
		return encoded
	}
	for index := len(path) - 1; index >= 0; index-- {
		if name, ok := path[index].(string); ok {
			return name
		}
	}
	return encoded
}

// credentialHasHolderBinding reports whether a stored credential carries a
// cryptographic holder binding key.
func credentialHasHolderBinding(flavor credential.SupportedSerializationFlavor, entry *SavedCredential) bool {
	if flavor == credential.SDJwtVC {
		return sdJWTCarriesConfirmation(entry.Entry.Raw)
	}
	if entry.Credential == nil || entry.Credential.Claims == nil {
		return false
	}
	_, present := (*entry.Credential.Claims)["cnf"]
	return present
}

// sdJWTCarriesConfirmation reports whether the issuer JWT payload of an
// SD-JWT VC carries a cnf claim, that is, cryptographic holder binding.
func sdJWTCarriesConfirmation(raw []byte) bool {
	issuerJWT := string(raw)
	if separator := strings.IndexByte(issuerJWT, '~'); separator >= 0 {
		issuerJWT = issuerJWT[:separator]
	}
	parts := strings.Split(issuerJWT, ".")
	if len(parts) != 3 {
		return false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return false
	}
	_, present := payload["cnf"]
	return present
}
