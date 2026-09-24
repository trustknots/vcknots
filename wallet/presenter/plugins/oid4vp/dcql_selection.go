package oid4vp

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// DCQLCredentialCandidate describes a wallet credential that may satisfy a DCQL request.
type DCQLCredentialCandidate struct {
	ID     string
	Format string
	VCT    string
	Claims []string
	// ClaimValues contains the top-level claim values used for values
	// restrictions. It may be omitted for queries without values; a restricted
	// claim with no supplied value cannot satisfy the query. Supply
	// json.Number for integers beyond the exact float range.
	ClaimValues map[string]any
	// ClaimObject is the decoded credential root object with all selectively
	// disclosable claims applied, including nested object properties and array
	// element disclosures. When non-nil it is the authoritative source for
	// claims path pointer evaluation; otherwise Claims and ClaimValues answer
	// single-segment paths only.
	ClaimObject map[string]any
	// HolderBound reports whether the credential carries a cryptographic holder
	// binding key (SD-JWT VC cnf claim). Nil means the caller did not evaluate
	// holder binding, and the candidate is not excluded. A query that requires
	// holder binding is not satisfied by a candidate marked unbound (OID4VP 1.0
	// Appendix B.3).
	HolderBound *bool
	// AuthorityKeyIDs lists the base64url-encoded Authority Key Identifiers of
	// the X.509 certificates in the credential's issuer chain. It is matched
	// against aki trusted_authorities queries (OID4VP 1.0 Section 6.1.1.1).
	AuthorityKeyIDs []string
	// Issuer is the credential's issuer identifier (iss, or the W3C VC
	// issuer).
	Issuer string
	// FederationEntityIDs lists the Entity Identifiers of the validated Trust
	// Chains from Issuer to a configured Trust Anchor, which
	// AdmittedRequest.ResolveFederationTrustedAuthorities sets. It is matched
	// against openid_federation trusted_authorities queries (OID4VP 1.0
	// Section 6.1.1.3).
	FederationEntityIDs []string
	// Types lists the W3C VC type values of the credential. It is matched
	// against meta.type_values (OID4VP 1.0 Appendix B.1.1).
	Types []string
}

// DCQLMatch is one candidate answering one DCQL credential query, with the
// claims path pointers it discloses: a bare name for a one-segment path,
// otherwise the JSON-encoded path with every null replaced by an index.
type DCQLMatch struct {
	QueryID     string
	CandidateID string
	Claims      []string
}

// dcqlQueryPlan is the validated structure of one DCQL query: every credential
// query by id, and the claim set options each of them offers. Choosing
// credentials for the request and validating a choice made outside this library
// share it, so both apply the same structural rules to the same request.
type dcqlQueryPlan struct {
	queries      map[string]CredentialQuery
	claimOptions map[string][][]DCQLClaimQuery
}

// planDCQLQuery validates the request structure defined in OID4VP 1.0 Sections
// 6.1 to 6.3 - credential query ids, claims, claim_sets and credential_sets -
// and returns the plan the selection paths work from.
func planDCQLQuery(query *DcqlQuery) (dcqlQueryPlan, error) {
	if query == nil {
		return dcqlQueryPlan{}, fmt.Errorf("dcql_query is required")
	}
	if len(query.Credentials) == 0 {
		return dcqlQueryPlan{}, fmt.Errorf("dcql_query.credentials must not be empty")
	}

	plan := dcqlQueryPlan{
		queries:      make(map[string]CredentialQuery, len(query.Credentials)),
		claimOptions: make(map[string][][]DCQLClaimQuery, len(query.Credentials)),
	}
	ids := map[string]bool{}
	for _, credentialQuery := range query.Credentials {
		if !credentialQueryIDPattern.MatchString(credentialQuery.ID) || ids[credentialQuery.ID] {
			return dcqlQueryPlan{}, fmt.Errorf("DCQL credential query ids must be valid and unique")
		}
		ids[credentialQuery.ID] = true
		options, err := dcqlClaimOptions(credentialQuery)
		if err != nil {
			return dcqlQueryPlan{}, err
		}
		plan.queries[credentialQuery.ID] = credentialQuery
		plan.claimOptions[credentialQuery.ID] = options
	}
	if query.CredentialSets != nil && len(query.CredentialSets) == 0 {
		return dcqlQueryPlan{}, fmt.Errorf("DCQL credential_sets must not be empty")
	}
	for _, set := range query.CredentialSets {
		if err := validateDCQLTypedOptions(set.Options, ids, false); err != nil {
			return dcqlQueryPlan{}, fmt.Errorf("invalid DCQL credential_set: %w", err)
		}
	}
	return plan, nil
}

// ResolveSatisfiableDCQLCredentials is the library's own choice: for every
// credential query the request requires, the candidates that satisfy it with
// the first claim set any candidate satisfies. A Holder's choice is checked
// with ValidateDCQLMatches instead.
//
// A request no available credential can answer is reported as an error wrapping
// ErrDCQLSelectionUnsatisfied, the same sentinel a rejected Holder choice
// carries, so a caller tells "this wallet cannot answer the request" from a
// malformed query with errors.Is.
func ResolveSatisfiableDCQLCredentials(query *DcqlQuery, candidates []DCQLCredentialCandidate) ([]DCQLMatch, error) {
	plan, err := planDCQLQuery(query)
	if err != nil {
		return nil, err
	}

	satisfiable := map[string][]DCQLMatch{}
	for _, credentialQuery := range query.Credentials {
		selections := resolveDCQLCredentialQuery(credentialQuery, plan.claimOptions[credentialQuery.ID], candidates)
		if len(selections) > 0 {
			satisfiable[credentialQuery.ID] = selections
		}
	}

	if len(query.CredentialSets) == 0 {
		selections := make([]DCQLMatch, 0, len(satisfiable))
		for _, credentialQuery := range query.Credentials {
			if querySelections, ok := satisfiable[credentialQuery.ID]; ok {
				selections = append(selections, querySelections...)
			} else {
				return nil, fmt.Errorf("%w: required DCQL credential query %q cannot be satisfied", ErrDCQLSelectionUnsatisfied, credentialQuery.ID)
			}
		}
		return selections, nil
	}

	selected := map[string][]DCQLMatch{}
	for _, credentialSet := range query.CredentialSets {
		matchingOption := []string(nil)
		for _, option := range credentialSet.Options {
			if everyDCQLCredentialIDSatisfiable(option, satisfiable) {
				matchingOption = option
				break
			}
		}
		if matchingOption == nil {
			if credentialSet.IsRequired() {
				return nil, fmt.Errorf("%w: required DCQL credential_set cannot be satisfied", ErrDCQLSelectionUnsatisfied)
			}
			continue
		}
		for _, queryID := range matchingOption {
			selected[queryID] = satisfiable[queryID]
		}
	}

	selections := make([]DCQLMatch, 0, len(selected))
	for _, credentialQuery := range query.Credentials {
		if querySelections, ok := selected[credentialQuery.ID]; ok {
			selections = append(selections, querySelections...)
		}
	}
	return selections, nil
}

// ResolveDCQLClaimSets returns, in the Verifier's order of preference (OID4VP
// 1.0 Section 6.4.1), the claims each claim set of credential query queryID
// resolves to for candidate, leaving out the sets candidate cannot satisfy. A
// Wallet whose Holder chooses the claim set picks one of these and checks the
// result with ValidateDCQLMatches.
//
// A candidate that fails the query's constraints or satisfies no claim set, and
// a queryID the request does not contain, are reported as errors wrapping
// ErrDCQLSelectionUnsatisfied.
func ResolveDCQLClaimSets(query *DcqlQuery, queryID string, candidate DCQLCredentialCandidate) ([][]string, error) {
	plan, err := planDCQLQuery(query)
	if err != nil {
		return nil, err
	}
	credentialQuery, requested := plan.queries[queryID]
	if !requested {
		return nil, fmt.Errorf("%w: the request contains no credential query %q", ErrDCQLSelectionUnsatisfied, queryID)
	}
	if err := dcqlCandidateConstraintError(credentialQuery, candidate); err != nil {
		return nil, err
	}
	var claimSets [][]string
	for _, claims := range plan.claimOptions[queryID] {
		if resolved, satisfied := matchDCQLClaims(claims, candidate); satisfied {
			claimSets = append(claimSets, resolved)
		}
	}
	if len(claimSets) == 0 {
		return nil, fmt.Errorf("%w: credential %q satisfies no claim set of credential query %q", ErrDCQLSelectionUnsatisfied, candidate.ID, queryID)
	}
	return claimSets, nil
}

// ValidateDCQLMatches checks matches chosen outside this library, typically
// by the Holder, against query. OID4VP 1.0 Sections 6.2 and 6.3 leave the
// choice of credential_set option and claim set to the Wallet; this function
// only checks it: each match satisfies its credential query with exactly one
// of its claim sets, multiple is honoured, every required credential_set has
// an answered option, and nothing outside an answered option is presented.
//
// An unacceptable choice wraps ErrDCQLSelectionUnsatisfied; a malformed query
// is a plain structural error.
func ValidateDCQLMatches(query *DcqlQuery, candidates []DCQLCredentialCandidate, matches []DCQLMatch) error {
	plan, err := planDCQLQuery(query)
	if err != nil {
		return err
	}
	byID := make(map[string]DCQLCredentialCandidate, len(candidates))
	for _, candidate := range candidates {
		byID[candidate.ID] = candidate
	}

	presented := map[string][]DCQLMatch{}
	for _, selection := range matches {
		credentialQuery, requested := plan.queries[selection.QueryID]
		if !requested {
			return fmt.Errorf("%w: selection references credential query %q, which the request does not contain", ErrDCQLSelectionUnsatisfied, selection.QueryID)
		}
		candidate, stored := byID[selection.CandidateID]
		if !stored {
			return fmt.Errorf("%w: selection references credential %q, which this wallet cannot present", ErrDCQLSelectionUnsatisfied, selection.CandidateID)
		}
		for _, earlier := range presented[selection.QueryID] {
			if earlier.CandidateID == selection.CandidateID {
				return fmt.Errorf("%w: credential %q is selected twice for credential query %q", ErrDCQLSelectionUnsatisfied, selection.CandidateID, selection.QueryID)
			}
		}
		// OID4VP 1.0 Section 6.1: multiple defaults to false, and "only one
		// Credential will be returned" for such a Credential Query.
		if !credentialQuery.Multiple && len(presented[selection.QueryID]) > 0 {
			return fmt.Errorf("%w: credential query %q does not accept more than one credential", ErrDCQLSelectionUnsatisfied, selection.QueryID)
		}
		if err := validateDCQLSelectedCandidate(credentialQuery, plan.claimOptions[selection.QueryID], candidate, selection); err != nil {
			return err
		}
		presented[selection.QueryID] = append(presented[selection.QueryID], selection)
	}
	return validateDCQLPresentedSets(query, presented)
}

// validateDCQLSelectedCandidate applies one credential query's own constraints
// to one selected credential, and requires its disclosed claims to be exactly
// one of the claim sets that query offers.
func validateDCQLSelectedCandidate(query CredentialQuery, claimOptions [][]DCQLClaimQuery, candidate DCQLCredentialCandidate, selection DCQLMatch) error {
	if err := dcqlCandidateConstraintError(query, candidate); err != nil {
		return err
	}
	for _, claims := range claimOptions {
		resolved, satisfied := matchDCQLClaims(claims, candidate)
		if satisfied && sameDCQLClaimSelection(resolved, selection.Claims) {
			return nil
		}
	}
	return fmt.Errorf("%w: the claims selected for credential query %q are not one of the claim sets it offers", ErrDCQLSelectionUnsatisfied, query.ID)
}

// dcqlCandidateConstraintError reports why candidate cannot answer query before
// any claim is considered: its format, meta type constraint, holder binding or
// issuer. OID4VP 1.0 Section 6.4.2 treats such a credential as absent. The
// error wraps ErrDCQLSelectionUnsatisfied unless the query's meta is malformed.
func dcqlCandidateConstraintError(query CredentialQuery, candidate DCQLCredentialCandidate) error {
	vctValues, validVCT := dcqlVCTValues(query.Meta)
	if !validVCT {
		return fmt.Errorf("credential query %q has an invalid meta.vct_values", query.ID)
	}
	typeValues, validTypes := dcqlTypeValues(query.Format, query.Meta)
	if !validTypes {
		return fmt.Errorf("credential query %q has an invalid meta.type_values", query.ID)
	}
	switch {
	case candidate.Format != query.Format:
		return fmt.Errorf("%w: credential %q is in format %q, and credential query %q requests %q", ErrDCQLSelectionUnsatisfied, candidate.ID, candidate.Format, query.ID, query.Format)
	case len(vctValues) > 0 && !containsString(vctValues, candidate.VCT):
		return fmt.Errorf("%w: credential %q does not carry a vct credential query %q accepts", ErrDCQLSelectionUnsatisfied, candidate.ID, query.ID)
	case len(typeValues) > 0 && !matchesDCQLTypeValues(typeValues, candidate.Types):
		return fmt.Errorf("%w: credential %q does not carry the types credential query %q accepts", ErrDCQLSelectionUnsatisfied, candidate.ID, query.ID)
	case query.Format == "dc+sd-jwt" && query.RequiresHolderBinding() && candidate.HolderBound != nil && !*candidate.HolderBound:
		// OID4VP 1.0 Appendix B.3: "SD-JWTs that do not support Holder Binding
		// (i.e., do not have a cnf Claim) cannot be returned in this case."
		return fmt.Errorf("%w: credential %q has no cryptographic holder binding, which credential query %q requires", ErrDCQLSelectionUnsatisfied, candidate.ID, query.ID)
	case !candidateMatchesTrustedAuthorities(query.TrustedAuthorities, candidate):
		return fmt.Errorf("%w: credential %q is outside the trusted authorities credential query %q accepts", ErrDCQLSelectionUnsatisfied, candidate.ID, query.ID)
	}
	return nil
}

// sameDCQLClaimSelection compares a resolved claim set with the claims a
// selection carries, ignoring order: a consent screen may present the claims of
// a claim set in any order, but must not add or drop one.
func sameDCQLClaimSelection(resolved, selected []string) bool {
	if len(resolved) != len(selected) {
		return false
	}
	for _, name := range resolved {
		if !containsString(selected, name) {
			return false
		}
	}
	for _, name := range selected {
		if !containsString(resolved, name) {
			return false
		}
	}
	return true
}

// validateDCQLPresentedSets applies the request's requirement structure to the
// credential queries the selection answered. Without credential_sets every
// credential query is required (OID4VP 1.0 Section 6.4.2); with them, every
// required set needs one fully answered option, and a credential query that no
// answered option contains would disclose a credential the request never asked
// for in that combination.
func validateDCQLPresentedSets(query *DcqlQuery, presented map[string][]DCQLMatch) error {
	if len(query.CredentialSets) == 0 {
		for _, credentialQuery := range query.Credentials {
			if len(presented[credentialQuery.ID]) == 0 {
				return fmt.Errorf("%w: required DCQL credential query %q is not answered", ErrDCQLSelectionUnsatisfied, credentialQuery.ID)
			}
		}
		return nil
	}
	answered := map[string]bool{}
	for _, credentialSet := range query.CredentialSets {
		matched := false
		for _, option := range credentialSet.Options {
			if !everyDCQLCredentialIDSatisfiable(option, presented) {
				continue
			}
			matched = true
			for _, id := range option {
				answered[id] = true
			}
		}
		if !matched && credentialSet.IsRequired() {
			return fmt.Errorf("%w: no option of a required DCQL credential_set is answered", ErrDCQLSelectionUnsatisfied)
		}
	}
	for _, credentialQuery := range query.Credentials {
		if len(presented[credentialQuery.ID]) > 0 && !answered[credentialQuery.ID] {
			return fmt.Errorf("%w: credential query %q is not part of any answered credential_set option", ErrDCQLSelectionUnsatisfied, credentialQuery.ID)
		}
	}
	return nil
}

// resolveDCQLCredentialQuery returns all candidates that satisfy the query for
// the first satisfiable claim set. When query.Multiple is false only the first
// matching candidate is returned (OID4VP 1.0 Section 6.1/8.1); otherwise every
// matching candidate is returned so it can be presented separately.
func resolveDCQLCredentialQuery(query CredentialQuery, claimOptions [][]DCQLClaimQuery, candidates []DCQLCredentialCandidate) []DCQLMatch {
	// Prefer the first satisfiable claim set across all candidates, rather than
	// selecting a later claim set merely because its credential appeared first.
	for _, claims := range claimOptions {
		selections := []DCQLMatch{}
		for _, candidate := range candidates {
			if dcqlCandidateConstraintError(query, candidate) != nil {
				continue
			}
			requestedClaims, ok := matchDCQLClaims(claims, candidate)
			if !ok {
				continue
			}
			selections = append(selections, DCQLMatch{
				QueryID:     query.ID,
				CandidateID: candidate.ID,
				Claims:      requestedClaims,
			})
			if !query.Multiple {
				break
			}
		}
		if len(selections) > 0 {
			return selections
		}
	}
	return nil
}

// matchDCQLClaims resolves one claim set against candidate and returns the
// encoded claims path pointers to disclose. A claim with values discloses only
// the elements whose value matches (OID4VP 1.0 Section 6.4.1 treats the others
// as absent), so a null component is replaced by the index of each match.
func matchDCQLClaims(claimQueries []DCQLClaimQuery, candidate DCQLCredentialCandidate) ([]string, bool) {
	claims := make([]string, 0, len(claimQueries))
	add := func(path []any) {
		encoded := encodeDCQLClaimPath(path)
		if !containsString(claims, encoded) {
			claims = append(claims, encoded)
		}
	}
	for _, claim := range claimQueries {
		elements, satisfied := candidate.selectDCQLClaimElements(claim.Path)
		if !satisfied {
			return nil, false
		}
		if claim.Values == nil {
			add(claim.Path)
			continue
		}
		matched := false
		for _, element := range elements {
			for _, expected := range claim.Values {
				if dcqlClaimValuesEqual(element.value, expected) {
					matched = true
					add(element.path)
					break
				}
			}
		}
		if !matched {
			return nil, false
		}
	}
	return claims, true
}

// dcqlClaimElement is one element a claims path pointer selected, with the
// pointer that addresses it alone: every null component replaced by an index.
type dcqlClaimElement struct {
	path  []any
	value any
}

// selectDCQLClaimElements applies a claims path pointer (OID4VP 1.0 Section 7.1.1)
// to the candidate. With a decoded ClaimObject the full nested path semantics
// apply; the Claims/ClaimValues representation supports one-segment string
// paths only.
func (candidate DCQLCredentialCandidate) selectDCQLClaimElements(path []any) ([]dcqlClaimElement, bool) {
	if candidate.ClaimObject != nil {
		return evaluateDCQLClaimPath(candidate.ClaimObject, path)
	}
	if len(path) != 1 {
		return nil, false
	}
	name, ok := path[0].(string)
	if !ok || name == "" || !containsString(candidate.Claims, name) {
		return nil, false
	}
	if candidate.ClaimValues == nil {
		return []dcqlClaimElement{}, true
	}
	value, exists := candidate.ClaimValues[name]
	if !exists {
		return []dcqlClaimElement{}, true
	}
	return []dcqlClaimElement{{path: path, value: value}}, true
}

// evaluateDCQLClaimPath processes a claims path pointer from left to right over
// a decoded JSON credential root. It returns the selected elements and reports
// whether any element was selected.
func evaluateDCQLClaimPath(root map[string]any, path []any) ([]dcqlClaimElement, bool) {
	current := []dcqlClaimElement{{path: []any{}, value: root}}
	for _, component := range path {
		next := []dcqlClaimElement{}
		extend := func(element dcqlClaimElement, step any, value any) {
			concrete := make([]any, len(element.path), len(element.path)+1)
			copy(concrete, element.path)
			next = append(next, dcqlClaimElement{path: append(concrete, step), value: value})
		}
		switch value := component.(type) {
		case string:
			for _, element := range current {
				object, ok := element.value.(map[string]any)
				if !ok {
					continue
				}
				if selected, exists := object[value]; exists {
					extend(element, value, selected)
				}
			}
		case nil:
			for _, element := range current {
				array, ok := element.value.([]any)
				if !ok {
					continue
				}
				for index, item := range array {
					extend(element, index, item)
				}
			}
		default:
			index, ok := dcqlPathIndex(value)
			if !ok {
				return nil, false
			}
			for _, element := range current {
				array, ok := element.value.([]any)
				if !ok {
					continue
				}
				if index < int64(len(array)) {
					extend(element, component, array[index])
				}
			}
		}
		if len(next) == 0 {
			return nil, false
		}
		current = next
	}
	return current, true
}

// encodeDCQLClaimPath serializes a path for the serializer's disclosure
// selector. A single string component is its plain name; anything else is
// JSON-encoded, e.g. ["address","postal_code"]
// or ["degrees",null,"type"] or ["nationalities",1].
func encodeDCQLClaimPath(path []any) string {
	if len(path) == 1 {
		if name, ok := path[0].(string); ok {
			return name
		}
	}
	encoded, err := json.Marshal(path)
	if err != nil {
		return fmt.Sprintf("%v", path)
	}
	return string(encoded)
}

// dcqlPathIndex returns a non-negative integer path component. It accepts the
// json.Number produced by the DCQL decoder and the Go integer types used by
// programmatically constructed queries.
func dcqlPathIndex(value any) (int64, bool) {
	switch number := value.(type) {
	case json.Number:
		index, err := number.Int64()
		if err != nil || index < 0 {
			return 0, false
		}
		return index, true
	case float64:
		if number < 0 || number != float64(int64(number)) {
			return 0, false
		}
		return int64(number), true
	case int:
		if number < 0 {
			return 0, false
		}
		return int64(number), true
	case int64:
		if number < 0 {
			return 0, false
		}
		return number, true
	case int32:
		if number < 0 {
			return 0, false
		}
		return int64(number), true
	default:
		return 0, false
	}
}

// candidateMatchesTrustedAuthorities applies OID4VP 1.0 Section 6.1.1: a
// credential matches when it matches one of the values of one of the entries.
// An "aki" value is an Authority Key Identifier of the issuer chain (Section
// 6.1.1.1); an "openid_federation" value is an Entity Identifier on a
// validated Trust Chain of the issuer (Section 6.1.1.3). An entry of any other
// type matches no credential, so a query naming only such types is
// unsatisfiable rather than unconstrained.
func candidateMatchesTrustedAuthorities(authorities []TrustedAuthority, candidate DCQLCredentialCandidate) bool {
	if len(authorities) == 0 {
		return true
	}
	for _, authority := range authorities {
		var evidence []string
		switch authority.Type {
		case "aki":
			evidence = candidate.AuthorityKeyIDs
		case trustedAuthorityOpenIDFederation:
			evidence = candidate.FederationEntityIDs
		default:
			continue
		}
		for _, value := range authority.Values {
			if containsString(evidence, value) {
				return true
			}
		}
	}
	return false
}

func dcqlClaimOptions(query CredentialQuery) ([][]DCQLClaimQuery, error) {
	if query.Claims != nil && len(query.Claims) == 0 {
		return nil, fmt.Errorf("DCQL claims must not be empty")
	}
	if query.Claims == nil && query.ClaimSets != nil {
		return nil, fmt.Errorf("DCQL claim_sets requires claims")
	}
	ids := map[string]bool{}
	byID := map[string]DCQLClaimQuery{}
	for _, claim := range query.Claims {
		if claim.ID != "" || query.ClaimSets != nil {
			if !credentialQueryIDPattern.MatchString(claim.ID) || ids[claim.ID] {
				return nil, fmt.Errorf("DCQL claim ids must be valid and unique")
			}
			ids[claim.ID] = true
			byID[claim.ID] = claim
		}
		if len(claim.Path) == 0 || (claim.Values != nil && len(claim.Values) == 0) {
			return nil, fmt.Errorf("DCQL claim paths and values must not be empty")
		}
		for _, value := range claim.Values {
			if !isDCQLClaimValue(value) {
				return nil, fmt.Errorf("DCQL values must be strings, integers or booleans")
			}
		}
	}
	if query.ClaimSets == nil {
		return [][]DCQLClaimQuery{query.Claims}, nil
	}
	if err := validateDCQLTypedOptions(query.ClaimSets, ids, true); err != nil {
		return nil, fmt.Errorf("invalid DCQL claim_sets: %w", err)
	}
	options := make([][]DCQLClaimQuery, 0, len(query.ClaimSets))
	for _, option := range query.ClaimSets {
		claims := make([]DCQLClaimQuery, 0, len(option))
		for _, id := range option {
			claims = append(claims, byID[id])
		}
		options = append(options, claims)
	}
	return options, nil
}

func validateDCQLTypedOptions(options [][]string, ids map[string]bool, allowEmptyOption bool) error {
	if len(options) == 0 {
		return fmt.Errorf("options must not be empty")
	}
	for _, option := range options {
		if option == nil {
			return fmt.Errorf("each option must be an array, not null")
		}
		if !allowEmptyOption && len(option) == 0 {
			return fmt.Errorf("each option must not be empty")
		}
		for _, id := range option {
			if !ids[id] {
				return fmt.Errorf("option references undefined identifier %q", id)
			}
		}
	}
	return nil
}

func isDCQLClaimValue(value any) bool {
	switch value.(type) {
	case string, bool:
		return true
	default:
		_, ok := dcqlIntegerValue(value)
		return ok
	}
}

func dcqlClaimValuesEqual(actual, expected any) bool {
	switch expected := expected.(type) {
	case string:
		actual, ok := actual.(string)
		return ok && actual == expected
	case bool:
		actual, ok := actual.(bool)
		return ok && actual == expected
	default:
		expectedNumber, validExpected := dcqlIntegerValue(expected)
		actualNumber, validActual := dcqlIntegerValue(actual)
		return validExpected && validActual && expectedNumber == actualNumber
	}
}

// dcqlIntegerValue returns an exact coefficient/exponent representation of a
// JSON integer. Decimal exponents stay symbolic, so a short wire value such as
// 1e1000000000 never allocates a billion-digit integer. json.Number avoids
// rounding large input integers through float64.
func dcqlIntegerValue(value any) (string, bool) {
	switch number := value.(type) {
	case float64:
		// A decoder may already have rounded a large integer. Such a value
		// cannot safely prove equality with the original credential claim.
		if number < -(1<<53-1) || number > 1<<53-1 {
			return "", false
		}
	case float32:
		if number < -(1<<24-1) || number > 1<<24-1 {
			return "", false
		}
	case json.Number, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
	default:
		return "", false
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", false
	}
	mantissa := string(encoded)
	exponent := new(big.Int)
	if i := strings.IndexAny(mantissa, "eE"); i >= 0 {
		if _, ok := exponent.SetString(mantissa[i+1:], 10); !ok {
			return "", false
		}
		mantissa = mantissa[:i]
	}
	negative := strings.HasPrefix(mantissa, "-")
	mantissa = strings.TrimPrefix(mantissa, "-")
	if i := strings.IndexByte(mantissa, '.'); i >= 0 {
		exponent.Sub(exponent, big.NewInt(int64(len(mantissa)-i-1)))
		mantissa = mantissa[:i] + mantissa[i+1:]
	}
	mantissa = strings.TrimLeft(mantissa, "0")
	if mantissa == "" {
		return "0", true
	}
	coefficient := strings.TrimRight(mantissa, "0")
	exponent.Add(exponent, big.NewInt(int64(len(mantissa)-len(coefficient))))
	if exponent.Sign() < 0 {
		return "", false
	}
	if negative {
		coefficient = "-" + coefficient
	}
	return coefficient + "e" + exponent.String(), true
}

func everyDCQLCredentialIDSatisfiable(ids []string, satisfiable map[string][]DCQLMatch) bool {
	if len(ids) == 0 {
		return false
	}
	for _, id := range ids {
		selections, ok := satisfiable[id]
		if !ok || len(selections) == 0 {
			return false
		}
	}
	return true
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// dcqlVCTValues handles both a directly constructed Go query and decoded JSON.
func dcqlVCTValues(meta map[string]any) ([]string, bool) {
	raw, exists := meta["vct_values"]
	if !exists {
		return nil, true
	}
	switch values := raw.(type) {
	case []string:
		return values, true
	case []any:
		result := make([]string, 0, len(values))
		for _, value := range values {
			text, ok := value.(string)
			if !ok {
				return nil, false
			}
			result = append(result, text)
		}
		return result, true
	default:
		return nil, false
	}
}

// dcqlTypeValues returns meta.type_values for a W3C VC format (OID4VP 1.0
// Appendix B.1.1), from a directly constructed Go query or decoded JSON.
func dcqlTypeValues(format string, meta map[string]any) ([][]string, bool) {
	if format != "jwt_vc_json" && format != "ldp_vc" {
		return nil, true
	}
	raw, exists := meta["type_values"]
	if !exists {
		return nil, true
	}
	if values, ok := raw.([][]string); ok {
		return values, true
	}
	alternatives, ok := raw.([]any)
	if !ok {
		return nil, false
	}
	result := make([][]string, 0, len(alternatives))
	for _, alternative := range alternatives {
		switch types := alternative.(type) {
		case []string:
			result = append(result, types)
		case []any:
			strs := make([]string, 0, len(types))
			for _, value := range types {
				text, ok := value.(string)
				if !ok {
					return nil, false
				}
				strs = append(strs, text)
			}
			result = append(result, strs)
		default:
			return nil, false
		}
	}
	return result, true
}

// w3cCredentialsVocabulary is the IRI the W3C VC base context maps its terms
// to, in both the VCDM 1.1 and 2.0 contexts.
const w3cCredentialsVocabulary = "https://www.w3.org/2018/credentials#"

// matchesDCQLTypeValues reports whether every type of one type_values
// alternative is among the credential's types. type_values holds fully
// expanded IRIs; without a JSON-LD processor the base context term
// VerifiableCredential is expanded to its IRI, and any other type is compared
// as written, which Appendix B.1.1 permits for types no @context defines. A
// type defined only by another context therefore does not match its IRI.
func matchesDCQLTypeValues(alternatives [][]string, types []string) bool {
	expanded := make([]string, 0, len(types)+1)
	for _, value := range types {
		expanded = append(expanded, value)
		if value == "VerifiableCredential" {
			expanded = append(expanded, w3cCredentialsVocabulary+value)
		}
	}
	for _, alternative := range alternatives {
		if len(alternative) == 0 {
			continue
		}
		matched := true
		for _, value := range alternative {
			if !containsString(expanded, value) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}
