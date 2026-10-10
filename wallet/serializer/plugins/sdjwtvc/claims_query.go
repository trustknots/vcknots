package sdjwtvc

import (
	"fmt"
	"math"
	"slices"

	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/serializer/types"
)

// selectDisclosures returns, in their original order, the disclosures a
// presentation must carry to answer query: those revealing each requested claim,
// the ones on the way to it and the ones nested inside it (OID4VP 1.0 Sections
// 6.4.1 and 7). A query without claims yields none, so only the issuer-signed JWT
// and the Key Binding JWT are presented. Claims Query values are not matched; the
// specification leaves that to the Wallet (SHOULD). allowed, when not empty, caps
// what the query may reveal.
func selectDisclosures(payload map[string]any, encoded []string, sdAlg string, query *types.ClaimsQuery, allowed []string) ([]string, error) {
	if len(query.Claims) == 0 {
		return nil, nil
	}

	byDigest := make(map[string]credential.SDJwtDisclosure, len(encoded))
	digests := make([]string, len(encoded))
	for i, e := range encoded {
		disc, err := parseDisclosure(e, sdAlg)
		if err != nil {
			continue // a disclosure that cannot be parsed cannot be referenced either
		}
		byDigest[disc.Digest] = disc
		digests[i] = disc.Digest
	}

	revealing := make([][]string, len(query.Claims))
	found := make([]bool, len(query.Claims))
	for i, claim := range query.Claims {
		revealing[i], found[i] = resolveClaim(payload, byDigest, claim.Path)
	}

	chosen, err := chooseClaims(query, found)
	if err != nil {
		return nil, err
	}
	if err := withinAllowedClaims(query, chosen, allowed); err != nil {
		return nil, err
	}

	keep := make(map[string]bool)
	for _, i := range chosen {
		for _, digest := range revealing[i] {
			keep[digest] = true
		}
	}
	var selected []string
	for i, e := range encoded {
		if digests[i] == "" || !keep[digests[i]] {
			continue
		}
		// SelectedClaims caps what the query may reveal. An array element's disclosure
		// carries no claim name of its own, so withinAllowedClaims covers those by the
		// root of the path that selected them.
		disc := byDigest[digests[i]]
		if len(allowed) > 0 && !disc.IsArrayElement && !slices.Contains(allowed, disc.Name) {
			return nil, fmt.Errorf("%w: %q is not among SelectedClaims", types.ErrClaimsNotSatisfiable, disc.Name)
		}
		selected = append(selected, e)
	}
	return selected, nil
}

// withinAllowedClaims refuses a query that names a claim the caller did not allow.
// It checks the root of each chosen path, because an array element's disclosure
// carries no claim name of its own and so cannot be checked by name as the
// selected disclosures are collected.
func withinAllowedClaims(query *types.ClaimsQuery, chosen []int, allowed []string) error {
	if len(allowed) == 0 {
		return nil
	}
	for _, i := range chosen {
		path := query.Claims[i].Path
		root, ok := "", false
		if len(path) > 0 {
			root, ok = path[0].(string)
		}
		if !ok || !slices.Contains(allowed, root) {
			return fmt.Errorf("%w: path %v is not among SelectedClaims", types.ErrClaimsNotSatisfiable, path)
		}
	}
	return nil
}

// chooseClaims returns the indexes of the claims to disclose: all of them, or the
// first claim_sets option whose claims are all present (OID4VP 1.0 Section 6.4.1).
func chooseClaims(query *types.ClaimsQuery, found []bool) ([]int, error) {
	if len(query.ClaimSets) == 0 {
		chosen := make([]int, 0, len(query.Claims))
		for i, claim := range query.Claims {
			if !found[i] {
				return nil, fmt.Errorf("%w: no claim at path %v", types.ErrClaimsNotSatisfiable, claim.Path)
			}
			chosen = append(chosen, i)
		}
		return chosen, nil
	}

	byID := make(map[string]int, len(query.Claims))
	for i, claim := range query.Claims {
		byID[claim.ID] = i
	}
	for _, option := range query.ClaimSets {
		if len(option) == 0 {
			continue // an empty option selects nothing, so it cannot be the answer
		}
		chosen := make([]int, 0, len(option))
		for _, id := range option {
			i, ok := byID[id]
			if !ok || !found[i] {
				chosen = nil
				break
			}
			chosen = append(chosen, i)
		}
		if chosen != nil {
			return chosen, nil
		}
	}
	return nil, fmt.Errorf("%w: no claim_sets option can be satisfied", types.ErrClaimsNotSatisfiable)
}

// selectedClaim is a claim reached while processing a claims path pointer,
// together with the digests of the disclosures needed to reveal it.
type selectedClaim struct {
	value       any
	disclosures []string
}

func (s selectedClaim) child(value any, digest string) selectedClaim {
	disclosures := append([]string(nil), s.disclosures...) // siblings share the prefix
	if digest != "" {
		disclosures = append(disclosures, digest)
	}
	return selectedClaim{value: value, disclosures: disclosures}
}

// resolveClaim processes a claims path pointer against the SD-JWT as far as the
// holder's disclosures reveal it (OID4VP 1.0 Section 7.1.1). It returns the digests
// of the disclosures revealing the selected claims, including everything nested in
// them, and false when the pointer selects nothing.
func resolveClaim(payload map[string]any, byDigest map[string]credential.SDJwtDisclosure, path []any) ([]string, bool) {
	if len(path) == 0 {
		return nil, false
	}

	// A valid SD-JWT references each digest once. Reuse would let a crafted
	// credential make the walk grow exponentially, so it fails the claim.
	reached := make(map[string]bool)
	valid := true
	take := func(next []selectedClaim, s selectedClaim, value any, digest string) []selectedClaim {
		if digest != "" {
			if reached[digest] {
				valid = false
			}
			reached[digest] = true
		}
		return append(next, s.child(value, digest))
	}

	selected := []selectedClaim{{value: payload}}
	for _, component := range path {
		var next []selectedClaim
		for _, s := range selected {
			switch c := component.(type) {
			case string:
				object, ok := s.value.(map[string]any)
				if !ok {
					return nil, false
				}
				if value, digest, ok := objectMember(object, c, byDigest); ok {
					next = take(next, s, value, digest)
				}
			case nil:
				array, ok := s.value.([]any)
				if !ok {
					return nil, false
				}
				for _, element := range array {
					if value, digest, ok := arrayElement(element, byDigest); ok {
						next = take(next, s, value, digest)
					}
				}
			default:
				index, ok := arrayIndex(c)
				if !ok {
					return nil, false
				}
				array, ok := s.value.([]any)
				if !ok {
					return nil, false
				}
				// Indexes count the elements the Credential reveals: decoys and elements
				// without a disclosure are not part of it.
				for _, element := range array {
					value, digest, ok := arrayElement(element, byDigest)
					if !ok {
						continue
					}
					if index == 0 {
						next = take(next, s, value, digest)
						break
					}
					index--
				}
			}
			if !valid {
				return nil, false
			}
		}
		if len(next) == 0 {
			return nil, false
		}
		selected = next
	}

	var disclosures []string
	seen := make(map[string]bool)
	for _, s := range selected {
		disclosures = append(disclosures, s.disclosures...)
		disclosures = appendNestedDisclosures(disclosures, s.value, byDigest, seen)
	}
	return disclosures, true
}

// objectMember returns the value of key in object, whether it is always visible
// or revealed by one of the object's disclosures, and that disclosure's digest.
func objectMember(object map[string]any, key string, byDigest map[string]credential.SDJwtDisclosure) (any, string, bool) {
	if value, ok := object[key]; ok {
		return value, "", true
	}
	sd, _ := object["_sd"].([]any)
	for _, d := range sd {
		digest, _ := d.(string)
		if disc, ok := byDigest[digest]; ok && !disc.IsArrayElement && disc.Name == key {
			return disc.Value, digest, true
		}
	}
	return nil, "", false
}

// arrayElement returns an array element, revealed through its disclosure when it
// is selectively disclosable ({"...": digest}). An element whose disclosure the
// holder does not have cannot be selected.
func arrayElement(element any, byDigest map[string]credential.SDJwtDisclosure) (any, string, bool) {
	if object, ok := element.(map[string]any); ok && len(object) == 1 {
		if digest, ok := object["..."].(string); ok {
			disc, ok := byDigest[digest]
			if !ok || !disc.IsArrayElement {
				return nil, "", false
			}
			return disc.Value, digest, true
		}
	}
	return element, "", true
}

// arrayIndex accepts a non-negative integer path component. A path that arrived as
// a dcql_query is decoded JSON, so its numbers are float64; a caller that fills
// SdJwtVcPresentationOptions.ClaimsQuery in Go writes an int. Both are accepted
// because that field is exported.
func arrayIndex(component any) (int, bool) {
	switch n := component.(type) {
	case int:
		return n, n >= 0
	case float64:
		if n < 0 || n != math.Trunc(n) || n > math.MaxInt32 {
			return 0, false
		}
		return int(n), true
	}
	return 0, false
}

// appendNestedDisclosures appends the disclosures revealing everything nested in
// value: selecting a claim selects it with its sub-claims (OID4VP 1.0 Section 7.3).
//
// The walk keeps its own stack rather than recursing. A disclosure's value can
// nest another disclosure, so the depth a credential reaches is the sum of its
// documents' depths, not the per-document limit encoding/json enforces. Recursion
// turns that into a stack overflow, which Go reports as a fatal error that recover
// cannot catch. Order does not matter here: the caller emits the disclosures in
// the credential's own order.
func appendNestedDisclosures(disclosures []string, value any, byDigest map[string]credential.SDJwtDisclosure, seen map[string]bool) []string {
	pending := []any{value}
	for len(pending) > 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]

		switch v := current.(type) {
		case map[string]any:
			sd, _ := v["_sd"].([]any)
			for _, d := range sd {
				digest, _ := d.(string)
				if disc, ok := byDigest[digest]; ok && !disc.IsArrayElement && !seen[digest] {
					seen[digest] = true
					disclosures = append(disclosures, digest)
					pending = append(pending, disc.Value)
				}
			}
			for key, child := range v {
				if key != "_sd" {
					pending = append(pending, child)
				}
			}
		case []any:
			for _, element := range v {
				child, digest, ok := arrayElement(element, byDigest)
				if !ok {
					continue
				}
				if digest != "" {
					if seen[digest] {
						continue
					}
					seen[digest] = true
					disclosures = append(disclosures, digest)
				}
				pending = append(pending, child)
			}
		}
	}
	return disclosures
}
