package sdjwtvc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/trustknots/vcknots/wallet/credential"
)

// Preserve the existing low-level name selector, including nested names. The
// caller remains responsible for resolving name ambiguity and parent disclosure
// dependencies. Final DCQL claims path pointers use selectTopLevelDisclosures
// instead.
func selectDisclosuresByName(disclosures []string, algorithm string, claims []string) ([]string, error) {
	selected := []string{}
	for _, encoded := range disclosures {
		disclosure, err := parseDisclosure(encoded, algorithm)
		if err != nil {
			return nil, err
		}
		if slices.Contains(claims, disclosure.Name) {
			selected = append(selected, encoded)
		}
	}
	if len(selected) != len(claims) {
		return nil, fmt.Errorf("selected claims are missing or ambiguous")
	}
	return selected, nil
}

// sdjwtDisclosureResolver resolves disclosure digests back to their parsed
// form and applies a claims path pointer to that view without materializing
// the whole credential.
type sdjwtDisclosureResolver struct {
	algorithm string
	byDigest  map[string]credential.SDJwtDisclosure
}

func newSDJWTDisclosureResolver(disclosures []string, algorithm string) (*sdjwtDisclosureResolver, error) {
	resolver := &sdjwtDisclosureResolver{
		algorithm: algorithm,
		byDigest:  make(map[string]credential.SDJwtDisclosure, len(disclosures)),
	}
	for _, encoded := range disclosures {
		disclosure, err := parseDisclosure(encoded, algorithm)
		if err != nil {
			return nil, fmt.Errorf("invalid disclosure: %w", err)
		}
		resolver.byDigest[disclosure.Digest] = disclosure
	}
	return resolver, nil
}

// selectTopLevelDisclosures selects the minimal set of disclosures required to
// reveal the requested claims. Each entry in claims is either a root claim name
// or a JSON-encoded OID4VP 1.0 Section 7 claims path pointer (for nested object
// properties and array element/index selection). Only disclosures that are
// actually needed to reveal the selected leaf elements are returned.
func selectTopLevelDisclosures(payload map[string]any, disclosures []string, algorithm string, claims []string) ([]string, error) {
	resolver, err := newSDJWTDisclosureResolver(disclosures, algorithm)
	if err != nil {
		return nil, err
	}
	needed := map[string]bool{}
	for _, claim := range claims {
		path, err := decodeSelectedClaimPath(claim)
		if err != nil {
			return nil, err
		}
		if len(path) == 0 {
			return nil, fmt.Errorf("invalid selected claim %q", claim)
		}
		if err := resolver.selectPath(payload, path, needed); err != nil {
			return nil, err
		}
	}
	selected := []string{}
	for _, encoded := range disclosures {
		disclosure, err := parseDisclosure(encoded, algorithm)
		if err != nil {
			return nil, fmt.Errorf("invalid disclosure: %w", err)
		}
		if needed[disclosure.Digest] {
			selected = append(selected, encoded)
		}
	}
	return selected, nil
}

// selectPath applies a claims path pointer to payload and records the digests
// of the disclosures that must be revealed.
func (r *sdjwtDisclosureResolver) selectPath(payload map[string]any, path []any, needed map[string]bool) error {
	current := []any{payload}
	for _, component := range path {
		next := []any{}
		switch value := component.(type) {
		case string:
			if value == "" || value == "_sd" || value == "_sd_alg" || value == "..." {
				return fmt.Errorf("invalid selected claim %q", value)
			}
			for _, element := range current {
				object, ok := element.(map[string]any)
				if !ok {
					continue
				}
				disclosure, err := r.objectDisclosure(object, value)
				if err != nil {
					return err
				}
				if plaintext, exists := object[value]; exists {
					if disclosure != nil {
						return fmt.Errorf("duplicate selected claim %q", value)
					}
					next = append(next, plaintext)
					continue
				}
				if disclosure == nil {
					continue
				}
				needed[disclosure.Digest] = true
				next = append(next, disclosure.Value)
			}
		case nil:
			for _, element := range current {
				array, ok := element.([]any)
				if !ok {
					continue
				}
				elements, err := r.arrayElements(array)
				if err != nil {
					return err
				}
				for _, element := range elements {
					if element.disclosure != nil {
						needed[element.disclosure.Digest] = true
					}
					next = append(next, element.value)
				}
			}
		default:
			index, ok := selectedPathIndex(value)
			if !ok {
				return fmt.Errorf("unsupported selected claim path component")
			}
			for _, element := range current {
				array, ok := element.([]any)
				if !ok {
					continue
				}
				elements, err := r.arrayElements(array)
				if err != nil {
					return err
				}
				if index < 0 || index >= int64(len(elements)) {
					continue
				}
				if disclosure := elements[index].disclosure; disclosure != nil {
					needed[disclosure.Digest] = true
				}
				next = append(next, elements[index].value)
			}
		}
		if len(next) == 0 {
			return fmt.Errorf("selected claim does not exist at the credential")
		}
		current = next
	}
	// The pointer selects each element as a whole (OID4VP 1.0 Section 7), so
	// the selectively disclosable members of a selected object or array are
	// part of the claim and are disclosed with it.
	walked := map[string]bool{}
	for _, element := range current {
		if err := r.discloseMembers(element, needed, walked); err != nil {
			return err
		}
	}
	return nil
}

// discloseMembers records the digests of every disclosure nested in value.
// walked holds the disclosures already descended into, which also bounds a
// credential that repeats digests.
func (r *sdjwtDisclosureResolver) discloseMembers(value any, needed, walked map[string]bool) error {
	switch node := value.(type) {
	case map[string]any:
		for key, member := range node {
			if key == "_sd" || key == "_sd_alg" {
				continue
			}
			if err := r.discloseMembers(member, needed, walked); err != nil {
				return err
			}
		}
		raw, exists := node["_sd"]
		if !exists {
			return nil
		}
		digests, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("_sd must be an array")
		}
		for _, rawDigest := range digests {
			digest, ok := rawDigest.(string)
			if !ok || digest == "" {
				return fmt.Errorf("_sd must contain non-empty digests")
			}
			// A digest with no disclosure is a decoy.
			disclosure, ok := r.byDigest[digest]
			if !ok || disclosure.IsArrayElement || walked[digest] {
				continue
			}
			walked[digest] = true
			needed[digest] = true
			if err := r.discloseMembers(disclosure.Value, needed, walked); err != nil {
				return err
			}
		}
	case []any:
		elements, err := r.arrayElements(node)
		if err != nil {
			return err
		}
		for _, element := range elements {
			if disclosure := element.disclosure; disclosure != nil {
				if walked[disclosure.Digest] {
					continue
				}
				walked[disclosure.Digest] = true
				needed[disclosure.Digest] = true
			}
			if err := r.discloseMembers(element.value, needed, walked); err != nil {
				return err
			}
		}
	}
	return nil
}

// objectDisclosure returns the object property disclosure named name that is
// committed by the object's _sd array. It errors when _sd is malformed or when
// more than one disclosure commits the same property name.
func (r *sdjwtDisclosureResolver) objectDisclosure(object map[string]any, name string) (*credential.SDJwtDisclosure, error) {
	raw, exists := object["_sd"]
	if !exists {
		return nil, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("_sd must be an array")
	}
	seen := map[string]bool{}
	var found *credential.SDJwtDisclosure
	for _, value := range values {
		digest, ok := value.(string)
		if !ok || digest == "" {
			return nil, fmt.Errorf("_sd must contain non-empty digests")
		}
		if seen[digest] {
			return nil, fmt.Errorf("_sd must contain unique digests")
		}
		seen[digest] = true
		disclosure, ok := r.byDigest[digest]
		if !ok || disclosure.IsArrayElement || disclosure.Name != name {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("duplicate selected claim %q", name)
		}
		copy := disclosure
		found = &copy
	}
	return found, nil
}

// arrayElement is one element of an array as the holder sees it: a plain
// value, or the value of the array element disclosure its placeholder commits.
type arrayElement struct {
	value      any
	disclosure *credential.SDJwtDisclosure
}

// arrayElements resolves the placeholders ({"...": "<digest>"}) of array and
// drops the decoys, placeholders whose digest no disclosure matches
// (RFC 9901 Section 4.2.5). Element indices are counted over the result, which
// is also the array ReconstructClaimsObject returns. A placeholder whose digest
// is not a string, or names an object property disclosure, is an error.
func (r *sdjwtDisclosureResolver) arrayElements(array []any) ([]arrayElement, error) {
	elements := make([]arrayElement, 0, len(array))
	for _, item := range array {
		object, ok := item.(map[string]any)
		if !ok {
			elements = append(elements, arrayElement{value: item})
			continue
		}
		raw, exists := object["..."]
		if !exists {
			elements = append(elements, arrayElement{value: item})
			continue
		}
		digest, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("array element placeholder must be a digest string")
		}
		disclosure, ok := r.byDigest[digest]
		if !ok {
			continue
		}
		if !disclosure.IsArrayElement {
			return nil, fmt.Errorf("array element placeholder names an object property disclosure")
		}
		copy := disclosure
		elements = append(elements, arrayElement{value: disclosure.Value, disclosure: &copy})
	}
	return elements, nil
}

// decodeSelectedClaimPath turns a selected claim string into a claims path
// pointer. Nested paths are carried as JSON arrays by the DCQL selection layer;
// a plain string is a single-segment root claim name.
func decodeSelectedClaimPath(claim string) ([]any, error) {
	trimmed := strings.TrimSpace(claim)
	if strings.HasPrefix(trimmed, "[") {
		decoder := json.NewDecoder(strings.NewReader(trimmed))
		decoder.UseNumber()
		var path []any
		if err := decoder.Decode(&path); err == nil && len(path) > 0 {
			valid := true
			for _, component := range path {
				switch component.(type) {
				case string, nil:
				default:
					if _, ok := selectedPathIndex(component); !ok {
						valid = false
					}
				}
			}
			if valid {
				return path, nil
			}
		}
	}
	return []any{claim}, nil
}

func selectedPathIndex(value any) (int64, bool) {
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
	default:
		return 0, false
	}
}

// ReconstructClaimsObject parses a combined SD-JWT VC credential and returns its
// root JSON object with all disclosures applied, including nested selectively
// disclosable object properties and array elements, with array decoys dropped.
// It lets the DCQL layer evaluate OID4VP 1.0 Section 7 claims path pointers
// over the decoded credential.
func ReconstructClaimsObject(rawCredential string) (map[string]any, error) {
	combined := ParseCombinedFormatForPresentation(rawCredential)
	if combined.SDJWT == "" {
		return nil, fmt.Errorf("SD-JWT is empty")
	}
	parts := strings.Split(combined.SDJWT, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("SD-JWT must have 3 parts")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid SD-JWT payload encoding: %w", err)
	}
	var payload map[string]any
	decoder := json.NewDecoder(bytes.NewReader(payloadBytes))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("invalid SD-JWT payload: %w", err)
	}
	algorithm := defaultHashAlgorithm
	if value, ok := payload["_sd_alg"].(string); ok {
		algorithm = normalizeSDHashAlgorithm(value)
	}
	resolver, err := newSDJWTDisclosureResolver(combined.Disclosures, algorithm)
	if err != nil {
		return nil, err
	}
	reconstructed, err := resolver.reconstruct(payload)
	if err != nil {
		return nil, err
	}
	object, ok := reconstructed.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("reconstructed credential is not an object")
	}
	return object, nil
}

// reconstruct materializes a payload value with every applicable disclosure
// applied recursively and array decoys dropped.
func (r *sdjwtDisclosureResolver) reconstruct(node any) (any, error) {
	switch value := node.(type) {
	case map[string]any:
		object := make(map[string]any, len(value))
		for key, item := range value {
			if key == "_sd" || key == "_sd_alg" {
				continue
			}
			reconstructed, err := r.reconstruct(item)
			if err != nil {
				return nil, err
			}
			object[key] = reconstructed
		}
		raw, exists := value["_sd"]
		if !exists {
			return object, nil
		}
		digests, ok := raw.([]any)
		if !ok {
			return nil, fmt.Errorf("_sd must be an array")
		}
		for _, rawDigest := range digests {
			digest, ok := rawDigest.(string)
			if !ok || digest == "" {
				return nil, fmt.Errorf("_sd must contain non-empty digests")
			}
			disclosure, ok := r.byDigest[digest]
			if !ok || disclosure.IsArrayElement || disclosure.Name == "" ||
				disclosure.Name == "_sd" || disclosure.Name == "_sd_alg" || disclosure.Name == "..." {
				continue
			}
			reconstructed, err := r.reconstruct(disclosure.Value)
			if err != nil {
				return nil, err
			}
			object[disclosure.Name] = reconstructed
		}
		return object, nil
	case []any:
		elements, err := r.arrayElements(value)
		if err != nil {
			return nil, err
		}
		array := make([]any, 0, len(elements))
		for _, element := range elements {
			reconstructed, err := r.reconstruct(element.value)
			if err != nil {
				return nil, err
			}
			array = append(array, reconstructed)
		}
		return array, nil
	default:
		return node, nil
	}
}
