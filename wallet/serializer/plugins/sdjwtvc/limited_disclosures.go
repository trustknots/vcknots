package sdjwtvc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/trustknots/vcknots/wallet/common"
)

// ErrDisclosureBeyondSelectedClaims reports a selection whose disclosures would
// reveal a value that no selected claim covers. A disclosure is revealed whole,
// so a plaintext member of a disclosed object, or a plaintext element of a
// disclosed array, is shown to the Verifier whenever a selected claim nested
// inside it is.
var ErrDisclosureBeyondSelectedClaims = common.NewCodedError("disclosure_beyond_selected_claims", "the disclosures reveal a value no selected claim covers")

// parseForSelection decodes the issuer-signed payload of a combined SD-JWT and
// indexes its disclosures.
func parseForSelection(rawCredential string) (map[string]any, *sdjwtDisclosureResolver, error) {
	combined := ParseCombinedFormatForPresentation(rawCredential)
	if combined.SDJWT == "" {
		return nil, nil, fmt.Errorf("SD-JWT is empty")
	}
	parts := strings.Split(combined.SDJWT, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("SD-JWT must have 3 parts")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid SD-JWT payload encoding: %w", err)
	}
	var payload map[string]any
	decoder := json.NewDecoder(bytes.NewReader(payloadBytes))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil, nil, fmt.Errorf("invalid SD-JWT payload: %w", err)
	}
	algorithm, err := sdHashAlgorithm(payload)
	if err != nil {
		return nil, nil, err
	}
	resolver, err := newSDJWTDisclosureResolver(combined.Disclosures, algorithm)
	if err != nil {
		return nil, nil, err
	}
	return payload, resolver, nil
}

// ClaimPathDisclosureNames returns the names of the object property
// disclosures a presentation of rawCredential carries to reveal the claim that
// claim selects, encoded as SdJwtVcPresentationOptions.SelectedClaims is under
// RequireRootClaimMatch: the disclosures on the path and every disclosure
// nested in the selected element. Array element disclosures have no name and
// are left out. found is false when the claim selects nothing.
func ClaimPathDisclosureNames(rawCredential, claim string) (names []string, found bool, err error) {
	payload, resolver, err := parseForSelection(rawCredential)
	if err != nil {
		return nil, false, err
	}
	path, err := decodeSelectedClaimPath(claim)
	if err != nil {
		return nil, false, err
	}
	needed := map[string]bool{}
	if err := resolver.selectPath(payload, path, needed); err != nil {
		if errors.Is(err, errSelectedClaimNotFound) {
			return nil, false, nil
		}
		return nil, false, err
	}
	names = []string{}
	for digest := range needed {
		disclosure := resolver.byDigest[digest]
		if !disclosure.IsArrayElement && !slices.Contains(names, disclosure.Name) {
			names = append(names, disclosure.Name)
		}
	}
	slices.Sort(names)
	return names, true, nil
}

// ConfineDisclosureToClaims checks that the disclosures presenting the claims
// selected by claims (encoded as for ClaimPathDisclosureNames) reveal nothing
// beyond them. A selected claim is revealed whole, while an object or array a
// selected path only passes through may show a member or element no path
// covers: it fails with ErrDisclosureBeyondSelectedClaims when such a value is
// plaintext inside a disclosure the selection reveals. Plaintext of the
// issuer-signed payload is shown whatever the selection is, and a selectively
// disclosable member no path names stays undisclosed.
func ConfineDisclosureToClaims(rawCredential string, claims []string) error {
	payload, resolver, err := parseForSelection(rawCredential)
	if err != nil {
		return err
	}
	root := &claimPathTrie{}
	for _, claim := range claims {
		path, err := decodeSelectedClaimPath(claim)
		if err != nil {
			return err
		}
		root.insert(path)
	}
	return resolver.confine(payload, []*claimPathTrie{root}, false, "$")
}

// claimPathTrie merges claims path pointers. terminal marks a selected
// element; members, anyElement (a null component) and indexes continue a
// path into an object or an array.
type claimPathTrie struct {
	terminal   bool
	members    map[string]*claimPathTrie
	anyElement *claimPathTrie
	indexes    map[int64]*claimPathTrie
}

func (t *claimPathTrie) insert(path []any) {
	node := t
	for _, component := range path {
		switch value := component.(type) {
		case string:
			if node.members == nil {
				node.members = map[string]*claimPathTrie{}
			}
			if node.members[value] == nil {
				node.members[value] = &claimPathTrie{}
			}
			node = node.members[value]
		case nil:
			if node.anyElement == nil {
				node.anyElement = &claimPathTrie{}
			}
			node = node.anyElement
		default:
			index, ok := selectedPathIndex(value)
			if !ok {
				return
			}
			if node.indexes == nil {
				node.indexes = map[int64]*claimPathTrie{}
			}
			if node.indexes[index] == nil {
				node.indexes[index] = &claimPathTrie{}
			}
			node = node.indexes[index]
		}
	}
	node.terminal = true
}

// confine walks value along the paths in nodes. revealed is true inside a
// disclosure the selection reveals, where every plaintext member or element
// must lie on a path; location names value in errors.
func (r *sdjwtDisclosureResolver) confine(value any, nodes []*claimPathTrie, revealed bool, location string) error {
	for _, node := range nodes {
		if node.terminal {
			return nil
		}
	}
	switch object := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			if key == "_sd" || key == "_sd_alg" {
				continue
			}
			member := object[key]
			next := memberNodes(nodes, key)
			if len(next) == 0 {
				if revealed {
					return fmt.Errorf("%w: %s.%s", ErrDisclosureBeyondSelectedClaims, location, key)
				}
				continue
			}
			if err := r.confine(member, next, revealed, location+"."+key); err != nil {
				return err
			}
		}
		for _, key := range pathMemberNames(nodes) {
			if _, plaintext := object[key]; plaintext {
				continue
			}
			disclosure, err := r.objectDisclosure(object, key)
			if err != nil {
				return err
			}
			if disclosure == nil {
				continue
			}
			if err := r.confine(disclosure.Value, memberNodes(nodes, key), true, location+"."+key); err != nil {
				return err
			}
		}
	case []any:
		elements, err := r.arrayElements(object)
		if err != nil {
			return err
		}
		for index, element := range elements {
			elementLocation := fmt.Sprintf("%s[%d]", location, index)
			next := elementNodes(nodes, int64(index))
			if len(next) == 0 {
				if revealed && element.disclosure == nil {
					return fmt.Errorf("%w: %s", ErrDisclosureBeyondSelectedClaims, elementLocation)
				}
				continue
			}
			if err := r.confine(element.value, next, revealed || element.disclosure != nil, elementLocation); err != nil {
				return err
			}
		}
	}
	return nil
}

func memberNodes(nodes []*claimPathTrie, key string) []*claimPathTrie {
	next := []*claimPathTrie{}
	for _, node := range nodes {
		if child := node.members[key]; child != nil {
			next = append(next, child)
		}
	}
	return next
}

func pathMemberNames(nodes []*claimPathTrie) []string {
	names := []string{}
	for _, node := range nodes {
		for name := range node.members {
			if !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	slices.Sort(names)
	return names
}

func elementNodes(nodes []*claimPathTrie, index int64) []*claimPathTrie {
	next := []*claimPathTrie{}
	for _, node := range nodes {
		if node.anyElement != nil {
			next = append(next, node.anyElement)
		}
		if child := node.indexes[index]; child != nil {
			next = append(next, child)
		}
	}
	return next
}
