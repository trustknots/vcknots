package wallet

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
)

// ErrLimitDisclosureUnsatisfiable reports a Draft 24 presentation that cannot
// honour an input descriptor's limit_disclosure "required" (DIF Presentation
// Exchange 2.0, Input Descriptor Object: "the Conformant Consumer MUST limit
// submitted fields to those listed in the fields array"): a credential format
// that cannot disclose selectively (a JWT or Data Integrity W3C VC, presented
// whole), disclosed claims beyond the listed fields, or a field path this
// library cannot map to a disclosure. Nothing is sent. Presentation Exchange
// lets a Wallet that cannot limit disclosure "return nothing (or cease the
// interaction with the Verifier)"; presenting the whole credential is not
// among the choices.
var ErrLimitDisclosureUnsatisfiable = common.NewCodedError("limit_disclosure_unsatisfiable", "the credential cannot limit disclosure to the fields the input descriptor lists")

// draft24InputDescriptor is the part of a Presentation Exchange input
// descriptor that limits disclosure.
type draft24InputDescriptor struct {
	ID          string `json:"id"`
	Constraints struct {
		LimitDisclosure string `json:"limit_disclosure"`
		Fields          []struct {
			Path []string `json:"path"`
		} `json:"fields"`
	} `json:"constraints"`
}

// draft24DisclosureLimits applies limit_disclosure "required" to the
// selections of a Draft 24 presentation. For each selection answering such a
// descriptor it returns the claims the presentation discloses, as JSON-encoded
// claims path pointers for sdjwtvc's RequireRootClaimMatch, and nil for a
// selection no required descriptor constrains.
//
// A field is matched by its full path, never by a claim name, so a same-named
// claim elsewhere in the credential stays undisclosed. Its path array is
// evaluated in order and the first path the credential resolves is the field
// (Presentation Exchange 2.0, Input Descriptor Object, fields). Without
// DisclosedClaims every resolved field is disclosed; with them a field is
// disclosed only when the Holder kept every disclosure it needs, and a kept
// name no field needs is refused. A selection whose disclosures would reveal a
// plaintext member of a parent disclosure that no field lists is refused too:
// a disclosure cannot be revealed in part.
func draft24DisclosureLimits(rawDefinition json.RawMessage, selections []CredentialSelection, credentials []resolvedCredential) ([][]string, error) {
	var definition struct {
		InputDescriptors []draft24InputDescriptor `json:"input_descriptors"`
	}
	if len(rawDefinition) == 0 {
		return make([][]string, len(selections)), nil
	}
	if err := json.Unmarshal(rawDefinition, &definition); err != nil {
		return nil, fmt.Errorf("%w: presentation_definition: %w", ErrInvalidArgument, err)
	}
	limits := make([][]string, len(selections))
	for index, selection := range selections {
		var fields [][]string
		required := false
		for _, descriptor := range definition.InputDescriptors {
			if !slices.Contains(selection.QueryIDs, descriptor.ID) || descriptor.Constraints.LimitDisclosure != "required" {
				continue
			}
			required = true
			for _, field := range descriptor.Constraints.Fields {
				pointers := make([]string, 0, len(field.Path))
				for _, path := range field.Path {
					pointer, ok := jsonPathClaimsPointer(path)
					if !ok {
						return nil, fmt.Errorf("%w: input descriptor %q lists the path %q, which names no claim this library can disclose alone", ErrLimitDisclosureUnsatisfiable, descriptor.ID, path)
					}
					pointers = append(pointers, pointer)
				}
				fields = append(fields, pointers)
			}
		}
		if !required {
			continue
		}
		presented := credentials[index]
		flavor, err := presented.saved.Entry.SerializationFlavor()
		if err != nil || flavor != credential.SDJwtVC {
			return nil, fmt.Errorf("%w: credential %q is a %s credential, which is presented whole", ErrLimitDisclosureUnsatisfiable, presented.id, flavor)
		}
		limited, err := limitSDJWTDisclosure(string(presented.saved.Entry.Raw), fields, selection.DisclosedClaims)
		if err != nil {
			return nil, fmt.Errorf("%w: credential %q: %w", ErrLimitDisclosureUnsatisfiable, presented.id, err)
		}
		limits[index] = limited
	}
	return limits, nil
}

// limitSDJWTDisclosure resolves each field to the first of its claims path
// pointers the credential holds and returns the pointers to disclose.
func limitSDJWTDisclosure(raw string, fields [][]string, kept []string) ([]string, error) {
	disclosed, needed := []string{}, []string{}
	for _, pointers := range fields {
		for _, pointer := range pointers {
			names, found, err := sdjwtvc.ClaimPathDisclosureNames(raw, pointer)
			if err != nil {
				return nil, err
			}
			if !found {
				continue
			}
			for _, name := range names {
				if !slices.Contains(needed, name) {
					needed = append(needed, name)
				}
			}
			if kept == nil || isSubset(names, kept) {
				if !slices.Contains(disclosed, pointer) {
					disclosed = append(disclosed, pointer)
				}
			}
			break
		}
	}
	for _, name := range kept {
		if !slices.Contains(needed, name) {
			return nil, fmt.Errorf("it would disclose %q, which no field of its input descriptors needs", name)
		}
	}
	if err := sdjwtvc.ConfineDisclosureToClaims(raw, disclosed); err != nil {
		return nil, err
	}
	return disclosed, nil
}

func isSubset(names, of []string) bool {
	for _, name := range names {
		if !slices.Contains(of, name) {
			return false
		}
	}
	return true
}

// jsonPathClaimsPointer converts a JSONPath expression of the forms
// Presentation Exchange fields use - $.a.b, $['a'], $["a"], [0] and [*] - to a
// JSON-encoded OID4VP claims path pointer: a member name per step, a
// non-negative index, or null for every array element. The path starts with a
// member name. Recursive descent, filters, scripts and negative indexes select
// no single position and are refused.
func jsonPathClaimsPointer(path string) (string, bool) {
	rest, found := strings.CutPrefix(strings.TrimSpace(path), "$")
	if !found {
		return "", false
	}
	pointer := []any{}
	for rest != "" {
		switch {
		case strings.HasPrefix(rest, "["):
			end := strings.Index(rest, "]")
			if end < 0 {
				return "", false
			}
			inner := strings.TrimSpace(rest[1:end])
			rest = rest[end+1:]
			switch {
			case len(inner) >= 2 && (inner[0] == '\'' || inner[0] == '"') && inner[len(inner)-1] == inner[0]:
				pointer = append(pointer, inner[1:len(inner)-1])
			case inner == "*":
				pointer = append(pointer, nil)
			default:
				index, err := strconv.ParseInt(inner, 10, 64)
				if err != nil || index < 0 {
					return "", false
				}
				pointer = append(pointer, index)
			}
		case strings.HasPrefix(rest, "."):
			rest = rest[1:]
			end := strings.IndexAny(rest, ".[")
			if end < 0 {
				end = len(rest)
			}
			segment := rest[:end]
			rest = rest[end:]
			switch {
			case segment == "" || strings.ContainsAny(segment, "?()@"):
				return "", false
			case segment == "*":
				pointer = append(pointer, nil)
			default:
				pointer = append(pointer, segment)
			}
		default:
			return "", false
		}
	}
	if len(pointer) == 0 {
		return "", false
	}
	if _, member := pointer[0].(string); !member {
		return "", false
	}
	encoded, err := json.Marshal(pointer)
	if err != nil {
		return "", false
	}
	return string(encoded), true
}
