package federation

import (
	"slices"
)

// federationEntityType is the Entity Type every Federation Entity may carry
// (OpenID Federation 1.0 Section 5.1.1); allowed_entity_types never excludes
// it (Section 6.2.3).
const federationEntityType = "federation_entity"

// DeriveEntityMetadata derives the final metadata of entityType for the
// subject of a validated Trust Chain (OpenID Federation 1.0 Section 6.1.4):
// the subject's own metadata, overridden parameter by parameter by the
// metadata its Immediate Superior states about it in the Subordinate
// Statement, with the chain's metadata policies resolved from the Trust
// Anchor down and applied to the result. The chain's statements are not
// modified.
func DeriveEntityMetadata(chain *TrustChain, entityType string) (map[string]any, error) {
	if chain == nil || len(chain.Statements) == 0 {
		return nil, failure(ErrMetadataDerivationFailed, "trust chain has no subject statement")
	}
	subject, superiors := chain.Statements[0], chain.Statements[1:]
	rawSubjectMetadata, present := subject.Metadata[entityType]
	if !present {
		return nil, failure(ErrMetadataDerivationFailed, "subject metadata is missing")
	}
	subjectMetadata, ok := asObject(rawSubjectMetadata)
	if !ok {
		return nil, failure(ErrMetadataDerivationFailed, "subject metadata scope must be an object")
	}
	if err := checkMetadataParameterValues(subjectMetadata, "subject"); err != nil {
		return nil, err
	}
	combined, err := cloneMetadataObject(subjectMetadata)
	if err != nil {
		return nil, err
	}
	if len(superiors) > 0 {
		if err := overlaySuperiorMetadata(combined, superiors[0].Metadata[entityType]); err != nil {
			return nil, err
		}
	}
	if err := checkEntityTypeAllowed(chain, entityType); err != nil {
		return nil, err
	}

	var policies []map[string]any
	for i := len(superiors) - 1; i >= 0; i-- {
		if superiors[i].isSubordinate() && superiors[i].MetadataPolicy != nil {
			policies = append(policies, superiors[i].MetadataPolicy)
		}
	}
	resolved, err := ResolveMetadataPolicy(policies)
	if err != nil {
		return nil, err
	}
	if resolved == nil {
		return combined, nil
	}
	return ApplyMetadataPolicy(combined, resolved, entityType)
}

// overlaySuperiorMetadata applies the metadata an Immediate Superior states
// about its subordinate, whose parameters take precedence over the subject's
// own. An absent or null scope states nothing.
func overlaySuperiorMetadata(combined map[string]any, rawSuperiorMetadata any) error {
	if rawSuperiorMetadata == nil {
		return nil
	}
	superiorMetadata, ok := asObject(rawSuperiorMetadata)
	if !ok {
		return failure(ErrMetadataDerivationFailed, "immediate superior metadata scope must be an object")
	}
	if err := checkMetadataParameterValues(superiorMetadata, "immediate superior"); err != nil {
		return err
	}
	overlay, err := cloneMetadataObject(superiorMetadata)
	if err != nil {
		return err
	}
	for parameter, value := range overlay {
		combined[parameter] = value
	}
	return nil
}

// checkEntityTypeAllowed applies the allowed_entity_types constraint (Section
// 6.2.3) of every Subordinate Statement of the chain.
func checkEntityTypeAllowed(chain *TrustChain, entityType string) error {
	if entityType == federationEntityType {
		return nil
	}
	for _, statement := range chain.Statements {
		if !statement.isSubordinate() || statement.Constraints == nil {
			continue
		}
		raw, present := statement.Constraints["allowed_entity_types"]
		if !present {
			continue
		}
		allowed, ok := asNonEmptyStringArray(raw)
		if !ok {
			return failure(ErrMetadataDerivationFailed, "allowed_entity_types constraint must be a string array")
		}
		if !slices.Contains(allowed, entityType) {
			return failure(ErrMetadataDerivationFailed, "metadata entity type is disallowed by constraints")
		}
	}
	return nil
}

func checkMetadataParameterValues(metadata map[string]any, label string) error {
	for _, value := range metadata {
		if value == nil {
			return failure(ErrMetadataDerivationFailed, "%s metadata parameters must not be null", label)
		}
	}
	return nil
}

func cloneMetadataObject(metadata map[string]any) (map[string]any, error) {
	cloned, err := cloneJSONObject(metadata)
	if err != nil {
		return nil, failure(ErrMetadataDerivationFailed, "metadata must be JSON-compatible")
	}
	return cloned, nil
}
