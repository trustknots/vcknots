package federation

import "slices"

// This file holds the combination of metadata policies along a Trust Chain
// (OpenID Federation 1.0 Section 6.1.4.1): normalization to the standard
// operators and the per-operator merge rules of Section 6.1.3.1.

func normalizeMetadataPolicy(metadataPolicy map[string]any) (map[string]any, error) {
	result := map[string]any{}
	for entityType, rawScope := range metadataPolicy {
		scope, ok := asObject(rawScope)
		if !ok {
			return nil, failure(ErrMetadataPolicyInvalid, "metadata policy scope must be an object")
		}
		normalized, err := normalizeScopedPolicy(scope)
		if err != nil {
			return nil, err
		}
		if len(normalized) > 0 {
			result[entityType] = normalized
		}
	}
	return result, nil
}

func normalizeScopedPolicy(scope map[string]any) (map[string]any, error) {
	result := map[string]any{}
	for parameter, rawPolicy := range scope {
		policy, ok := asObject(rawPolicy)
		if !ok {
			return nil, failure(ErrMetadataPolicyInvalid, "metadata parameter policy must be an object")
		}
		normalized, err := normalizeParameterPolicy(policy)
		if err != nil {
			return nil, err
		}
		if len(normalized) > 0 {
			result[parameter] = normalized
		}
	}
	return result, nil
}

func normalizeParameterPolicy(policy map[string]any) (map[string]any, error) {
	result := map[string]any{}
	for operator, value := range policy {
		if !isStandardPolicyOperator(operator) {
			continue
		}
		cloned, err := clonePolicyValue(value)
		if err != nil {
			return nil, err
		}
		result[operator] = cloned
	}
	return result, nil
}

func mergeMetadataPolicy(current, next map[string]any) (map[string]any, error) {
	result, err := clonePolicyObject(current)
	if err != nil {
		return nil, err
	}
	for entityType, rawScope := range next {
		nextScope, _ := asObject(rawScope)
		var merged map[string]any
		if currentScope, ok := asObject(result[entityType]); ok {
			merged, err = mergeScopedPolicy(currentScope, nextScope)
		} else {
			merged, err = normalizeScopedPolicy(nextScope)
		}
		if err != nil {
			return nil, err
		}
		result[entityType] = merged
	}
	return result, nil
}

func mergeScopedPolicy(current, next map[string]any) (map[string]any, error) {
	result, err := clonePolicyObject(current)
	if err != nil {
		return nil, err
	}
	for parameter, rawPolicy := range next {
		nextPolicy, _ := asObject(rawPolicy)
		var merged map[string]any
		if currentPolicy, ok := asObject(result[parameter]); ok {
			merged, err = mergeParameterPolicy(currentPolicy, nextPolicy)
		} else {
			merged, err = normalizeParameterPolicy(nextPolicy)
		}
		if err != nil {
			return nil, err
		}
		result[parameter] = merged
	}
	return result, nil
}

func mergeParameterPolicy(current, next map[string]any) (map[string]any, error) {
	result, err := clonePolicyObject(current)
	if err != nil {
		return nil, err
	}
	for operator, nextValue := range next {
		if !isStandardPolicyOperator(operator) {
			continue
		}
		var merged any
		if currentValue, present := result[operator]; present {
			merged, err = mergeOperatorValue(operator, currentValue, nextValue)
		} else {
			merged, err = clonePolicyValue(nextValue)
		}
		if err != nil {
			return nil, err
		}
		result[operator] = merged
	}
	if err := checkOperatorCombination(result); err != nil {
		return nil, err
	}
	return result, nil
}

// mergeOperatorValue combines the values two policies give one operator
// (Section 6.1.3.1): value and default must be equal, add and superset_of
// unite, one_of and subset_of intersect, and essential is true when either is.
// value and default are compared structurally, never as serialized text.
func mergeOperatorValue(operator string, left, right any) (any, error) {
	switch operator {
	case "value", "default":
		if !jsonEqual(left, right) {
			return nil, failure(ErrMetadataPolicyInvalid, "metadata %s policy values do not match", operator)
		}
		return clonePolicyValue(left)
	case "add", "superset_of":
		leftValues, err := policyStringArray(left, operator)
		if err != nil {
			return nil, err
		}
		rightValues, err := policyStringArray(right, operator)
		if err != nil {
			return nil, err
		}
		return stringsToJSON(uniqueStrings(append(leftValues, rightValues...))), nil
	case "one_of":
		return mergeOneOf(left, right)
	case "subset_of":
		leftValues, err := policyStringArray(left, operator)
		if err != nil {
			return nil, err
		}
		rightValues, err := policyStringArray(right, operator)
		if err != nil {
			return nil, err
		}
		return stringsToJSON(intersectStrings(leftValues, rightValues)), nil
	case "essential":
		leftFlag, leftOK := left.(bool)
		rightFlag, rightOK := right.(bool)
		if !leftOK || !rightOK {
			return nil, failure(ErrMetadataPolicyInvalid, "metadata essential policy must be boolean")
		}
		return leftFlag || rightFlag, nil
	default:
		return nil, failure(ErrMetadataPolicyInvalid, "metadata policy operator %q is unsupported", operator)
	}
}

func mergeOneOf(left, right any) (any, error) {
	leftValues, err := nonEmptyPolicyArray(left, "one_of")
	if err != nil {
		return nil, err
	}
	rightValues, err := nonEmptyPolicyArray(right, "one_of")
	if err != nil {
		return nil, err
	}
	intersection := []any{}
	for _, item := range leftValues {
		if slices.ContainsFunc(rightValues, func(candidate any) bool { return jsonEqual(item, candidate) }) {
			intersection = append(intersection, item)
		}
	}
	if len(intersection) == 0 {
		return nil, failure(ErrMetadataPolicyInvalid, "metadata one_of policy merge is empty")
	}
	return intersection, nil
}
