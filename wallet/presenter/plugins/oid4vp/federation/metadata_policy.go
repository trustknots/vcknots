package federation

import (
	"slices"
)

// standardPolicyOperators are the metadata policy operators of OpenID
// Federation 1.0 Section 6.1.3.1, in the order Section 6.1.4.2 applies them.
var standardPolicyOperators = []string{"value", "add", "default", "one_of", "subset_of", "superset_of", "essential"}

func isStandardPolicyOperator(operator string) bool {
	return slices.Contains(standardPolicyOperators, operator)
}

// parameterState is the state of one metadata parameter while a policy is
// applied to it: absent, or present with a value.
type parameterState struct {
	present bool
	value   any
}

// ApplyMetadataPolicy applies the resolved metadata policy of entityType to
// metadata and returns the result, leaving metadata untouched (OpenID
// Federation 1.0 Section 6.1.4.2). Each parameter policy runs its operators in
// the order value, add, default, one_of, subset_of, superset_of, essential.
// Operators this library does not know are ignored; an unknown critical one
// was already refused while the chain was validated.
func ApplyMetadataPolicy(metadata, metadataPolicy map[string]any, entityType string) (map[string]any, error) {
	result, err := clonePolicyObject(metadata)
	if err != nil {
		return nil, err
	}
	rawScope, present := metadataPolicy[entityType]
	if !present {
		return result, nil
	}
	scope, ok := asObject(rawScope)
	if !ok {
		return nil, failure(ErrMetadataPolicyInvalid, "metadata policy scope must be an object")
	}
	for parameter, rawPolicy := range scope {
		policy, ok := asObject(rawPolicy)
		if !ok {
			return nil, failure(ErrMetadataPolicyInvalid, "metadata parameter policy must be an object")
		}
		if err := checkOperatorCombination(policy); err != nil {
			return nil, err
		}
		current, present := result[parameter]
		state, err := applyParameterPolicy(parameterState{present: present, value: current}, policy, parameter)
		if err != nil {
			return nil, err
		}
		if state.present {
			result[parameter] = state.value
		} else {
			delete(result, parameter)
		}
	}
	return result, nil
}

// ResolveMetadataPolicy combines the metadata policies of a Trust Chain,
// ordered from the Trust Anchor down to the subject's Immediate Superior, into
// one policy (OpenID Federation 1.0 Section 6.1.4.1). Operators outside the
// standard set are dropped. It returns nil when no policy remains.
func ResolveMetadataPolicy(metadataPolicies []map[string]any) (map[string]any, error) {
	var resolved map[string]any
	for _, metadataPolicy := range metadataPolicies {
		if err := checkMetadataPolicy(metadataPolicy); err != nil {
			return nil, err
		}
		normalized, err := normalizeMetadataPolicy(metadataPolicy)
		if err != nil {
			return nil, err
		}
		if len(normalized) == 0 {
			continue
		}
		if resolved == nil {
			resolved = normalized
			continue
		}
		if resolved, err = mergeMetadataPolicy(resolved, normalized); err != nil {
			return nil, err
		}
	}
	return resolved, nil
}

// applyParameterPolicy runs one parameter policy against the parameter state.
func applyParameterPolicy(state parameterState, policy map[string]any, parameter string) (parameterState, error) {
	if state.present {
		value, err := clonePolicyValue(state.value)
		if err != nil {
			return state, err
		}
		state.value = value
	}
	if value, present := policy["value"]; present {
		if value == nil {
			state = parameterState{}
		} else {
			cloned, err := clonePolicyValue(value)
			if err != nil {
				return state, err
			}
			state = parameterState{present: true, value: cloned}
		}
	}
	if add, present := policy["add"]; present {
		additions, err := policyStringArray(add, "add")
		if err != nil {
			return state, err
		}
		var existing []string
		if state.present {
			if existing, err = parameterStringArray(state.value, parameter); err != nil {
				return state, err
			}
		}
		state = parameterState{present: true, value: stringsToJSON(uniqueStrings(append(existing, additions...)))}
	}
	if defaultValue, present := policy["default"]; present && !state.present {
		if defaultValue == nil {
			return state, failure(ErrMetadataPolicyInvalid, "metadata default policy must not be null")
		}
		cloned, err := clonePolicyValue(defaultValue)
		if err != nil {
			return state, err
		}
		state = parameterState{present: true, value: cloned}
	}
	if oneOf, present := policy["one_of"]; present && state.present {
		matches, err := oneOfMatches(state.value, oneOf)
		if err != nil {
			return state, err
		}
		if !matches {
			return state, failure(ErrMetadataPolicyInvalid, "metadata value is not allowed by one_of")
		}
	}
	if subsetOf, present := policy["subset_of"]; present && state.present {
		values, err := parameterStringArray(state.value, parameter)
		if err != nil {
			return state, err
		}
		allowed, err := policyStringArray(subsetOf, "subset_of")
		if err != nil {
			return state, err
		}
		state.value = stringsToJSON(intersectStrings(values, allowed))
	}
	if supersetOf, present := policy["superset_of"]; present && state.present {
		values, err := parameterStringArray(state.value, parameter)
		if err != nil {
			return state, err
		}
		required, err := policyStringArray(supersetOf, "superset_of")
		if err != nil {
			return state, err
		}
		if !includesAll(values, required) {
			return state, failure(ErrMetadataPolicyInvalid, "metadata value does not satisfy superset_of")
		}
	}
	if essential, present := policy["essential"]; present {
		flag, ok := essential.(bool)
		if !ok {
			return state, failure(ErrMetadataPolicyInvalid, "metadata essential policy must be boolean")
		}
		if flag && !state.present {
			return state, failure(ErrMetadataPolicyInvalid, "metadata essential value is missing")
		}
	}
	if state.present && state.value == nil {
		return state, failure(ErrMetadataPolicyInvalid, "metadata policy output must not contain null")
	}
	return state, nil
}

// checkMetadataPolicy checks every parameter policy of a metadata_policy claim
// before it is combined with others.
func checkMetadataPolicy(metadataPolicy map[string]any) error {
	for _, rawScope := range metadataPolicy {
		scope, ok := asObject(rawScope)
		if !ok {
			return failure(ErrMetadataPolicyInvalid, "metadata policy scope must be an object")
		}
		for _, rawPolicy := range scope {
			policy, ok := asObject(rawPolicy)
			if !ok {
				return failure(ErrMetadataPolicyInvalid, "metadata parameter policy must be an object")
			}
			if err := checkOperatorCombination(policy); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkOperatorCombination applies the operator combination rules of Section
// 6.1.3.1: which operators may appear together in one parameter policy and
// what their values must then satisfy.
func checkOperatorCombination(policy map[string]any) error {
	value, hasValue := policy["value"]
	defaultValue, hasDefault := policy["default"]
	essential, hasEssential := policy["essential"]
	_, hasAdd := policy["add"]
	_, hasSubsetOf := policy["subset_of"]
	_, hasSupersetOf := policy["superset_of"]
	oneOf, hasOneOf := policy["one_of"]

	if hasDefault && defaultValue == nil {
		return failure(ErrMetadataPolicyInvalid, "metadata default policy must not be null")
	}
	if _, isBool := essential.(bool); hasEssential && !isBool {
		return failure(ErrMetadataPolicyInvalid, "metadata essential policy must be boolean")
	}
	if hasValue && value == nil && essential == true {
		return failure(ErrMetadataPolicyInvalid, "metadata value and essential policies are incompatible")
	}
	if hasValue && value == nil && hasDefault {
		return failure(ErrMetadataPolicyInvalid, "metadata value and default policies are incompatible")
	}
	if hasOneOf {
		for _, disallowed := range []string{"add", "subset_of", "superset_of"} {
			if _, present := policy[disallowed]; present {
				return failure(ErrMetadataPolicyInvalid, "metadata one_of policy cannot be combined with %s", disallowed)
			}
		}
		if hasValue {
			matches, err := oneOfMatches(value, oneOf)
			if err != nil {
				return err
			}
			if !matches {
				return failure(ErrMetadataPolicyInvalid, "metadata value policy is not allowed by one_of")
			}
		}
	}
	type inclusion struct {
		present          bool
		subset, superset string
		message          string
	}
	for _, rule := range []inclusion{
		{hasValue && hasAdd, "add", "value", "metadata value policy must include add values"},
		{hasValue && hasSubsetOf, "value", "subset_of", "metadata value policy does not satisfy subset_of"},
		{hasValue && hasSupersetOf, "superset_of", "value", "metadata value policy does not satisfy superset_of"},
		{hasAdd && hasSubsetOf, "add", "subset_of", "metadata add policy does not satisfy subset_of"},
		{hasSubsetOf && hasSupersetOf, "superset_of", "subset_of", "metadata subset_of policy does not satisfy superset_of"},
	} {
		if !rule.present {
			continue
		}
		subset, err := operatorOrValueStrings(policy, rule.subset)
		if err != nil {
			return err
		}
		superset, err := operatorOrValueStrings(policy, rule.superset)
		if err != nil {
			return err
		}
		if !includesAll(superset, subset) {
			return failure(ErrMetadataPolicyInvalid, "%s", rule.message)
		}
	}
	return nil
}

// operatorOrValueStrings reads the string array an operator of policy holds;
// the value operator is read as a parameter value, the others as operator
// values, which only differ in how a failure is reported.
func operatorOrValueStrings(policy map[string]any, operator string) ([]string, error) {
	if operator == "value" {
		return parameterStringArray(policy["value"], "value")
	}
	return policyStringArray(policy[operator], operator)
}

func oneOfMatches(value, oneOf any) (bool, error) {
	allowed, ok := asArray(oneOf)
	if !ok || len(allowed) == 0 {
		return false, failure(ErrMetadataPolicyInvalid, "metadata one_of policy must be a non-empty array")
	}
	return slices.ContainsFunc(allowed, func(candidate any) bool { return jsonEqual(value, candidate) }), nil
}

func nonEmptyPolicyArray(value any, operator string) ([]any, error) {
	items, ok := asArray(value)
	if !ok || len(items) == 0 {
		return nil, failure(ErrMetadataPolicyInvalid, "metadata %s policy must be a non-empty array", operator)
	}
	cloned, err := clonePolicyValue(items)
	if err != nil {
		return nil, err
	}
	return cloned.([]any), nil
}

func parameterStringArray(value any, parameter string) ([]string, error) {
	values, ok := asStringArray(value)
	if !ok {
		return nil, failure(ErrMetadataPolicyInvalid, "metadata parameter %s must be a string array for this policy", parameter)
	}
	return values, nil
}

func policyStringArray(value any, operator string) ([]string, error) {
	values, ok := asStringArray(value)
	if !ok {
		return nil, failure(ErrMetadataPolicyInvalid, "metadata %s policy must be a string array", operator)
	}
	return values, nil
}

func clonePolicyValue(value any) (any, error) {
	cloned, err := cloneJSON(value)
	if err != nil {
		return nil, failure(ErrMetadataPolicyInvalid, "metadata policy value must be JSON-compatible")
	}
	return cloned, nil
}

func clonePolicyObject(value map[string]any) (map[string]any, error) {
	cloned, err := cloneJSONObject(value)
	if err != nil {
		return nil, failure(ErrMetadataPolicyInvalid, "metadata policy value must be JSON-compatible")
	}
	return cloned, nil
}

func uniqueStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !slices.Contains(result, value) {
			result = append(result, value)
		}
	}
	return result
}

func intersectStrings(left, right []string) []string {
	result := make([]string, 0, len(left))
	for _, item := range left {
		if slices.Contains(right, item) {
			result = append(result, item)
		}
	}
	return result
}

// includesAll reports whether every item of subset is in superset.
func includesAll(superset, subset []string) bool {
	for _, item := range subset {
		if !slices.Contains(superset, item) {
			return false
		}
	}
	return true
}

// stringsToJSON converts a string slice to the []any shape decoded JSON has.
func stringsToJSON(values []string) []any {
	items := make([]any, len(values))
	for i, value := range values {
		items[i] = value
	}
	return items
}
