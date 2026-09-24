package federation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
)

// decodeJSONObject decodes a JSON object keeping numbers as json.Number, so
// metadata values never round through float64.
func decodeJSONObject(data []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if value == nil {
		return nil, fmt.Errorf("JSON value is not an object")
	}
	return value, nil
}

// asObject reports value as a JSON object, or false when it is anything else.
func asObject(value any) (map[string]any, bool) {
	object, ok := value.(map[string]any)
	return object, ok && object != nil
}

// asArray reports value as a JSON array, or false when it is anything else.
func asArray(value any) ([]any, bool) {
	switch typed := value.(type) {
	case []any:
		return typed, typed != nil
	case []string:
		if typed == nil {
			return nil, false
		}
		items := make([]any, len(typed))
		for i, item := range typed {
			items[i] = item
		}
		return items, true
	default:
		return nil, false
	}
}

// asStringArray reports value as an array whose every item is a string.
func asStringArray(value any) ([]string, bool) {
	items, ok := asArray(value)
	if !ok {
		return nil, false
	}
	values := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, false
		}
		values = append(values, text)
	}
	return values, true
}

// asNonEmptyStringArray reports value as an array whose every item is a
// non-empty string. The array itself may be empty.
func asNonEmptyStringArray(value any) ([]string, bool) {
	values, ok := asStringArray(value)
	if !ok || slices.Contains(values, "") {
		return nil, false
	}
	return values, true
}

// cloneJSON deep-copies a JSON value. A value that JSON cannot represent is
// refused.
func cloneJSON(value any) (any, error) {
	switch typed := value.(type) {
	case nil, string, bool, json.Number, float64, float32,
		int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return typed, nil
	case map[string]any:
		if typed == nil {
			return nil, nil
		}
		clone := make(map[string]any, len(typed))
		for key, item := range typed {
			copied, err := cloneJSON(item)
			if err != nil {
				return nil, err
			}
			clone[key] = copied
		}
		return clone, nil
	case []any, []string:
		items, _ := asArray(typed)
		if items == nil {
			return nil, nil
		}
		clone := make([]any, len(items))
		for i, item := range items {
			copied, err := cloneJSON(item)
			if err != nil {
				return nil, err
			}
			clone[i] = copied
		}
		return clone, nil
	default:
		return nil, fmt.Errorf("value of type %T is not JSON-compatible", value)
	}
}

// cloneJSONObject deep-copies a JSON object.
func cloneJSONObject(value map[string]any) (map[string]any, error) {
	clone, err := cloneJSON(value)
	if err != nil {
		return nil, err
	}
	object, _ := clone.(map[string]any)
	if object == nil {
		object = map[string]any{}
	}
	return object, nil
}

// jsonEqual compares two JSON values structurally: objects by their member
// sets regardless of member order, arrays item by item, and numbers by their
// exact numeric value regardless of spelling ("1" equals "1.0"). It is the
// canonical comparison the value, default and one_of operators need. Comparing
// serialized text instead would make JSON object member order significant,
// which it is not (RFC 8259 Section 4).
func jsonEqual(left, right any) bool {
	if leftNumber, ok := jsonNumber(left); ok {
		rightNumber, ok := jsonNumber(right)
		return ok && leftNumber.Cmp(rightNumber) == 0
	}
	if leftObject, ok := asObject(left); ok {
		rightObject, ok := asObject(right)
		if !ok || len(leftObject) != len(rightObject) {
			return false
		}
		for key, leftItem := range leftObject {
			rightItem, present := rightObject[key]
			if !present || !jsonEqual(leftItem, rightItem) {
				return false
			}
		}
		return true
	}
	if leftArray, ok := asArray(left); ok {
		rightArray, ok := asArray(right)
		if !ok || len(leftArray) != len(rightArray) {
			return false
		}
		for i := range leftArray {
			if !jsonEqual(leftArray[i], rightArray[i]) {
				return false
			}
		}
		return true
	}
	switch typed := left.(type) {
	case nil:
		return right == nil
	case string:
		text, ok := right.(string)
		return ok && text == typed
	case bool:
		flag, ok := right.(bool)
		return ok && flag == typed
	default:
		return false
	}
}

// jsonNumber reads a JSON number, whichever Go type carries it, as an exact
// rational.
func jsonNumber(value any) (*big.Rat, bool) {
	var text string
	switch typed := value.(type) {
	case json.Number:
		text = typed.String()
	case float64:
		rat := new(big.Rat)
		if rat.SetFloat64(typed) == nil {
			return nil, false
		}
		return rat, true
	case float32:
		return jsonNumber(float64(typed))
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		text = fmt.Sprint(typed)
	default:
		return nil, false
	}
	rat, ok := new(big.Rat).SetString(text)
	return rat, ok
}

// jsonInteger reads a JSON number that is an integer, as JavaScript's
// Number.isInteger does ("5" and "5.0" both are).
func jsonInteger(value any) (int64, bool) {
	rat, ok := jsonNumber(value)
	if !ok || !rat.IsInt() || !rat.Num().IsInt64() {
		return 0, false
	}
	return rat.Num().Int64(), true
}
