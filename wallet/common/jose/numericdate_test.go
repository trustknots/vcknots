package jose

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNumericDate(t *testing.T) {
	valid := []struct {
		value any
		want  time.Time
	}{
		{json.Number("1700000000"), time.Unix(1700000000, 0).UTC()},
		{json.Number("1700000000.25"), time.Unix(1700000000, 250_000_000).UTC()},
		{json.Number("-1"), time.Unix(-1, 0).UTC()},
		{float64(1700000000), time.Unix(1700000000, 0).UTC()},
	}
	for _, tc := range valid {
		got, err := NumericDate(tc.value)
		if err != nil || !got.Equal(tc.want) {
			t.Errorf("NumericDate(%v) = %v, %v; want %v", tc.value, got, err, tc.want)
		}
	}
	for _, value := range []any{"1700000000", nil, true, json.Number("1e400"), json.Number("9e12"), float64(-9e12), json.Number("NaN")} {
		if _, err := NumericDate(value); err == nil {
			t.Errorf("NumericDate(%#v) accepted", value)
		}
	}
}

func TestNumericDateClaim(t *testing.T) {
	claims := map[string]any{"exp": json.Number("1700000000"), "nbf": "soon"}
	if at, present, err := NumericDateClaim(claims, "exp"); err != nil || !present || at.Unix() != 1700000000 {
		t.Fatalf("exp = %v, %v, %v", at, present, err)
	}
	if _, present, err := NumericDateClaim(claims, "iat"); err != nil || present {
		t.Fatalf("absent iat = %v, %v", present, err)
	}
	if _, present, err := NumericDateClaim(claims, "nbf"); err == nil || !present {
		t.Fatalf("string nbf = %v, %v", present, err)
	}
}
