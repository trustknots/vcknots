package jose

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"
)

// maxNumericDateSeconds bounds the NumericDate values NumericDate accepts to
// the ECMAScript Date range (8.64e15 ms either side of the epoch). A value
// beyond it is not a date an issuer means and is refused rather than wrapped.
const maxNumericDateSeconds = 8.64e12

// NumericDate converts a decoded JWT NumericDate (RFC 7519 Section 2), a JSON
// number of seconds since the epoch that may be fractional, into a UTC time.
// value is a json.Number or a float64, as encoding/json decodes it; anything
// else, a non-finite number, and a number outside ±8.64e12 seconds is an
// error.
func NumericDate(value any) (time.Time, error) {
	var seconds float64
	switch typed := value.(type) {
	case json.Number:
		parsed, err := strconv.ParseFloat(typed.String(), 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("NumericDate %q is not a number", typed)
		}
		seconds = parsed
	case float64:
		seconds = typed
	default:
		return time.Time{}, fmt.Errorf("NumericDate must be a JSON number, got %T", value)
	}
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) || math.Abs(seconds) > maxNumericDateSeconds {
		return time.Time{}, fmt.Errorf("NumericDate %v is out of range", seconds)
	}
	whole, fraction := math.Modf(seconds)
	return time.Unix(int64(whole), int64(math.Round(fraction*1e9))).UTC(), nil
}

// NumericDateClaim reads the optional NumericDate claim name from claims.
// present is false when the claim is absent; a present claim that is not a
// NumericDate is an error naming the claim.
func NumericDateClaim(claims map[string]any, name string) (at time.Time, present bool, err error) {
	raw, present := claims[name]
	if !present {
		return time.Time{}, false, nil
	}
	at, err = NumericDate(raw)
	if err != nil {
		return time.Time{}, true, fmt.Errorf("%s claim: %w", name, err)
	}
	return at, true, nil
}
