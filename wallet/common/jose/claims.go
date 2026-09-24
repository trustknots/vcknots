package jose

import (
	"bytes"
	"encoding/json"
)

// Claims preserves JSON numbers when go-jose decodes an extensible JWT claims
// object. DCQL values and credential claims must not round through float64.
type Claims map[string]any

// UnmarshalJSON implements json.Unmarshaler, decoding numbers as json.Number.
func (claims *Claims) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var values map[string]any
	if err := decoder.Decode(&values); err != nil {
		return err
	}
	*claims = values
	return nil
}
