package common

import (
	"encoding/json"
	"net/url"
)

type URIField url.URL

// UnmarshalJSON implements json.Unmarshaler
func (u *URIField) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	parsed, err := url.Parse(str)
	if err != nil {
		return err
	}

	*u = URIField(*parsed)
	return nil
}

func (u URIField) MarshalJSON() ([]byte, error) {
	x := url.URL(u)
	str := x.String()
	return json.Marshal(str)
}

// String returns the string representation of the URI
func (u URIField) String() string {
	x := url.URL(u)
	return x.String()
}

func ParseURIField(raw string) (*URIField, error) {
	x, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	uri := URIField(*x)
	return &uri, nil
}
