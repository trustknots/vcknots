package common

import (
	"encoding/json"
	"net/netip"
	"net/url"
	"strings"
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

// IsLoopbackHost reports whether host names the local machine, so that a
// cleartext request to it never leaves the device. host is a URL host without
// its port, as returned by url.URL.Hostname.
//
// Only the literal name "localhost" and IP literals in a loopback range are
// accepted. Names that merely resolve to a loopback address are rejected: what
// a name resolves to is outside this package's control, and accepting them
// would make the check depend on DNS.
func IsLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	// A zone (fe80::1%eth0) is irrelevant to whether the address is loopback,
	// and netip reports zoned addresses as non-loopback.
	return addr.WithZone("").IsLoopback()
}
