package statuslist

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"fmt"
	"io"
	"math"
)

// defaultMaxDecompressedBytes bounds how large an inflated status list may be
// when the caller sets no bound of its own. The compressed form is attacker
// controlled in the sense that it is whatever the Status List endpoint served,
// and DEFLATE reaches ratios above 1000:1, so an unbounded inflate turns a
// small response into an allocation the wallet cannot refuse. One mebibyte
// holds 8388608 one-bit entries, far past any list a wallet is asked to read.
const defaultMaxDecompressedBytes = 1 << 20

// maxExactInteger is the largest integer a JSON number represents without loss
// (2^53 - 1). Indexes beyond it cannot survive a round trip through an
// implementation that decodes JSON numbers as IEEE 754 doubles, which RFC 8259
// Section 6 warns about, so they are refused rather than silently shifted.
const maxExactInteger = 1<<53 - 1

// statusListBitsAllowed is the set of entry widths
// draft-ietf-oauth-status-list Section 4.1 defines for a Status List: 1, 2, 4
// or 8 bits. Every allowed width divides a byte evenly, which is what lets an
// index be resolved by integer division instead of by bit addressing across
// byte boundaries. A width outside the set is not a Status List this package
// can read, and is refused rather than approximated.
var statusListBitsAllowed = [...]int{1, 2, 4, 8}

// ReadValue reads one status value out of the `lst` member of a Status List.
//
// encodedList is the base64url encoded (RFC 7515 Section 2, unpadded) zlib
// compressed data stream (RFC 1950) that draft-ietf-oauth-status-list
// Section 4.1 defines, and bits is the accompanying `bits` value: 1, 2, 4 or 8.
// maxDecompressedBytes bounds the inflated list; a value of zero or less means
// one mebibyte. The bound is applied while inflating, not after, so an
// over-long stream is abandoned rather than buffered.
//
// Within the decoded byte string, entries are packed from the least
// significant bits of each byte upwards, as Section 4.1 specifies:
//
//	valuesPerByte = 8 / bits
//	byteIndex     = index / valuesPerByte
//	bitOffset     = (index % valuesPerByte) * bits
//	value         = (list[byteIndex] >> bitOffset) & (1<<bits - 1)
//
// so with bits = 2 the byte 0xC9 carries the values 1, 2, 0 and 3, in that
// order of index. An index past the end of the decoded list is reported as
// ErrStatusListIndexOutOfRange and never as a value: a wallet must not read a
// missing entry as the "VALID" the zero bit pattern would look like.
func ReadValue(bits int, encodedList string, index int, maxDecompressedBytes int) (int, error) {
	if err := validateBits(bits); err != nil {
		return 0, err
	}
	if index < 0 || int64(index) > maxExactInteger {
		return 0, fmt.Errorf("%w: status list index %d is not an exactly representable non-negative integer", ErrStatusReferenceInvalid, index)
	}
	compressed, err := decodeBase64URL(encodedList)
	if err != nil {
		return 0, err
	}
	list, err := inflate(compressed, maxDecompressedBytes)
	if err != nil {
		return 0, err
	}

	valuesPerByte := 8 / bits
	byteIndex := index / valuesPerByte
	if byteIndex >= len(list) {
		return 0, fmt.Errorf("%w: index %d needs byte %d of a %d byte status list", ErrStatusListIndexOutOfRange, index, byteIndex, len(list))
	}
	bitOffset := (index % valuesPerByte) * bits
	mask := 1<<bits - 1
	return int(list[byteIndex]>>bitOffset) & mask, nil
}

// validateBits checks an entry width against the widths
// draft-ietf-oauth-status-list Section 4.1 defines.
func validateBits(bits int) error {
	for _, allowed := range statusListBitsAllowed {
		if bits == allowed {
			return nil
		}
	}
	return fmt.Errorf("%w: status list bits must be 1, 2, 4 or 8, got %d", ErrStatusListTokenInvalid, bits)
}

// decodeBase64URL decodes the `lst` member. The encoding is base64url without
// padding (RFC 7515 Section 2), so a value carrying '=' , '+' or '/' is not the
// encoding the specification names and is refused rather than repaired: a
// wallet that accepts several spellings of the same list accepts a list its
// issuer never published. encoding/base64 silently skips carriage returns and
// line feeds, so the alphabet is checked first: a line-wrapped value is not the
// encoding either.
func decodeBase64URL(encodedList string) ([]byte, error) {
	if encodedList == "" {
		return nil, fmt.Errorf("%w: status list lst is empty", ErrStatusListDecodeFailed)
	}
	for position := 0; position < len(encodedList); position++ {
		if !isBase64URLByte(encodedList[position]) {
			return nil, fmt.Errorf("%w: status list lst carries %q at offset %d, outside the base64url alphabet", ErrStatusListDecodeFailed, encodedList[position], position)
		}
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encodedList)
	if err != nil {
		return nil, fmt.Errorf("%w: status list lst is not unpadded base64url: %w", ErrStatusListDecodeFailed, err)
	}
	return decoded, nil
}

// inflate decompresses a status list, refusing to hold more than
// maxDecompressedBytes of output.
//
// draft-ietf-oauth-status-list Section 4.1 compresses the status list with
// DEFLATE (RFC 1951) in the ZLIB data format (RFC 1950), so the stream carries
// the two byte ZLIB header and the trailing Adler-32 check value; raw DEFLATE
// is not that format and is refused by the reader.
//
// The bound is enforced during inflation by reading through a reader limited to
// one byte past the cap: if that extra byte materializes, the stream is longer
// than the caller allows and the rest is never produced. Inflating first and
// measuring afterwards would already have paid the allocation the bound exists
// to prevent.
func inflate(compressed []byte, maxDecompressedBytes int) ([]byte, error) {
	if maxDecompressedBytes <= 0 {
		maxDecompressedBytes = defaultMaxDecompressedBytes
	}
	reader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("%w: status list is not a zlib compressed data stream: %w", ErrStatusListDecodeFailed, err)
	}
	defer reader.Close()

	limit := int64(maxDecompressedBytes)
	if limit < math.MaxInt64 {
		limit++
	}
	list, err := io.ReadAll(io.LimitReader(reader, limit))
	if err != nil {
		return nil, fmt.Errorf("%w: status list could not be inflated: %w", ErrStatusListDecodeFailed, err)
	}
	if len(list) > maxDecompressedBytes {
		return nil, fmt.Errorf("%w: status list inflates to more than the %d byte cap", ErrStatusListDecodeFailed, maxDecompressedBytes)
	}
	return list, nil
}

// isBase64URLByte reports whether b belongs to the base64url alphabet of
// RFC 4648 Section 5.
func isBase64URLByte(b byte) bool {
	return 'A' <= b && b <= 'Z' || 'a' <= b && b <= 'z' || '0' <= b && b <= '9' || b == '-' || b == '_'
}
