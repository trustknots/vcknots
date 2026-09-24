package statuslist

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"testing"
)

// ietfOneBitList is the one-bit example of draft-ietf-oauth-status-list
// Section 4.1: the bytes 0xB9 0xA3.
const ietfOneBitList = "eNrbuRgAAhcBXQ"

func zlibList(t *testing.T, raw []byte) string {
	t.Helper()
	var buffer bytes.Buffer
	writer := zlib.NewWriter(&buffer)
	if _, err := writer.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer.Bytes())
}

func readAll(t *testing.T, bits int, encoded string, count int) []int {
	t.Helper()
	values := make([]int, count)
	for index := range values {
		value, err := ReadValue(bits, encoded, index, 0)
		if err != nil {
			t.Fatalf("ReadValue(bits=%d, index=%d): %v", bits, index, err)
		}
		values[index] = value
	}
	return values
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestReadValueDecodesPackedEntriesLeastSignificantBitsFirst(t *testing.T) {
	tests := []struct {
		name    string
		bits    int
		encoded string
		want    []int
	}{
		{
			name:    "IETF one-bit example",
			bits:    1,
			encoded: ietfOneBitList,
			want:    []int{1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1},
		},
		{
			name:    "two-bit entries",
			bits:    2,
			encoded: zlibList(t, []byte{0xC9, 0x44, 0xF9}),
			want:    []int{1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3},
		},
		{
			name:    "four-bit entries",
			bits:    4,
			encoded: zlibList(t, []byte{0x21, 0xF0}),
			want:    []int{1, 2, 0, 15},
		},
		{
			name:    "eight-bit entries",
			bits:    8,
			encoded: zlibList(t, []byte{0x00, 0x01, 0x02, 0xFF}),
			want:    []int{0, 1, 2, 255},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := readAll(t, test.bits, test.encoded, len(test.want))
			if !equalInts(got, test.want) {
				t.Fatalf("values = %v, want %v", got, test.want)
			}
		})
	}
}

func TestReadValueRefusesIndexPastTheList(t *testing.T) {
	// Two bytes hold 16, 8, 4 and 2 entries at 1, 2, 4 and 8 bits: the first
	// index past each is refused, never read as the zero "VALID" value.
	encoded := zlibList(t, []byte{0x00, 0x00})
	for _, test := range []struct{ bits, lastValid int }{{1, 15}, {2, 7}, {4, 3}, {8, 1}} {
		t.Run(strconv.Itoa(test.bits), func(t *testing.T) {
			if _, err := ReadValue(test.bits, encoded, test.lastValid, 0); err != nil {
				t.Fatalf("last valid index %d: %v", test.lastValid, err)
			}
			_, err := ReadValue(test.bits, encoded, test.lastValid+1, 0)
			if !errors.Is(err, ErrStatusListIndexOutOfRange) {
				t.Fatalf("index %d: err = %v, want ErrStatusListIndexOutOfRange", test.lastValid+1, err)
			}
		})
	}
}

func TestReadValueRefusesInvalidInput(t *testing.T) {
	var rawDeflate bytes.Buffer
	writer, err := flate.NewWriter(&rawDeflate, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = writer.Write([]byte{0xB9})
	_ = writer.Close()

	corrupt, _ := base64.RawURLEncoding.DecodeString(ietfOneBitList)
	corrupt[len(corrupt)-1] ^= 0xFF // Adler-32 trailer

	tests := []struct {
		name    string
		bits    int
		encoded string
		index   int
		want    error
	}{
		{"bits 0", 0, ietfOneBitList, 0, ErrStatusListTokenInvalid},
		{"bits 3", 3, ietfOneBitList, 0, ErrStatusListTokenInvalid},
		{"bits 16", 16, ietfOneBitList, 0, ErrStatusListTokenInvalid},
		{"negative index", 1, ietfOneBitList, -1, ErrStatusReferenceInvalid},
		{"empty lst", 1, "", 0, ErrStatusListDecodeFailed},
		{"not base64url", 1, "not-a-status-list!", 0, ErrStatusListDecodeFailed},
		{"padded base64url", 1, "eNrbuRgAAhcBXQ==", 0, ErrStatusListDecodeFailed},
		{"standard base64 alphabet", 1, "eNrbuRgAAhcB+Q", 0, ErrStatusListDecodeFailed},
		{"line-wrapped", 1, "eNrbuRgA\nAhcBXQ", 0, ErrStatusListDecodeFailed},
		{"raw deflate without zlib header", 1, base64.RawURLEncoding.EncodeToString(rawDeflate.Bytes()), 0, ErrStatusListDecodeFailed},
		{"corrupt checksum", 1, base64.RawURLEncoding.EncodeToString(corrupt), 0, ErrStatusListDecodeFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ReadValue(test.bits, test.encoded, test.index, 0)
			if !errors.Is(err, test.want) {
				t.Fatalf("err = %v, want %v", err, test.want)
			}
		})
	}
}

func TestReadValueRefusesIndexBeyondExactIntegers(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("int cannot hold 2^53 on this platform")
	}
	past := int64(maxExactInteger)
	past++
	index := int(past)
	if _, err := ReadValue(1, ietfOneBitList, index, 0); !errors.Is(err, ErrStatusReferenceInvalid) {
		t.Fatalf("err = %v, want ErrStatusReferenceInvalid", err)
	}
}

func TestReadValueCapsTheInflatedList(t *testing.T) {
	t.Run("exactly at the cap", func(t *testing.T) {
		encoded := zlibList(t, make([]byte, 4))
		if _, err := ReadValue(8, encoded, 3, 4); err != nil {
			t.Fatalf("list of exactly the cap: %v", err)
		}
	})
	t.Run("one byte past the cap", func(t *testing.T) {
		encoded := zlibList(t, make([]byte, 5))
		if _, err := ReadValue(8, encoded, 0, 4); !errors.Is(err, ErrStatusListDecodeFailed) {
			t.Fatalf("err = %v, want ErrStatusListDecodeFailed", err)
		}
	})
	t.Run("compression bomb against the default cap", func(t *testing.T) {
		encoded := zlibList(t, make([]byte, 64<<20))
		if len(encoded) > 128<<10 {
			t.Fatalf("bomb is not a bomb: %d encoded bytes", len(encoded))
		}
		if _, err := ReadValue(1, encoded, 0, 0); !errors.Is(err, ErrStatusListDecodeFailed) {
			t.Fatalf("err = %v, want ErrStatusListDecodeFailed", err)
		}
	})
}

func TestIntegerValue(t *testing.T) {
	tests := []struct {
		name   string
		value  any
		want   int64
		wantOK bool
	}{
		{"json.Number integer", json.Number("42"), 42, true},
		{"json.Number integral fraction", json.Number("1.0"), 1, true},
		{"json.Number exponent", json.Number("1e3"), 1000, true},
		{"json.Number fraction", json.Number("1.5"), 0, false},
		{"json.Number max exact", json.Number("9007199254740991"), maxExactInteger, true},
		{"json.Number past max exact", json.Number("9007199254740992"), 0, false},
		{"json.Number huge", json.Number("1e400"), 0, false},
		{"json.Number negative", json.Number("-3"), -3, true},
		{"float64 integral", float64(7), 7, true},
		{"float64 fraction", 7.25, 0, false},
		{"float64 NaN", math.NaN(), 0, false},
		{"float64 Inf", math.Inf(1), 0, false},
		{"float64 past max exact", float64(1 << 53), 0, false},
		{"int", 5, 5, true},
		{"int64", int64(6), 6, true},
		{"int64 past max exact", int64(1 << 53), 0, false},
		{"string", "1", 0, false},
		{"nil", nil, 0, false},
		{"bool", true, 0, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := integerValue(test.value)
			if ok != test.wantOK || got != test.want {
				t.Fatalf("integerValue(%v) = %d, %v; want %d, %v", test.value, got, ok, test.want, test.wantOK)
			}
		})
	}
}
