package types

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/trustknots/vcknots/wallet/internal/credential"
)

func TestParseCredentialEntry(t *testing.T) {
	// Existing test cases
	t.Run("Normal case", func(t *testing.T) {
		ce := &CredentialEntry{
			Id:         "123abc",
			ReceivedAt: time.Date(2025, 7, 28, 17, 20, 21, 123, time.UTC),
			Raw:        []byte(`{"hoge": "fuga"}`),
			MimeType:   "application/json",
		}

		got, err := ce.Serialize()
		if err != nil {
			t.Errorf("CredentialEntry.Serialize() error = %v, wantErr %v", err, false)
			return
		}

		parsed, err := ParseCredentialEntry(got)
		if err != nil {
			t.Fatalf("Serialized results could not be parsed again. error = %v", err)
		}
		if !reflect.DeepEqual(parsed, *ce) {
			t.Errorf("When the serialized results were parsed again, the fields did not match.")
		}
	})

	// Additional Test Cases
	t.Run("Parse invalid data", func(t *testing.T) {
		invalidData := []byte("this is not a valid json")
		_, err := ParseCredentialEntry(invalidData)
		if err == nil {
			t.Error("ParseCredentialEntry should have returned an error for invalid data, but it didn't")
		}
	})

	t.Run("CredStoreError methods", func(t *testing.T) {
		baseErr := errors.New("underlying database error")
		errWithId := NewCredStoreError(0, "test-id-123", "save", baseErr)
		expectedMsg := "credential store 0 operation save for ID test-id-123: underlying database error"
		if errWithId.Error() != expectedMsg {
			t.Errorf("CredStoreError.Error() with ID mismatch:\ngot:  %s\nwant: %s", errWithId.Error(), expectedMsg)
		}

		errWithoutId := NewCredStoreError(0, "", "list", baseErr)
		expectedMsgWithoutId := "credential store 0 operation list: underlying database error"
		if errWithoutId.Error() != expectedMsgWithoutId {
			t.Errorf("CredStoreError.Error() without ID mismatch:\ngot:  %s\nwant: %s", errWithoutId.Error(), expectedMsgWithoutId)
		}

		if unwrapped := errWithId.Unwrap(); unwrapped != baseErr {
			t.Errorf("CredStoreError.Unwrap() should return the original error")
		}
	})
}

func TestCredentialEntry_SerializationFlavor(t *testing.T) {
	type fields struct {
		Id         string
		ReceivedAt time.Time
		Raw        []byte
		MimeType   string
	}
	tests := []struct {
		name    string
		fields  fields
		want    credential.SupportedSerializationFlavor
		wantErr bool
	}{
		{
			name: "Normal case (JwtVc)",
			fields: fields{
				Id:         "hoge",
				ReceivedAt: time.Now(),
				Raw:        []byte(""),
				MimeType:   "application/vc+jwt",
			},
			want:    credential.JwtVc,
			wantErr: false,
		},
		{
			name: "Normal case (mock)",
			fields: fields{
				Id:         "hoge",
				ReceivedAt: time.Now(),
				Raw:        []byte(""),
				MimeType:   "plain/mock",
			},
			want:    credential.MockFormat,
			wantErr: false,
		},
		{
			name: "Normal case (SdJwtVc)",
			fields: fields{
				Id:         "hoge",
				ReceivedAt: time.Now(),
				Raw:        []byte(""),
				MimeType:   "application/dc+sd-jwt",
			},
			want:    credential.SDJwtVC,
			wantErr: false,
		},
		{
			name: "Invalid case",
			fields: fields{
				Id:         "hoge",
				ReceivedAt: time.Now(),
				Raw:        []byte(""),
				MimeType:   "application/hogefugapiyo",
			},
			want:    credential.JwtVc,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ce := &CredentialEntry{
				Id:         tt.fields.Id,
				ReceivedAt: tt.fields.ReceivedAt,
				Raw:        tt.fields.Raw,
				MimeType:   tt.fields.MimeType,
			}
			got, err := ce.SerializationFlavor()
			if err != nil {
				if tt.wantErr {
					return
				}
				t.Errorf("CredentialEntry.SerializationFlavor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CredentialEntry.SerializationFlavor() = %v, want %v", got, tt.want)
			}
		})
	}
}
