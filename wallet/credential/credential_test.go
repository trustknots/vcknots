package credential

import (
	"reflect"
	"testing"
)

func TestSupportedSerializationFlavor_OID4VPFormatIdentifier(t *testing.T) {
	tests := []struct {
		name    string
		flavor  SupportedSerializationFlavor
		wantVc  string
		wantVp  string
		wantErr bool
	}{
		{
			name:    "Normal case (JwtVc)",
			flavor:  JwtVc,
			wantVc:  "jwt_vc_json",
			wantVp:  "jwt_vp_json",
			wantErr: false,
		},
		{
			name:    "Normal case (SDJwtVC)",
			flavor:  SDJwtVC,
			wantVc:  "dc+sd-jwt",
			wantVp:  "dc+sd-jwt",
			wantErr: false,
		},
		{
			name:    "Normal case (Mock)",
			flavor:  MockFormat,
			wantVc:  "mock_vc",
			wantVp:  "mock_vp",
			wantErr: false,
		},
		{
			name:    "Invalid case (Mock)",
			flavor:  "this_is_unsupported_flavor",
			wantVc:  "",
			wantVp:  "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVc, gotVp, err := tt.flavor.OID4VPFormatIdentifier()
			if err != nil {
				if tt.wantErr {
					return
				}
				t.Errorf("CredentialEntry.DIFClaimFormat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !(reflect.DeepEqual(gotVc, tt.wantVc) && reflect.DeepEqual(gotVp, tt.wantVp)) {
				t.Errorf("SupportedSerializationFlavor.OID4VPFormatIdentifier() = %v, %v. want %v, %v", gotVc, gotVp, tt.wantVc, tt.wantVp)
			}
		})
	}
}
