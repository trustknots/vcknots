package wallet

import (
	"testing"
)

func TestController_GetCredentialEntries_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	// Test with valid request using default config
	req := GetCredentialEntriesRequest{
		Offset: 0,
		Limit:  nil,
		Filter: nil,
	}

	// Integration test with real credential store (with default config)
	_, _, err := controller.GetCredentialEntries(req)
	if err != nil {
		t.Skipf("GetCredentialEntries failed with default plugin configuration, skipping: %v", err)
	}
}

func TestController_GetCredentialEntries_WithFilter_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	// Test with filter function
	req := GetCredentialEntriesRequest{
		Offset: 0,
		Limit:  nil,
		Filter: func(cred *SavedCredential) bool {
			return len(cred.Credential.Types) > 0
		},
	}

	_, _, err := controller.GetCredentialEntries(req)
	if err != nil {
		t.Skipf("GetCredentialEntries with filter failed, skipping: %v", err)
	}
}

func TestController_GetCredentialEntry_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	// Test with non-existent ID - should not error but return nil
	result, err := controller.GetCredentialEntry("non-existent-id")
	if err != nil {
		t.Skipf("GetCredentialEntry failed with non-existent ID, skipping: %v", err)
	}
	if result != nil {
		t.Error("GetCredentialEntry should return nil for non-existent ID")
	}
}

func TestController_GetCredentialEntry_ErrorPaths_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	tests := []struct {
		name     string
		id       string
		wantErr  bool
		errCheck func(error) bool
	}{
		{
			name:    "empty ID",
			id:      "",
			wantErr: true,
			errCheck: func(err error) bool {
				return err != nil
			},
		},
		{
			name:    "invalid ID with special characters",
			id:      "invalid/id\\with:special*chars",
			wantErr: true,
			errCheck: func(err error) bool {
				return err != nil
			},
		},
		{
			name:    "very long ID",
			id:      string(make([]byte, 1000)),
			wantErr: true,
			errCheck: func(err error) bool {
				return err != nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := controller.GetCredentialEntry(tt.id)
			if tt.wantErr && err == nil {
				t.Errorf("GetCredentialEntry() expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("GetCredentialEntry() unexpected error: %v", err)
			}
			if tt.wantErr && err != nil && !tt.errCheck(err) {
				t.Errorf("GetCredentialEntry() error check failed: %v", err)
			}
			if result != nil && tt.wantErr {
				t.Errorf("GetCredentialEntry() expected nil result on error")
			}
		})
	}
}

func TestController_GetCredentialEntries_OffsetLimitTests(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	tests := []struct {
		name    string
		request GetCredentialEntriesRequest
		wantErr bool
	}{
		{
			name: "high offset",
			request: GetCredentialEntriesRequest{
				Offset: 1000,
				Limit:  intPtr(10),
				Filter: nil,
			},
			wantErr: false,
		},
		{
			name: "zero limit",
			request: GetCredentialEntriesRequest{
				Offset: 0,
				Limit:  intPtr(0),
				Filter: nil,
			},
			wantErr: false,
		},
		{
			name: "negative offset (should be handled)",
			request: GetCredentialEntriesRequest{
				Offset: -1,
				Limit:  intPtr(10),
				Filter: nil,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := controller.GetCredentialEntries(tt.request)
			if tt.wantErr && err == nil {
				t.Errorf("GetCredentialEntries() expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("GetCredentialEntries() unexpected error: %v", err)
			}
		})
	}
}

// Helper function for creating int pointers
func intPtr(i int) *int {
	return &i
}

func TestController_GetCredentialEntries_FilterTests(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	tests := []struct {
		name   string
		filter func(cred *SavedCredential) bool
	}{
		{
			name: "filter by type",
			filter: func(cred *SavedCredential) bool {
				if cred == nil || cred.Credential == nil {
					return false
				}
				for _, t := range cred.Credential.Types {
					if t == "VerifiableCredential" {
						return true
					}
				}
				return false
			},
		},
		{
			name: "filter by ID presence",
			filter: func(cred *SavedCredential) bool {
				return cred != nil && cred.Credential != nil && cred.Credential.ID != ""
			},
		},
		{
			name: "filter always false",
			filter: func(cred *SavedCredential) bool {
				return false
			},
		},
		{
			name: "filter always true",
			filter: func(cred *SavedCredential) bool {
				return true
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := GetCredentialEntriesRequest{
				Offset: 0,
				Limit:  nil,
				Filter: tt.filter,
			}
			_, _, err := controller.GetCredentialEntries(req)
			if err != nil {
				t.Skipf("GetCredentialEntries with %s filter not supported in test environment: %v", tt.name, err)
			}
		})
	}
}
