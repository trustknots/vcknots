package local

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/trustknots/vcknots/wallet/credstore/types"
)

func TestNewLocalCredentialStorage(t *testing.T) {
	type args struct {
		path   string
		result chan struct {
			LocalCredentialStorage *LocalCredentialStorage
			Error                  error
		}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Normal case",
			args: args{path: "local_test.db", result: make(chan struct {
				LocalCredentialStorage *LocalCredentialStorage
				Error                  error
			})},
			wantErr: false,
		},
		{
			name: "Unexisting path",
			args: args{path: "/u/n/e/x/i/s/t/i/n/g/path/local_test.db", result: make(chan struct {
				LocalCredentialStorage *LocalCredentialStorage
				Error                  error
			})},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lcs, err := NewLocalCredentialStorage(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewLocalCredentialStorage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (lcs == nil) != tt.wantErr {
				t.Errorf("NewLocalCredentialStorage() returns nil")
				return
			}
		})
		_ = os.Remove(tt.args.path)
	}
}

func TestLocalCredentialStorage_SaveCredentialEntry(t *testing.T) {
	type args struct {
		credentialEntry types.CredentialEntry
		result          chan error
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Normal case",
			args: args{
				credentialEntry: types.CredentialEntry{
					Id:         "123-456",
					ReceivedAt: time.Now(),
					Raw:        []byte("hogefuga"),
					MimeType:   "application/json",
				},
				result: make(chan error),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lcs, _ := NewLocalCredentialStorage("local_test.db")
			err := lcs.SaveCredentialEntry(tt.args.credentialEntry, Local)
			if (err != nil) != tt.wantErr {
				t.Errorf("SaveCredentialEntry() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
		_ = os.Remove("local_test.db")
	}
}

func TestLocalCredentialStorage_GetCredentialEntries(t *testing.T) {
	type args struct {
		offset int
		limit  *int
		result chan struct {
			Entries    *[]types.CredentialEntry
			TotalCount *int
			Error      error
		}
	}
	tests := []struct {
		name                    string
		storedCredentialEntries []types.CredentialEntry
		args                    args
		wantErr                 bool
	}{
		{
			name: "Normal case",
			storedCredentialEntries: []types.CredentialEntry{
				{Id: "123-456", ReceivedAt: time.Now().Truncate(0), Raw: []byte("hoge"), MimeType: "application/json"},
				{Id: "456-789", ReceivedAt: time.Now().Truncate(0), Raw: []byte("fuga"), MimeType: "application/json+ld"},
				{Id: "789-123", ReceivedAt: time.Now().Truncate(0), Raw: []byte("piyo"), MimeType: "plain/txt"},
			},
			args: args{
				offset: 0,
				limit:  nil,
				result: make(chan struct {
					Entries    *[]types.CredentialEntry
					TotalCount *int
					Error      error
				}),
			},
			wantErr: false,
		},
		{
			name: "Offset",
			storedCredentialEntries: []types.CredentialEntry{
				{Id: "123-456", ReceivedAt: time.Now().Truncate(0), Raw: []byte("hoge"), MimeType: "application/json"},
				{Id: "456-789", ReceivedAt: time.Now().Truncate(0), Raw: []byte("fuga"), MimeType: "application/json+ld"},
				{Id: "789-123", ReceivedAt: time.Now().Truncate(0), Raw: []byte("piyo"), MimeType: "plain/txt"},
			},
			args: args{
				offset: 1,
				limit:  nil,
				result: make(chan struct {
					Entries    *[]types.CredentialEntry
					TotalCount *int
					Error      error
				}),
			},
			wantErr: false,
		},
		{
			name: "Limit",
			storedCredentialEntries: []types.CredentialEntry{
				{Id: "123-456", ReceivedAt: time.Now().Truncate(0), Raw: []byte("hoge"), MimeType: "application/json"},
				{Id: "456-789", ReceivedAt: time.Now().Truncate(0), Raw: []byte("fuga"), MimeType: "application/json+ld"},
				{Id: "789-123", ReceivedAt: time.Now().Truncate(0), Raw: []byte("piyo"), MimeType: "plain/txt"},
			},
			args: args{
				offset: 0,
				limit:  func() *int { i := 1; return &i }(),
				result: make(chan struct {
					Entries    *[]types.CredentialEntry
					TotalCount *int
					Error      error
				}),
			},
			wantErr: false,
		},
		{
			name: "Limit (over)",
			storedCredentialEntries: []types.CredentialEntry{
				{Id: "123-456", ReceivedAt: time.Now().Truncate(0), Raw: []byte("hoge"), MimeType: "application/json"},
				{Id: "456-789", ReceivedAt: time.Now().Truncate(0), Raw: []byte("fuga"), MimeType: "application/json+ld"},
				{Id: "789-123", ReceivedAt: time.Now().Truncate(0), Raw: []byte("piyo"), MimeType: "plain/txt"},
			},
			args: args{
				offset: 0,
				limit:  func() *int { i := 100; return &i }(),
				result: make(chan struct {
					Entries    *[]types.CredentialEntry
					TotalCount *int
					Error      error
				}),
			},
			wantErr: false,
		},
		{
			name: "Offset (over)",
			storedCredentialEntries: []types.CredentialEntry{
				{Id: "123-456", ReceivedAt: time.Now().Truncate(0), Raw: []byte("hoge"), MimeType: "application/json"},
				{Id: "456-789", ReceivedAt: time.Now().Truncate(0), Raw: []byte("fuga"), MimeType: "application/json+ld"},
				{Id: "789-123", ReceivedAt: time.Now().Truncate(0), Raw: []byte("piyo"), MimeType: "plain/txt"},
			},
			args: args{
				offset: 100,
				limit:  nil,
				result: make(chan struct {
					Entries    *[]types.CredentialEntry
					TotalCount *int
					Error      error
				}),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lcs, _ := NewLocalCredentialStorage("local_test.db")
			// Save
			for _, e := range tt.storedCredentialEntries {
				_ = lcs.SaveCredentialEntry(e, Local)
			}
			// Collect
			result, err := lcs.GetCredentialEntries(tt.args.offset, tt.args.limit, Local)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCredentialEntries() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if result.Entries == nil {
					t.Errorf("GetCredentialEntries() returned nil entries")
					return
				}
				totalCount := len(tt.storedCredentialEntries)
				if *(result.TotalCount) != totalCount {
					t.Errorf("GetCredentialEntries() returned unexpected TotalCount. expected = %v, result = %v", totalCount, *(result.TotalCount))
					return
				}
				start := tt.args.offset
				end := totalCount
				if start >= totalCount {
					start = totalCount
					end = totalCount
				} else {
					if tt.args.limit != nil && start+*tt.args.limit < totalCount {
						end = start + *tt.args.limit
					}
				}
				expectedEntries := tt.storedCredentialEntries[start:end]
				for i := range expectedEntries {
					if !cmp.Equal(expectedEntries[i], (*result.Entries)[i]) {
						t.Errorf("GetCredentialEntries() returned unexpected entries. expected = %v, result = %v", expectedEntries[i], (*result.Entries)[i])
						return
					}
				}
			}
		})
		_ = os.Remove("local_test.db")
	}
}

func TestLocalCredentialStorage_GetCredentialEntry(t *testing.T) {
	type args struct {
		id     string
		result chan struct {
			Entry *types.CredentialEntry
			Error error
		}
	}
	tests := []struct {
		name                    string
		storedCredentialEntries []types.CredentialEntry
		args                    args
		wantErr                 bool
	}{
		{
			name: "Normal case",
			storedCredentialEntries: []types.CredentialEntry{
				{Id: "123-456", ReceivedAt: time.Now().Truncate(0), Raw: []byte("hoge"), MimeType: "application/json"},
				{Id: "456-789", ReceivedAt: time.Now().Truncate(0), Raw: []byte("fuga"), MimeType: "application/json+ld"},
				{Id: "789-123", ReceivedAt: time.Now().Truncate(0), Raw: []byte("piyo"), MimeType: "plain/txt"},
			},
			args: args{
				id: "456-789",
				result: make(chan struct {
					Entry *types.CredentialEntry
					Error error
				}),
			},
			wantErr: false,
		},
		{
			name: "Not found case",
			storedCredentialEntries: []types.CredentialEntry{
				{Id: "123-456", ReceivedAt: time.Now().Truncate(0), Raw: []byte("hoge"), MimeType: "application/json"},
				{Id: "456-789", ReceivedAt: time.Now().Truncate(0), Raw: []byte("fuga"), MimeType: "application/json+ld"},
				{Id: "789-123", ReceivedAt: time.Now().Truncate(0), Raw: []byte("piyo"), MimeType: "plain/txt"},
			},
			args: args{
				id: "fake-fake",
				result: make(chan struct {
					Entry *types.CredentialEntry
					Error error
				}),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lcs, _ := NewLocalCredentialStorage("local_test.db")
			// Save
			for _, e := range tt.storedCredentialEntries {
				_ = lcs.SaveCredentialEntry(e, Local)
			}
			// Collect
			ce, err := lcs.GetCredentialEntry(tt.args.id, Local)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("credstore.GetCredentialEntry() error = %v", err)
					return
				} else {
					return
				}
			}

			exists := false
			for _, e := range tt.storedCredentialEntries {
				if e.Id == tt.args.id {
					if !cmp.Equal(e, *ce) {
						t.Errorf("credstore.GetCredentialEntry returns different entry. expected = %v, result = %v", e, *ce)
						return
					}
					exists = true
				}
			}

			if !exists {
				t.Errorf("credstore.GetCredentialEntry returns unexsited entry.")
				return
			}
		})
		_ = os.Remove("local_test.db")
	}
}
