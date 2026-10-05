package wallet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"testing"

	"github.com/trustknots/vcknots/wallet/acceptance"
)

func TestClassifyGivesEveryErrorACode(t *testing.T) {
	uncoded := errors.New("boom")
	coded := fmt.Errorf("wrapped: %w", acceptance.ErrCredentialExpired)
	tests := []struct {
		name  string
		err   error
		want  string
		is    []error
		keeps bool // the input is returned unchanged
	}{
		{"coded error is kept", coded, "credential_expired", []error{acceptance.ErrCredentialExpired}, true},
		{"canceled", fmt.Errorf("send: %w", context.Canceled), "canceled", []error{ErrCanceled, context.Canceled}, false},
		{"deadline", &url.Error{Op: "Post", URL: "https://x", Err: context.DeadlineExceeded}, "deadline_exceeded", []error{ErrDeadlineExceeded, context.DeadlineExceeded}, false},
		{"network", &url.Error{Op: "Get", URL: "https://x", Err: &net.OpError{Op: "dial", Err: uncoded}}, "network_error", []error{ErrNetwork, uncoded}, false},
		{"malformed URL", &url.Error{Op: "parse", URL: "::", Err: uncoded}, "unclassified", []error{ErrUnclassified}, false},
		{"anything else", uncoded, "unclassified", []error{ErrUnclassified, uncoded}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := classify(test.err)
			if code, ok := ErrorCode(got); !ok || code != test.want {
				t.Fatalf("ErrorCode(classify(err)) = %q, %v; want %q", code, ok, test.want)
			}
			for _, target := range test.is {
				if !errors.Is(got, target) {
					t.Errorf("classify(err) does not match %v", target)
				}
			}
			if test.keeps && got != test.err {
				t.Error("an error that already has a code must be returned unchanged")
			}
		})
	}
	if classify(nil) != nil {
		t.Error("classify(nil) must be nil")
	}
}
