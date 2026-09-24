package wallet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"

	"github.com/trustknots/vcknots/wallet/common"
)

// CodedError is an error that names its condition with a stable,
// machine-readable code, so an integrator can branch on the condition, or
// carry it across a process or language boundary, without matching error text.
//
// The library promises:
//  1. Codes are lower_snake_case ASCII, unique across the module and never
//     reused for another condition. Removing a code is a breaking change.
//  2. Every non-nil error returned by an exported function or method of this
//     package has at least one code in its chain. Failures with no more
//     specific code are reported as ErrInvalidArgument, ErrCanceled,
//     ErrDeadlineExceeded, ErrNetwork or ErrUnclassified. The one exception is
//     an error returned by PresentCredentialOptions.OnRedirect, which is
//     passed back unchanged.
//  3. Exported sentinels and error types of the sub-packages are coded, but a
//     plugin method called directly may return an uncoded error from a
//     dependency; promise 2 applies once it crosses a method of this package.
type CodedError = common.CodedError

// Generic conditions, used only when no more specific code applies.
var (
	// ErrInvalidArgument reports input rejected before any I/O.
	ErrInvalidArgument = common.ErrInvalidInput
	// ErrCanceled reports that the operation's context was canceled; the
	// error also matches context.Canceled.
	ErrCanceled = common.ErrCancelled
	// ErrDeadlineExceeded reports that the operation's context deadline
	// passed; the error also matches context.DeadlineExceeded.
	ErrDeadlineExceeded = common.ErrTimeout
	// ErrNetwork reports a transport failure: the peer could not be reached
	// or the connection failed. The underlying error stays in the chain.
	ErrNetwork = common.NewCodedError("network_error", "network request failed")
	// ErrUnclassified reports a failure the library did not classify. It
	// indicates a missing code in the library.
	ErrUnclassified = common.NewCodedError("unclassified", "unclassified error")
)

// Profile conditions, reported when the wallet is built or its receiver set.
var (
	// ErrProfileMismatch reports a plugin whose profile.Carrier reports a
	// profile other than Config.Profile.
	ErrProfileMismatch = common.NewCodedError("profile_mismatch", "plugin profile does not match the wallet profile")
	// ErrProfilePluginUnsupported reports a plugin that does not implement
	// profile.Carrier in a HAIP wallet.
	ErrProfilePluginUnsupported = common.NewCodedError("profile_plugin_unsupported", "plugin does not report a profile")
	// ErrProfileForbidsDraft reports a draft protocol version or a test hook
	// used in a HAIP wallet. HAIP 1.0 applies only to OpenID4VCI 1.0 and
	// OpenID4VP 1.0.
	ErrProfileForbidsDraft = common.NewCodedError("profile_forbids_draft", "the HAIP profile allows no draft protocol version or test hook")
)

// ErrorCode reports the code of the outermost CodedError in err's chain, and
// whether one was found. ("", false) means err did not come from this library.
//
// The outermost code wins because an error that wraps another and still names
// a code has classified what it wraps.
func ErrorCode(err error) (string, bool) {
	return common.CodeOf(err)
}

// ErrorCodes reports every code in err's chain, most specific first: the codes
// of the errors a wrapper was built around come before the wrapper's own.
//
// A consumer that keeps its own table of the conditions it renders takes the
// first code its table holds. ErrorCode returns the outermost code only.
func ErrorCodes(err error) []string {
	return common.Codes(err)
}

// classify gives err a code when its chain has none, keeping err in the chain.
// Exported methods apply it to the errors they return.
func classify(err error) error {
	if err == nil {
		return nil
	}
	if _, coded := common.CodeOf(err); coded {
		return err
	}
	switch {
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("%w: %w", ErrCanceled, err)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%w: %w", ErrDeadlineExceeded, err)
	case isNetworkError(err):
		return fmt.Errorf("%w: %w", ErrNetwork, err)
	default:
		return fmt.Errorf("%w: %w", ErrUnclassified, err)
	}
}

// isNetworkError reports a transport failure. A *url.Error from url.Parse is
// a malformed URL, not one.
func isNetworkError(err error) bool {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Op != "parse"
	}
	var netErr net.Error
	return errors.As(err, &netErr)
}
