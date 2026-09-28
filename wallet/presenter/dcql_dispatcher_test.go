package presenter

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/trustknots/vcknots/wallet/presenter/types"
)

// customProtocol is a protocol value no bundled plugin uses, so a routing
// test proves the dispatcher routes by the request rather than by Oid4vp.
const customProtocol types.SupportedPresentationProtocol = 7

type routedRequest struct {
	protocol types.SupportedPresentationProtocol
}

func (r routedRequest) Protocol() types.SupportedPresentationProtocol { return r.protocol }

type respondingPresenter struct {
	mockPresenter
	submit func(ctx context.Context, req types.AdmittedRequest, vpToken map[string][]string) (*types.SubmitResult, error)
	parse  func(ctx context.Context, uri string) (types.AdmittedRequest, error)
}

func (p *respondingPresenter) SubmitDCQLResponse(ctx context.Context, req types.AdmittedRequest, vpToken map[string][]string) (*types.SubmitResult, error) {
	return p.submit(ctx, req, vpToken)
}

func (p *respondingPresenter) SubmitErrorResponse(context.Context, types.AdmittedRequest, string, string) (*types.SubmitResult, error) {
	return &types.SubmitResult{}, nil
}

func (p *respondingPresenter) ParseRequest(ctx context.Context, uri string) (types.AdmittedRequest, error) {
	return p.parse(ctx, uri)
}

func (p *respondingPresenter) ParseRequestObject(context.Context, string, types.RequestObjectSource) (types.AdmittedRequest, error) {
	return nil, errors.New("not used")
}

func TestPresentationDispatcher_SubmitDCQLResponse_RequiresRegisteredCapability(t *testing.T) {
	tests := []struct {
		name   string
		plugin types.Presenter
		op     string
	}{
		{name: "no registered plugin", op: "get_plugin"},
		{name: "plugin has only single-query Present", plugin: &mockPresenter{}, op: "submit_dcql"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dispatcher, err := NewPresentationDispatcher()
			if err != nil {
				t.Fatalf("NewPresentationDispatcher() error = %v", err)
			}
			if tt.plugin != nil {
				if err := dispatcher.registerPlugin(customProtocol, tt.plugin); err != nil {
					t.Fatalf("register plugin: %v", err)
				}
			}
			result, err := dispatcher.SubmitDCQLResponse(context.Background(), routedRequest{customProtocol}, map[string][]string{"identity": {"presentation"}})
			if result != nil || !errors.Is(err, types.ErrUnsupportedProtocol) {
				t.Fatalf("SubmitDCQLResponse() = (%v, %v), want ErrUnsupportedProtocol", result, err)
			}
			var presenterError *types.PresenterError
			if !errors.As(err, &presenterError) || presenterError.Protocol != customProtocol || presenterError.Op != tt.op {
				t.Fatalf("expected contextual PresenterError, got %#v", err)
			}
		})
	}
}

func TestPresentationDispatcher_SubmitDCQLResponse_RoutesByRequestProtocol(t *testing.T) {
	tokens := map[string][]string{"identity": {"identity-token"}, "accounts": {"account-one", "account-two"}}
	request := routedRequest{customProtocol}
	want := &types.SubmitResult{RedirectURI: "https://verifier.example/complete"}
	called := 0
	plugin := &respondingPresenter{submit: func(_ context.Context, gotRequest types.AdmittedRequest, gotTokens map[string][]string) (*types.SubmitResult, error) {
		called++
		if gotRequest != request || !reflect.DeepEqual(gotTokens, tokens) {
			t.Errorf("plugin received modified inputs: request=%#v tokens=%v", gotRequest, gotTokens)
		}
		return want, nil
	}}
	dispatcher, err := NewPresentationDispatcher(WithPlugin(customProtocol, plugin))
	if err != nil {
		t.Fatalf("NewPresentationDispatcher() error = %v", err)
	}
	result, err := dispatcher.SubmitDCQLResponse(context.Background(), request, tokens)
	if err != nil || result != want || called != 1 {
		t.Fatalf("SubmitDCQLResponse() = (%v, %v), calls=%d", result, err, called)
	}
	if _, err := dispatcher.SubmitDCQLResponse(context.Background(), nil, tokens); !errors.Is(err, types.ErrInvalidPresentation) {
		t.Fatalf("a nil request must be refused, got %v", err)
	}
}

func TestPresentationDispatcher_SubmitDCQLResponse_PreservesPluginError(t *testing.T) {
	failure := errors.New("verifier rejected authorization response")
	plugin := &respondingPresenter{submit: func(context.Context, types.AdmittedRequest, map[string][]string) (*types.SubmitResult, error) {
		return nil, failure
	}}
	dispatcher, err := NewPresentationDispatcher(WithPlugin(customProtocol, plugin))
	if err != nil {
		t.Fatalf("NewPresentationDispatcher() error = %v", err)
	}
	_, err = dispatcher.SubmitDCQLResponse(context.Background(), routedRequest{customProtocol}, map[string][]string{"identity": {"token"}})
	if !errors.Is(err, failure) {
		t.Fatalf("SubmitDCQLResponse() error = %v, want plugin error", err)
	}
	var presenterError *types.PresenterError
	if !errors.As(err, &presenterError) || presenterError.Op != "submit_dcql" {
		t.Fatalf("expected operation in PresenterError, got %#v", err)
	}
}

func TestPresentationDispatcher_ParseRequest_UsesTheNamedProtocol(t *testing.T) {
	admitted := routedRequest{customProtocol}
	plugin := &respondingPresenter{parse: func(_ context.Context, uri string) (types.AdmittedRequest, error) {
		if uri != "openid4vp://authorize?request_uri=x" {
			t.Errorf("uri = %q", uri)
		}
		return admitted, nil
	}}
	dispatcher, err := NewPresentationDispatcher(WithPlugin(customProtocol, plugin))
	if err != nil {
		t.Fatalf("NewPresentationDispatcher() error = %v", err)
	}
	got, err := dispatcher.ParseRequest(context.Background(), customProtocol, "openid4vp://authorize?request_uri=x")
	if err != nil || got != admitted {
		t.Fatalf("ParseRequest() = (%v, %v)", got, err)
	}
	if _, err := dispatcher.ParseDraft24Request(context.Background(), customProtocol, "x"); !errors.Is(err, types.ErrUnsupportedProtocol) {
		t.Fatalf("a plugin without Draft 24 support must be refused, got %v", err)
	}
	if _, err := dispatcher.ParseRequest(context.Background(), types.Oid4vp, "x"); !errors.Is(err, types.ErrUnsupportedProtocol) {
		t.Fatalf("an unregistered protocol must be refused, got %v", err)
	}
}
