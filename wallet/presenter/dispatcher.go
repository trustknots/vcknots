package presenter

import (
	"context"
	"fmt"
	"net/url"

	"github.com/trustknots/vcknots/wallet/env"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/presenter/types"
)

// PresentationRequest is types.PresentationRequest.
type PresentationRequest = types.PresentationRequest

// PresentationDispatcher routes presentation operations to the plugin
// registered for the requested protocol.
type PresentationDispatcher struct {
	plugins map[types.SupportedPresentationProtocol]types.Presenter
}

// NewPresentationDispatcher returns a PresentationDispatcher configured by
// options, such as WithDefaultConfig and WithPlugin.
func NewPresentationDispatcher(options ...func(*PresentationDispatcher) error) (*PresentationDispatcher, error) {
	d := &PresentationDispatcher{
		plugins: make(map[types.SupportedPresentationProtocol]types.Presenter),
	}

	for _, option := range options {
		if err := option(d); err != nil {
			return nil, types.NewPresenterError(0, "", "configure", fmt.Errorf("failed to configure presentation dispatcher: %w", err))
		}
	}

	return d, nil
}

// WithDefaultConfig registers an oid4vp.Oid4vpPresenter for types.Oid4vp,
// allowing plain http endpoints only when env.IsHTTPAllowed reports true.
func WithDefaultConfig() func(d *PresentationDispatcher) error {
	return func(d *PresentationDispatcher) error {
		oid4vpReceiver := &oid4vp.Oid4vpPresenter{AllowHTTP: env.IsHTTPAllowed()}
		return d.registerPlugin(types.Oid4vp, oid4vpReceiver)
	}
}

// WithPlugin registers plugin for protocol. A nil plugin is an error.
func WithPlugin(protocol types.SupportedPresentationProtocol, plugin types.Presenter) func(*PresentationDispatcher) error {
	return func(d *PresentationDispatcher) error {
		return d.registerPlugin(protocol, plugin)
	}
}

func (d *PresentationDispatcher) registerPlugin(protocol types.SupportedPresentationProtocol, plugin types.Presenter) error {
	if plugin == nil {
		return types.NewPresenterError(protocol, "", "register", types.ErrNilPlugin)
	}
	d.plugins[protocol] = plugin
	return nil
}

func (d *PresentationDispatcher) getPlugin(protocol types.SupportedPresentationProtocol) (types.Presenter, error) {
	plugin, exists := d.plugins[protocol]
	if !exists {
		return nil, types.NewPresenterError(protocol, "", "get_plugin", types.ErrUnsupportedProtocol)
	}
	return plugin, nil
}

// capability returns the plugin registered for protocol as the capability C.
func capability[C any](d *PresentationDispatcher, protocol types.SupportedPresentationProtocol, op string) (C, error) {
	var zero C
	plugin, err := d.getPlugin(protocol)
	if err != nil {
		return zero, err
	}
	capable, ok := plugin.(C)
	if !ok {
		return zero, types.NewPresenterError(protocol, "", op, types.ErrUnsupportedProtocol)
	}
	return capable, nil
}

// requestProtocol returns the protocol of an admitted request.
func requestProtocol(req types.AdmittedRequest, op string) (types.SupportedPresentationProtocol, error) {
	if req == nil {
		return 0, types.NewPresenterError(0, "", op, types.ErrInvalidPresentation)
	}
	return req.Protocol(), nil
}

// Plugins returns the registered presenter plugins for profile propagation and
// inspection. The returned slice is a copy, so callers cannot mutate the
// dispatcher's registry.
func (d *PresentationDispatcher) Plugins() []types.Presenter {
	plugins := make([]types.Presenter, 0, len(d.plugins))
	for _, plugin := range d.plugins {
		plugins = append(plugins, plugin)
	}
	return plugins
}

// Present sends serializedPresentation to endpoint with the plugin for
// protocol and returns the redirect URI the plugin reports, which may be empty.
func (d *PresentationDispatcher) Present(protocol SupportedPresentationProtocol, endpoint url.URL, serializedPresentation []byte, request *PresentationRequest) (string, error) {
	if len(serializedPresentation) == 0 {
		return "", types.NewPresenterError(protocol, endpoint.String(), "present", types.ErrInvalidPresentation)
	}

	plugin, err := d.getPlugin(protocol)
	if err != nil {
		return "", err
	}

	redirectURI, err := plugin.Present(protocol, endpoint, serializedPresentation, request)
	if err != nil {
		return "", types.NewPresenterError(protocol, endpoint.String(), "present", err)
	}
	return redirectURI, nil
}

// ParseRequestURI parses an OpenID4VP Authorization Request URI with the
// plugin registered for types.Oid4vp.
func (d *PresentationDispatcher) ParseRequestURI(uriString string) (*oid4vp.CredentialPresentationRequest, error) {
	protocol := types.Oid4vp
	admitted, err := d.ParseRequest(context.Background(), protocol, uriString)
	if err != nil {
		return nil, err
	}
	handle, ok := admitted.(*oid4vp.AdmittedRequest)
	if !ok {
		return nil, types.NewPresenterError(protocol, "", "parse_uri", types.ErrUnsupportedProtocol)
	}
	request := handle.Request()
	return &request, nil
}

// ParseRequest parses and admits an OpenID4VP 1.0 Authorization Request URI
// with the plugin registered for protocol.
func (d *PresentationDispatcher) ParseRequest(ctx context.Context, protocol types.SupportedPresentationProtocol, uri string) (types.AdmittedRequest, error) {
	parser, err := capability[types.RequestParser](d, protocol, "parse_uri")
	if err != nil {
		return nil, err
	}
	req, err := parser.ParseRequest(ctx, uri)
	if err != nil {
		return nil, types.NewPresenterError(protocol, "", "parse_uri", err)
	}
	return req, nil
}

// ParseRequestObject authenticates a Request Object the caller already holds,
// the by-value counterpart of ParseRequest.
func (d *PresentationDispatcher) ParseRequestObject(ctx context.Context, protocol types.SupportedPresentationProtocol, requestObject string, src types.RequestObjectSource) (types.AdmittedRequest, error) {
	parser, err := capability[types.RequestParser](d, protocol, "parse_request_object")
	if err != nil {
		return nil, err
	}
	req, err := parser.ParseRequestObject(ctx, requestObject, src)
	if err != nil {
		return nil, types.NewPresenterError(protocol, "", "parse_request_object", err)
	}
	return req, nil
}

// ParseDCAPIRequest parses and admits a Digital Credentials API invocation.
func (d *PresentationDispatcher) ParseDCAPIRequest(ctx context.Context, protocol types.SupportedPresentationProtocol, invocation types.DCAPIInvocation) (types.AdmittedRequest, error) {
	parser, err := capability[types.DCAPIRequestParser](d, protocol, "parse_dc_api")
	if err != nil {
		return nil, err
	}
	req, err := parser.ParseDCAPIRequest(ctx, invocation)
	if err != nil {
		return nil, types.NewPresenterError(protocol, "", "parse_dc_api", err)
	}
	return req, nil
}

// ParseDraft24Request parses and admits an OpenID4VP Draft 24 Authorization
// Request URI.
func (d *PresentationDispatcher) ParseDraft24Request(ctx context.Context, protocol types.SupportedPresentationProtocol, uri string) (types.AdmittedRequest, error) {
	parser, err := capability[types.Draft24RequestParser](d, protocol, "parse_draft24")
	if err != nil {
		return nil, err
	}
	req, err := parser.ParseDraft24Request(ctx, uri)
	if err != nil {
		return nil, types.NewPresenterError(protocol, "", "parse_draft24", err)
	}
	return req, nil
}

// ParseDraft24RequestObject is ParseRequestObject for the Draft 24 wire
// contract.
func (d *PresentationDispatcher) ParseDraft24RequestObject(ctx context.Context, protocol types.SupportedPresentationProtocol, requestObject string, src types.RequestObjectSource) (types.AdmittedRequest, error) {
	parser, err := capability[types.Draft24RequestParser](d, protocol, "parse_draft24_request_object")
	if err != nil {
		return nil, err
	}
	req, err := parser.ParseDraft24RequestObject(ctx, requestObject, src)
	if err != nil {
		return nil, types.NewPresenterError(protocol, "", "parse_draft24_request_object", err)
	}
	return req, nil
}

// SubmitDCQLResponse answers an admitted request with vp_token through the
// plugin registered for the request's protocol.
func (d *PresentationDispatcher) SubmitDCQLResponse(ctx context.Context, req types.AdmittedRequest, vpToken map[string][]string) (*types.SubmitResult, error) {
	protocol, err := requestProtocol(req, "submit_dcql")
	if err != nil {
		return nil, err
	}
	responder, err := capability[types.Responder](d, protocol, "submit_dcql")
	if err != nil {
		return nil, err
	}
	result, err := responder.SubmitDCQLResponse(ctx, req, vpToken)
	if err != nil {
		return nil, types.NewPresenterError(protocol, "", "submit_dcql", err)
	}
	return result, nil
}

// SubmitErrorResponse answers an admitted request with an error response
// through the plugin registered for the request's protocol.
func (d *PresentationDispatcher) SubmitErrorResponse(ctx context.Context, req types.AdmittedRequest, code, description string) (*types.SubmitResult, error) {
	protocol, err := requestProtocol(req, "submit_error")
	if err != nil {
		return nil, err
	}
	responder, err := capability[types.Responder](d, protocol, "submit_error")
	if err != nil {
		return nil, err
	}
	result, err := responder.SubmitErrorResponse(ctx, req, code, description)
	if err != nil {
		return nil, types.NewPresenterError(protocol, "", "submit_error", err)
	}
	return result, nil
}

// SubmitPresentationExchangeResponse answers an admitted Draft 24 request
// through the plugin registered for the request's protocol.
func (d *PresentationDispatcher) SubmitPresentationExchangeResponse(ctx context.Context, req types.AdmittedRequest, vpToken []byte, submission types.PresentationSubmission) (*types.SubmitResult, error) {
	protocol, err := requestProtocol(req, "submit_presentation_exchange")
	if err != nil {
		return nil, err
	}
	if len(vpToken) == 0 {
		return nil, types.NewPresenterError(protocol, "", "submit_presentation_exchange", types.ErrInvalidPresentation)
	}
	responder, err := capability[types.PresentationExchangeResponder](d, protocol, "submit_presentation_exchange")
	if err != nil {
		return nil, err
	}
	result, err := responder.SubmitPresentationExchangeResponse(ctx, req, vpToken, submission)
	if err != nil {
		return nil, types.NewPresenterError(protocol, "", "submit_presentation_exchange", err)
	}
	return result, nil
}
