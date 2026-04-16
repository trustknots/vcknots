package presenter

import (
	"fmt"
	"net/url"

	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/presenter/types"
)

type PresentationRequest = types.PresentationRequest

type PresentationDispatcher struct {
	plugins map[types.SupportedPresentationProtocol]types.Presenter
}

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

func WithDefaultConfig() func(d *PresentationDispatcher) error {
	return func(d *PresentationDispatcher) error {
		oid4vpReceiver := &oid4vp.Oid4vpPresenter{}
		return d.registerPlugin(types.Oid4vp, oid4vpReceiver)
	}
}

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

func (d *PresentationDispatcher) Present(protocol SupportedPresentationProtocol, endpoint url.URL, serializedPresentation []byte, presentationSubmission PresentationSubmission, request *PresentationRequest) error {
	if len(serializedPresentation) == 0 {
		return types.NewPresenterError(protocol, endpoint.String(), "present", types.ErrInvalidPresentation)
	}

	plugin, err := d.getPlugin(protocol)
	if err != nil {
		return err
	}

	if err := plugin.Present(protocol, endpoint, serializedPresentation, presentationSubmission, request); err != nil {
		return types.NewPresenterError(protocol, endpoint.String(), "present", err)
	}

	return nil
}

func (d *PresentationDispatcher) ParseRequestURI(uriString string) (*oid4vp.CredentialPresentationRequest, error) {
	// Determine protocol from URI (currently only OID4VP is supported)
	protocol := types.Oid4vp

	// Get appropriate plugin
	plugin, err := d.getPlugin(protocol)
	if err != nil {
		return nil, types.NewPresenterError(protocol, "", "parse_uri", err)
	}
	// Cast to OID4VP plugin and call ParsePresentationRequest
	if oid4vpPlugin, ok := plugin.(*oid4vp.Oid4vpPresenter); ok {
		req, err := oid4vpPlugin.ParsePresentationRequest(uriString)
		if err != nil {
			return nil, types.NewPresenterError(protocol, "", "parse_uri", err)
		}
		return req, nil
	}
	return nil, types.NewPresenterError(protocol, "", "parse_uri", types.ErrUnsupportedProtocol)
}
