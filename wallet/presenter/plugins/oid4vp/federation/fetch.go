package federation

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
)

// entityStatementMediaType is the media type an Entity Statement is served
// with (OpenID Federation 1.0 Sections 8.1.2 and 9.2).
const entityStatementMediaType = "application/entity-statement+jwt"

// entityConfigurationPath is the well-known path an Entity Configuration is
// published at (OpenID Federation 1.0 Section 9).
const entityConfigurationPath = "/.well-known/openid-federation"

// EntityConfigurationURL returns the URL of the Entity Configuration of
// entityID (OpenID Federation 1.0 Section 9): the well-known path appended to
// the Entity Identifier with any trailing slash removed. The Entity Identifier
// must be an https URL without userinfo, query or fragment.
func EntityConfigurationURL(entityID string) (string, error) {
	entity, err := parseHTTPSFederationURL(entityID, "entity identifier")
	if err != nil {
		return "", err
	}
	if entity.RawQuery != "" || entity.ForceQuery {
		return "", failure(ErrStatementFetchFailed, "entity identifier must not contain query or fragment")
	}
	return entity.Scheme + "://" + entity.Host + strings.TrimSuffix(entity.EscapedPath(), "/") + entityConfigurationPath, nil
}

// SubordinateStatementURL returns the fetch endpoint request for the
// Subordinate Statement about subjectEntityID (OpenID Federation 1.0 Section
// 8.1.1): the superior's federation_fetch_endpoint with the `sub` query
// parameter appended. The subject is sent exactly as written, without URL
// normalization.
func SubordinateStatementURL(federationFetchEndpoint, subjectEntityID string) (string, error) {
	endpoint, err := parseHTTPSFederationURL(federationFetchEndpoint, "fetch endpoint")
	if err != nil {
		return "", err
	}
	subject, err := parseHTTPSFederationURL(subjectEntityID, "subordinate entity identifier")
	if err != nil {
		return "", err
	}
	if subject.RawQuery != "" || subject.ForceQuery {
		return "", failure(ErrStatementFetchFailed, "subordinate entity identifier must not contain query or fragment")
	}
	query := endpoint.RawQuery
	if query != "" {
		query += "&"
	}
	endpoint.RawQuery = query + "sub=" + url.QueryEscape(subjectEntityID)
	endpoint.ForceQuery = false
	return endpoint.String(), nil
}

// parseHTTPSFederationURL parses a URL a statement is fetched from or named
// by, requiring https and refusing userinfo and fragments.
func parseHTTPSFederationURL(value, label string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return nil, failure(ErrStatementFetchFailed, "%s is not a URL", label)
	}
	if parsed.Scheme != "https" {
		return nil, failure(ErrStatementFetchFailed, "%s must use HTTPS", label)
	}
	if parsed.User != nil {
		return nil, failure(ErrStatementFetchFailed, "%s must not contain userinfo", label)
	}
	if parsed.Fragment != "" || strings.Contains(value, "#") {
		return nil, failure(ErrStatementFetchFailed, "%s must not contain a fragment", label)
	}
	return parsed, nil
}

// fetchEntityStatement retrieves one Entity Statement. It refuses a non-https
// URL, a host the public-network policy rejects, any redirect, a non-2xx
// status, a response not labelled as an Entity Statement, and an empty or
// oversized body.
func (r *Resolver) fetchEntityStatement(ctx context.Context, statementURL string) (string, error) {
	parsed, err := parseHTTPSFederationURL(statementURL, "entity statement URL")
	if err != nil {
		return "", err
	}
	if err := r.checkPublicNetworkHost(parsed.Hostname()); err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, statementURL, nil)
	if err != nil {
		return "", failure(ErrStatementFetchFailed, "entity statement request could not be built")
	}
	request.Header.Set("Accept", entityStatementMediaType)
	response, err := r.client().Do(request)
	if err != nil {
		return "", failure(ErrStatementFetchFailed, "entity statement request failed")
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode >= http.StatusMultipleChoices && response.StatusCode < http.StatusBadRequest {
		return "", failure(ErrStatementFetchFailed, "entity statement redirects are not allowed")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", failure(ErrStatementFetchFailed, "entity statement returned HTTP %d", response.StatusCode)
	}
	if !httpfetch.MediaTypeIs(response.Header, entityStatementMediaType) {
		return "", failure(ErrStatementFetchFailed, "entity statement response must use %s", entityStatementMediaType)
	}
	body, err := httpfetch.ReadLimited(response, r.maxStatementBytes())
	if errors.Is(err, httpfetch.ErrBodyTooLarge) {
		return "", failure(ErrStatementFetchFailed, "entity statement response is too large")
	}
	if err != nil {
		return "", failure(ErrStatementFetchFailed, "entity statement response could not be read")
	}
	statement := strings.TrimSpace(string(body))
	if statement == "" {
		return "", failure(ErrStatementFetchFailed, "entity statement response is empty")
	}
	return statement, nil
}

// checkPublicNetworkHost applies RequirePublicNetworkHost. With no
// IsPublicNetworkHost function configured every host is refused.
func (r *Resolver) checkPublicNetworkHost(host string) error {
	if !r.RequirePublicNetworkHost {
		return nil
	}
	if r.IsPublicNetworkHost != nil && r.IsPublicNetworkHost(host) {
		return nil
	}
	return failure(ErrStatementFetchFailed, "entity statement URL must use a public network host")
}
