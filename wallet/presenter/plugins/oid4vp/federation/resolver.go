package federation

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
)

// Package defaults a zero-valued Resolver field stands for.
const (
	// DefaultMaxDepth bounds how many Entities discovery walks up from the
	// subject before giving up.
	DefaultMaxDepth = 6
	// DefaultMaxAuthorityHints bounds how many authority_hints of one Entity
	// Configuration discovery follows, in the order they are listed.
	DefaultMaxAuthorityHints = 4
	// DefaultMaxFetches bounds the Entity Statements one resolution fetches.
	// A six-level chain needs eleven.
	DefaultMaxFetches = 32
	// DefaultMaxDuration bounds the wall-clock time of one discovery.
	DefaultMaxDuration = 30 * time.Second
	// DefaultMaxStatementBytes bounds one Entity Statement response.
	DefaultMaxStatementBytes int64 = 128 * 1024
	// DefaultHTTPTimeout is the timeout of the client used when Resolver
	// leaves HTTPClient nil.
	DefaultHTTPTimeout = 10 * time.Second
)

// maxPathsPerEntity bounds the candidate paths kept per Entity during
// discovery; the shortest are kept. It keeps path enumeration linear in the
// number of Entities even when authority hints form a dense graph.
const maxPathsPerEntity = 8

// Resolver discovers and validates Trust Chains (OpenID Federation 1.0
// Section 10). Zero-valued fields mean the package defaults. A Resolver keeps
// no state across calls: the Entity Statements it fetches are memoized only for
// the duration of one resolution.
//
// Discovery follows authority hints named by the Entities being resolved, so
// every fetch it makes is steered by untrusted input. MaxAuthorityHints,
// MaxFetches, MaxDuration and MaxDepth bound that work. Which hosts may be
// contacted is decided by HTTPClient's transport or by
// RequirePublicNetworkHost; by default any https host is fetched.
type Resolver struct {
	// HTTPClient fetches Entity Statements. It is copied, never mutated, to
	// refuse redirects. Nil means a client with DefaultHTTPTimeout.
	HTTPClient *http.Client
	// TrustAnchors are the Trust Anchors a chain must end at.
	TrustAnchors []TrustAnchor
	// Now is the validation time. Nil means time.Now.
	Now func() time.Time
	// MaxDepth bounds discovery. Zero means DefaultMaxDepth; any other value
	// below 2 is refused.
	MaxDepth int
	// MaxAuthorityHints bounds the authority hints followed per Entity. Zero
	// or less means DefaultMaxAuthorityHints.
	MaxAuthorityHints int
	// MaxFetches bounds the Entity Statements fetched per resolution. Zero or
	// less means DefaultMaxFetches.
	MaxFetches int
	// MaxDuration bounds the time one discovery may take, on top of any
	// deadline of the caller's context. Zero or less means
	// DefaultMaxDuration.
	MaxDuration time.Duration
	// MaxStatementBytes bounds one Entity Statement response. Zero or less
	// means DefaultMaxStatementBytes.
	MaxStatementBytes int64
	// RequirePublicNetworkHost refuses to fetch from a host IsPublicNetworkHost
	// does not accept, so a Trust Chain cannot steer the Wallet at an internal
	// address. It is off by default.
	RequirePublicNetworkHost bool
	// IsPublicNetworkHost decides whether a host name is on the public
	// network. Nil with RequirePublicNetworkHost set refuses every host.
	IsPublicNetworkHost func(host string) bool
}

func (r *Resolver) client() *http.Client {
	base := r.HTTPClient
	if base == nil {
		base = &http.Client{Timeout: DefaultHTTPTimeout}
	}
	return httpfetch.NoRedirect(base)
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Resolver) maxStatementBytes() int64 {
	if r.MaxStatementBytes > 0 {
		return r.MaxStatementBytes
	}
	return DefaultMaxStatementBytes
}

func positiveOr[T int | time.Duration](value, fallback T) T {
	if value > 0 {
		return value
	}
	return fallback
}

// ResolveTrustChains discovers every Trust Chain from subjectEntityID to a
// configured Trust Anchor (OpenID Federation 1.0 Section 10.1) and returns the
// valid ones, shortest first (Section 10.3). When none is valid the first
// validation failure is returned. Discovery stops when a bound of the Resolver
// is reached; chains found by then are still validated and returned.
func (r *Resolver) ResolveTrustChains(ctx context.Context, subjectEntityID string) ([]*TrustChain, error) {
	run, err := r.newResolution(ctx)
	if err != nil {
		return nil, err
	}
	defer run.cancel()
	paths, err := run.resolveTrustPaths(subjectEntityID, run.maxDepth, nil)
	if len(paths) == 0 {
		if run.stopped != nil {
			return nil, run.stopped
		}
		if err != nil {
			return nil, err
		}
		return nil, failure(ErrTrustChainUnresolved, "trust chain could not be resolved to a configured trust anchor")
	}

	var chains []*TrustChain
	var firstErr error
	for _, path := range paths {
		chain, err := ValidateTrustChain(path.chain, subjectEntityID, r.TrustAnchors, run.now)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		chains = append(chains, chain)
	}
	if len(chains) == 0 {
		return nil, firstErr
	}
	return chains, nil
}

// resolution is the state of one discovery run. It memoizes Entity
// Configurations and Subordinate Statements, including failed fetches, so an
// Entity reached through several authority hints is fetched once, and the
// paths found from an Entity, so they are enumerated once per remaining depth.
type resolution struct {
	resolver       *Resolver
	ctx            context.Context
	cancel         context.CancelFunc
	now            time.Time
	anchorIDs      map[string]struct{}
	maxDepth       int
	maxHints       int
	fetchesLeft    int
	stopped        error
	configurations map[string]configurationResult
	subordinates   map[string]statementResult
	paths          map[pathKey]pathsResult
}

type configurationResult struct {
	configuration *entityConfiguration
	err           error
}

type statementResult struct {
	statement string
	err       error
}

type pathKey struct {
	entityID  string
	remaining int
}

type pathsResult struct {
	paths []trustPath
	err   error
}

// trustPath is one discovered path from an Entity to a Trust Anchor: the
// Entity's configuration, the compact statements of the chain and the Entity
// Identifiers it passes through.
type trustPath struct {
	entityID      string
	configuration *entityConfiguration
	chain         []string
	entities      []string
}

func (r *Resolver) newResolution(ctx context.Context) (*resolution, error) {
	if len(r.TrustAnchors) == 0 {
		return nil, failure(ErrTrustAnchorNotConfigured, "trust anchors must be configured")
	}
	maxDepth := r.MaxDepth
	if maxDepth == 0 {
		maxDepth = DefaultMaxDepth
	}
	if maxDepth < 2 {
		return nil, failure(ErrTrustChainUnresolved, "trust chain maximum depth is invalid")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, positiveOr(r.MaxDuration, DefaultMaxDuration))
	anchorIDs := make(map[string]struct{}, len(r.TrustAnchors))
	for _, anchor := range r.TrustAnchors {
		anchorIDs[anchor.EntityID] = struct{}{}
	}
	return &resolution{
		resolver:       r,
		ctx:            ctx,
		cancel:         cancel,
		now:            r.now(),
		anchorIDs:      anchorIDs,
		maxDepth:       maxDepth,
		maxHints:       positiveOr(r.MaxAuthorityHints, DefaultMaxAuthorityHints),
		fetchesLeft:    positiveOr(r.MaxFetches, DefaultMaxFetches),
		configurations: map[string]configurationResult{},
		subordinates:   map[string]statementResult{},
		paths:          map[pathKey]pathsResult{},
	}, nil
}

func (run *resolution) isAnchor(entityID string) bool {
	_, ok := run.anchorIDs[entityID]
	return ok
}

// checkBudget reports whether discovery may continue. Once the fetch budget
// or the context is exhausted, discovery stops for good.
func (run *resolution) checkBudget() error {
	if run.stopped == nil {
		if err := run.ctx.Err(); err != nil {
			run.stopped = fmt.Errorf("%w: trust chain discovery stopped: %w", ErrTrustChainUnresolved, err)
		}
	}
	return run.stopped
}

// fetch spends one unit of the fetch budget on statementURL.
func (run *resolution) fetch(endpoint observe.Endpoint, statementURL string) (string, error) {
	if err := run.checkBudget(); err != nil {
		return "", err
	}
	if run.fetchesLeft <= 0 {
		run.stopped = failure(ErrTrustChainUnresolved, "trust chain discovery exceeded the fetch budget")
		return "", run.stopped
	}
	run.fetchesLeft--
	statement, err := run.resolver.fetchEntityStatement(observe.WithEndpoint(run.ctx, endpoint), statementURL)
	if err != nil {
		if stopErr := run.checkBudget(); stopErr != nil {
			return "", stopErr
		}
	}
	return statement, err
}

// resolveTrustPaths walks the authority hints of entityID up to configured
// Trust Anchors, with at most remaining Entities on the way including
// entityID. onPath holds the Entities already on the current path, so a loop
// of authority hints ends instead of recursing. A failure on one hint does not
// stop the others; it is returned only when no path was found.
//
// Results are memoized per Entity and remaining depth. A result computed while
// a loop was cut may lack paths through the cut Entity; that only removes
// candidates.
func (run *resolution) resolveTrustPaths(entityID string, remaining int, onPath []string) ([]trustPath, error) {
	if slices.Contains(onPath, entityID) {
		return nil, nil
	}
	if err := run.checkBudget(); err != nil {
		return nil, err
	}
	if remaining <= 0 {
		return nil, failure(ErrTrustChainUnresolved, "trust chain resolution exceeded maximum depth")
	}
	key := pathKey{entityID: entityID, remaining: remaining}
	if cached, ok := run.paths[key]; ok {
		return cached.paths, cached.err
	}
	paths, err := run.discoverTrustPaths(entityID, remaining, onPath)
	if run.stopped == nil {
		run.paths[key] = pathsResult{paths: paths, err: err}
	}
	return paths, err
}

func (run *resolution) discoverTrustPaths(entityID string, remaining int, onPath []string) ([]trustPath, error) {
	configuration, err := run.entityConfiguration(entityID)
	if err != nil {
		return nil, err
	}
	if run.isAnchor(entityID) {
		return []trustPath{{entityID: entityID, configuration: configuration, chain: []string{configuration.raw}, entities: []string{entityID}}}, nil
	}

	var paths []trustPath
	var firstErr error
	remember := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	nextOnPath := append(slices.Clone(onPath), entityID)
	hints := configuration.authorityHints
	if len(hints) > run.maxHints {
		hints = hints[:run.maxHints]
	}
	for _, authorityHint := range hints {
		if run.stopped != nil {
			break
		}
		superiorPaths, err := run.resolveTrustPaths(authorityHint, remaining-1, nextOnPath)
		if err != nil {
			remember(err)
			continue
		}
		for _, superior := range superiorPaths {
			if slices.Contains(superior.entities, entityID) {
				continue
			}
			statement, err := run.subordinateStatement(superior.configuration, entityID)
			if err != nil {
				remember(err)
				continue
			}
			tail := superior.chain
			if !run.isAnchor(superior.entityID) {
				tail = tail[1:]
			}
			paths = append(paths, trustPath{
				entityID:      entityID,
				configuration: configuration,
				chain:         append([]string{configuration.raw, statement}, tail...),
				entities:      append([]string{entityID}, superior.entities...),
			})
		}
	}
	if len(paths) == 0 {
		return nil, firstErr
	}
	slices.SortStableFunc(paths, func(left, right trustPath) int { return len(left.chain) - len(right.chain) })
	if len(paths) > maxPathsPerEntity {
		paths = paths[:maxPathsPerEntity]
	}
	return paths, nil
}

// entityConfiguration fetches and decodes the Entity Configuration of
// entityID once per resolution.
func (run *resolution) entityConfiguration(entityID string) (*entityConfiguration, error) {
	if cached, ok := run.configurations[entityID]; ok {
		return cached.configuration, cached.err
	}
	configuration, err := run.fetchEntityConfiguration(entityID)
	if run.stopped == nil {
		run.configurations[entityID] = configurationResult{configuration: configuration, err: err}
	}
	return configuration, err
}

func (run *resolution) fetchEntityConfiguration(entityID string) (*entityConfiguration, error) {
	statementURL, err := EntityConfigurationURL(entityID)
	if err != nil {
		return nil, err
	}
	raw, err := run.fetch(observe.EndpointFederationEntityConfiguration, statementURL)
	if err != nil {
		return nil, err
	}
	return decodeEntityConfiguration(raw, entityID)
}

// subordinateStatement fetches the Subordinate Statement superior issues about
// subjectEntityID from the superior's federation_fetch_endpoint, once per
// resolution.
func (run *resolution) subordinateStatement(superior *entityConfiguration, subjectEntityID string) (string, error) {
	endpoint, err := superior.federationFetchEndpoint()
	if err != nil {
		return "", err
	}
	statementURL, err := SubordinateStatementURL(endpoint, subjectEntityID)
	if err != nil {
		return "", err
	}
	if cached, ok := run.subordinates[statementURL]; ok {
		return cached.statement, cached.err
	}
	statement, err := run.fetch(observe.EndpointFederationSubordinateStatement, statementURL)
	if run.stopped == nil {
		run.subordinates[statementURL] = statementResult{statement: statement, err: err}
	}
	return statement, err
}

// entityConfiguration is the part of an Entity Configuration discovery reads
// before the chain is validated: its authority hints and its federation_entity
// metadata. None of it is trusted until the whole chain verifies.
type entityConfiguration struct {
	raw            string
	metadata       map[string]any
	authorityHints []string
}

func decodeEntityConfiguration(raw, expectedEntityID string) (*entityConfiguration, error) {
	payload, err := unverifiedJWTPayload(raw)
	if err != nil {
		return nil, failure(ErrTrustChainUnresolved, "entity configuration is not a JWT")
	}
	for _, name := range []string{"iss", "sub"} {
		if value, _ := payload[name].(string); value == "" {
			return nil, failure(ErrTrustChainUnresolved, "entity configuration %s claim is required", name)
		}
	}
	if payload["iss"] != expectedEntityID || payload["sub"] != expectedEntityID {
		return nil, failure(ErrTrustChainUnresolved, "entity configuration subject does not match entity identifier")
	}
	configuration := &entityConfiguration{raw: raw}
	if value, present := payload["metadata"]; present {
		metadata, ok := asObject(value)
		if !ok {
			return nil, failure(ErrTrustChainUnresolved, "entity configuration metadata claim must be an object")
		}
		configuration.metadata = metadata
	}
	if configuration.authorityHints, err = authorityHintsClaim(payload); err != nil {
		return nil, err
	}
	return configuration, nil
}

// authorityHintsClaim reads the authority_hints of an Entity Configuration
// (OpenID Federation 1.0 Section 3.1): Entity Identifiers whose configuration
// URL can be built.
func authorityHintsClaim(payload map[string]any) ([]string, error) {
	value, present := payload["authority_hints"]
	if !present {
		return nil, nil
	}
	hints, ok := asNonEmptyStringArray(value)
	if !ok {
		return nil, failure(ErrTrustChainUnresolved, "entity configuration authority_hints claim must be a string array")
	}
	for _, hint := range hints {
		if _, err := EntityConfigurationURL(hint); err != nil {
			return nil, failure(ErrTrustChainUnresolved, "entity configuration authority_hints value is invalid")
		}
	}
	return hints, nil
}

// federationFetchEndpoint reads the federation_fetch_endpoint a superior
// publishes in its federation_entity metadata (OpenID Federation 1.0 Section
// 5.1.1).
func (c *entityConfiguration) federationFetchEndpoint() (string, error) {
	entity, ok := asObject(c.metadata[federationEntityType])
	if !ok {
		return "", failure(ErrTrustChainUnresolved, "superior entity configuration must include federation_entity metadata")
	}
	endpoint, _ := entity["federation_fetch_endpoint"].(string)
	if endpoint == "" {
		return "", failure(ErrTrustChainUnresolved, "superior entity configuration must include federation_fetch_endpoint")
	}
	return endpoint, nil
}
