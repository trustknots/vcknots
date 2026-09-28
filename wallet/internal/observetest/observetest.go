// Package observetest records observe.Exchange values for tests.
package observetest

import (
	"sync"

	"github.com/trustknots/vcknots/wallet/common/observe"
)

// Recorder is an observe.Observer that keeps every exchange. It is safe for
// concurrent use.
type Recorder struct {
	mu        sync.Mutex
	exchanges []observe.Exchange
}

// ObserveExchange keeps exchange.
func (r *Recorder) ObserveExchange(exchange observe.Exchange) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.exchanges = append(r.exchanges, exchange)
}

// Exchanges returns the kept exchanges in the order they completed.
func (r *Recorder) Exchanges() []observe.Exchange {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]observe.Exchange(nil), r.exchanges...)
}

// Endpoints returns the label of every kept exchange, in order.
func (r *Recorder) Endpoints() []observe.Endpoint {
	endpoints := []observe.Endpoint{}
	for _, exchange := range r.Exchanges() {
		endpoints = append(endpoints, exchange.Endpoint)
	}
	return endpoints
}
