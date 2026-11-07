package dnsserver

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type forwardCall struct {
	done    chan struct{}
	cancel  context.CancelFunc
	waiters int
	result  forwardResult
}

type forwardState struct {
	mutex  sync.Mutex
	cache  forwardCache
	calls  map[forwardKey]*forwardCall
	closed bool
}

func (state *forwardState) close() {
	state.mutex.Lock()
	defer state.mutex.Unlock()

	state.closed = true

	for _, call := range state.calls {
		call.cancel()
	}
}

func (s *DNSServer) forwardQuery(ctx context.Context, request *dns.Msg) (*dns.Msg, error) {
	err := ctx.Err()
	if err != nil {
		return nil, err
	}

	key, shareable := queryForwardKey(request)
	if !shareable {
		return s.exchangeForward(ctx, request)
	}

	state := &s.forward

	state.mutex.Lock()

	if state.closed {
		state.mutex.Unlock()

		return nil, context.Canceled
	}

	now := time.Now()

	result, cached := state.cache.get(key, now)
	if cached {
		state.mutex.Unlock()

		return result.response(request, now)
	}

	call := state.calls[key]
	if call == nil {
		if state.calls == nil {
			state.calls = make(map[forwardKey]*forwardCall)
		}

		// One caller's deadline must not terminate work needed by other callers.
		// The shared budget is fixed; cancel early when the last waiter leaves.
		shared, cancel := context.WithTimeout(context.WithoutCancel(ctx), dohTimeout)
		call = &forwardCall{
			done:   make(chan struct{}),
			cancel: cancel,
		}

		state.calls[key] = call
		go s.runForward(shared, key, request.Copy(), call)
	}

	call.waiters++
	state.mutex.Unlock()

	select {
	case <-call.done:
		return call.result.response(request, time.Now())
	case <-ctx.Done():
		state.mutex.Lock()
		call.waiters--

		if call.waiters == 0 && state.calls[key] == call {
			delete(state.calls, key)
			call.cancel()
		}

		state.mutex.Unlock()

		return nil, ctx.Err()
	}
}

func (s *DNSServer) runForward(ctx context.Context, key forwardKey, request *dns.Msg, call *forwardCall) {
	defer call.cancel()

	response, err := s.exchangeForward(ctx, request)
	result := forwardResult{err: err}
	lifetime := forwardFailureTTL

	if err == nil {
		lifetime = responseCacheLifetime(response)
		response.Compress = true

		result.data, result.err = response.Pack()
		if result.err != nil {
			lifetime = forwardFailureTTL
		}
	}

	result.stored = time.Now()

	state := &s.forward

	state.mutex.Lock()
	defer state.mutex.Unlock()

	call.result = result

	if state.calls[key] == call {
		delete(state.calls, key)

		if !state.closed {
			state.cache.put(key, result, lifetime)
		}
	}

	close(call.done)
}

func (s *DNSServer) exchangeForward(ctx context.Context, request *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, dohTimeout)
	defer cancel()

	var (
		response *dns.Msg
		err      error
	)

	if s.fallbackHTTPS != "" {
		response, err = s.ExchangeDoH(ctx, request)
	} else {
		response, _, err = s.dnsClient.ExchangeContext(ctx, request, s.fallbackIP)
	}

	if err == nil && !validForwardResponse(request, response) {
		err = errors.New("upstream returned a mismatched DNS response")
	}

	if err != nil {
		if !errors.Is(err, context.Canceled) {
			log.Warnf("DNS fallback resolver error: %v\n", err)
		}

		return nil, err
	}

	response.Id = request.Id

	return response, nil
}

func validForwardResponse(request, response *dns.Msg) bool {
	if response == nil || !response.Response || response.Opcode != request.Opcode || len(response.Question) != 1 {
		return false
	}

	question := request.Question[0]
	answer := response.Question[0]

	return question.Qtype == answer.Qtype && question.Qclass == answer.Qclass && sameDNSName(question.Name, answer.Name)
}
