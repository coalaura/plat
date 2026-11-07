package dnsserver

import (
	"container/list"
	"time"

	"github.com/miekg/dns"
)

const (
	forwardCacheEntries = 10000
	forwardCacheBytes   = 32 << 20
	forwardFailureTTL   = time.Second
	forwardCacheSweep   = time.Minute
)

type forwardKey struct {
	name       string
	queryType  uint16
	queryClass uint16
	udpSize    uint16
	edns       bool
	dnssec     bool
	recursion  bool
	checking   bool
	authentic  bool
}

type forwardResult struct {
	data   []byte
	err    error
	stored time.Time
}

type forwardEntry struct {
	key     forwardKey
	result  forwardResult
	expires time.Time
}

// The owning forwardState holds its mutex for all cache operations. Wire data
// stays immutable; unpacking gives each caller its own records to age/truncate.
type forwardCache struct {
	entries   map[forwardKey]*list.Element
	order     list.List
	bytes     int
	nextSweep time.Time
}

func (cache *forwardCache) get(key forwardKey, now time.Time) (forwardResult, bool) {
	element := cache.entries[key]
	if element == nil {
		return forwardResult{}, false
	}

	entry := element.Value.(*forwardEntry)
	if !now.Before(entry.expires) {
		cache.remove(element)

		return forwardResult{}, false
	}

	cache.order.MoveToFront(element)

	return entry.result, true
}

func (cache *forwardCache) put(key forwardKey, result forwardResult, lifetime time.Duration) {
	if lifetime <= 0 || len(result.data) > forwardCacheBytes {
		return
	}

	if cache.entries == nil {
		cache.entries = make(map[forwardKey]*list.Element, forwardCacheEntries)
	}

	if !result.stored.Before(cache.nextSweep) {
		for element := cache.order.Back(); element != nil; {
			previous := element.Prev()

			entry := element.Value.(*forwardEntry)
			if !result.stored.Before(entry.expires) {
				cache.remove(element)
			}

			element = previous
		}

		cache.nextSweep = result.stored.Add(forwardCacheSweep)
	}

	element := cache.entries[key]
	if element != nil {
		cache.remove(element)
	}

	for cache.order.Len() >= forwardCacheEntries || cache.bytes+len(result.data) > forwardCacheBytes {
		cache.remove(cache.order.Back())
	}

	entry := &forwardEntry{
		key:     key,
		result:  result,
		expires: result.stored.Add(lifetime),
	}

	cache.entries[key] = cache.order.PushFront(entry)
	cache.bytes += len(result.data)
}

func (cache *forwardCache) remove(element *list.Element) {
	entry := element.Value.(*forwardEntry)
	delete(cache.entries, entry.key)

	cache.bytes -= len(entry.result.data)
	cache.order.Remove(element)
}

func (result forwardResult) response(request *dns.Msg, now time.Time) (*dns.Msg, error) {
	if result.err != nil {
		return nil, result.err
	}

	response := new(dns.Msg)

	err := response.Unpack(result.data)
	if err != nil {
		return nil, err
	}

	response.Id = request.Id
	response.Question[0] = request.Question[0]
	response.Compress = true

	seconds := uint32(max(0, now.Sub(result.stored)/time.Second))
	ageRecords(response.Answer, seconds)
	ageRecords(response.Ns, seconds)
	ageRecords(response.Extra, seconds)

	return response, nil
}

func queryForwardKey(request *dns.Msg) (forwardKey, bool) {
	if len(request.Question) != 1 || request.Opcode != dns.OpcodeQuery || request.Response || request.Authoritative || request.Truncated || request.RecursionAvailable || request.Zero || request.Rcode != 0 || len(request.Answer) != 0 || len(request.Ns) != 0 {
		return forwardKey{}, false
	}

	question := request.Question[0]

	key := forwardKey{
		name:       dns.CanonicalName(question.Name),
		queryType:  question.Qtype,
		queryClass: question.Qclass,
		recursion:  request.RecursionDesired,
		checking:   request.CheckingDisabled,
		authentic:  request.AuthenticatedData,
	}

	if len(request.Extra) != 0 {
		if len(request.Extra) != 1 {
			return forwardKey{}, false
		}

		option, ok := request.Extra[0].(*dns.OPT)
		if !ok || option.Hdr.Name != "." || option.Version() != 0 || option.ExtendedRcode() != 0 || option.Z() != 0 || len(option.Option) != 0 {
			return forwardKey{}, false
		}

		key.edns = true
		key.dnssec = option.Do()
		key.udpSize = option.UDPSize()
	}

	// Transfers and signed/client-specific EDNS requests must never be shared.
	return key, question.Qtype != dns.TypeAXFR && question.Qtype != dns.TypeIXFR
}

func responseCacheLifetime(response *dns.Msg) time.Duration {
	if response.Truncated {
		return 0
	}

	if response.IsTsig() != nil {
		return 0
	}

	if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
		return forwardFailureTTL
	}

	option := response.IsEdns0()
	if option != nil && (option.Version() != 0 || len(option.Option) != 0) {
		return 0
	}

	ttl := uint32(1<<31 - 1)
	ttl = minimumRecordTTL(response.Answer, ttl)
	ttl = minimumRecordTTL(response.Ns, ttl)
	ttl = minimumRecordTTL(response.Extra, ttl)

	question := response.Question[0]

	terminal, answered := answerTerminal(response, question)
	if terminal == "" {
		return 0
	}

	if response.Rcode == dns.RcodeNameError || !answered {
		negative := false

		for _, record := range response.Ns {
			soa, ok := record.(*dns.SOA)
			if !ok || soa.Hdr.Class != question.Qclass || !dns.IsSubDomain(soa.Hdr.Name, terminal) {
				continue
			}

			negative = true
			soa.Hdr.Ttl = min(soa.Hdr.Ttl, soa.Minttl)
			ttl = min(ttl, soa.Hdr.Ttl)
		}

		if !negative {
			return 0
		}
	}

	return time.Duration(ttl) * time.Second
}

func answerTerminal(response *dns.Msg, question dns.Question) (string, bool) {
	name := question.Name

	for range len(response.Answer) + 1 {
		next := name

		for _, record := range response.Answer {
			header := record.Header()
			if header.Class != question.Qclass || !sameDNSName(header.Name, name) {
				continue
			}

			if header.Rrtype == question.Qtype || question.Qtype == dns.TypeANY {
				return name, true
			}

			if alias, ok := record.(*dns.CNAME); ok {
				next = alias.Target
			}
		}

		if sameDNSName(next, name) {
			return name, false
		}

		name = next
	}

	return "", false
}

func minimumRecordTTL(records []dns.RR, ttl uint32) uint32 {
	for _, record := range records {
		header := record.Header()
		if header.Rrtype == dns.TypeOPT {
			continue
		}

		// RFC 2181 treats TTLs with the high bit set as zero.
		if header.Ttl > 1<<31-1 {
			return 0
		}

		ttl = min(ttl, header.Ttl)
	}

	return ttl
}

func ageRecords(records []dns.RR, seconds uint32) {
	for _, record := range records {
		header := record.Header()
		if header.Rrtype != dns.TypeOPT {
			header.Ttl -= min(header.Ttl, seconds)
		}
	}
}

func sameDNSName(left, right string) bool {
	return dns.CanonicalName(left) == dns.CanonicalName(right)
}
