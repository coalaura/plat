package dnsserver

import (
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/miekg/dns"
)

type localHost struct {
	name      string
	addresses map[netip.Addr]struct{}
}

func (host *localHost) answer(request, response *dns.Msg, peer netip.Addr) bool {
	question := request.Question[0]
	if host.name == "" || !strings.EqualFold(strings.TrimSuffix(question.Name, "."), host.name) {
		return false
	}

	if !host.isLocal(peer) {
		return false
	}

	option := request.IsEdns0()
	if option != nil {
		response.SetEdns0(1232, option.Do())
	}

	count := 1

	switch question.Qtype {
	case dns.TypeA, dns.TypeAAAA:
	case dns.TypeANY:
		count = 2
	default:
		return true
	}

	response.Answer = make([]dns.RR, 0, count)

	// These answers depend on the caller and must not be cached for other clients.
	header := dns.RR_Header{
		Name:  question.Name,
		Class: dns.ClassINET,
		Ttl:   0,
	}

	if question.Qtype == dns.TypeA || question.Qtype == dns.TypeANY {
		header.Rrtype = dns.TypeA

		response.Answer = append(response.Answer, &dns.A{
			Hdr: header,
			A:   net.IP{127, 0, 0, 1},
		})
	}

	if question.Qtype == dns.TypeAAAA || question.Qtype == dns.TypeANY {
		header.Rrtype = dns.TypeAAAA

		response.Answer = append(response.Answer, &dns.AAAA{
			Hdr:  header,
			AAAA: net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		})
	}

	return true
}

func (host *localHost) isLocal(peer netip.Addr) bool {
	peer = peer.Unmap().WithZone("")
	if !peer.IsValid() {
		return false
	}

	if peer.IsLoopback() {
		return true
	}

	_, exists := host.addresses[peer]
	return exists
}

func newLocalHost() localHost {
	name, err := os.Hostname()
	if err != nil {
		log.Warnf("Local hostname resolution unavailable: %v", err)

		return localHost{}
	}

	host := localHost{name: strings.TrimSuffix(name, ".")}

	addresses, err := net.InterfaceAddrs()
	if err != nil {
		log.Warnf("Local hostname resolution limited to loopback clients: %v", err)

		return host
	}

	host.addresses = make(map[netip.Addr]struct{}, len(addresses))

	for _, address := range addresses {
		network, ok := address.(*net.IPNet)
		if !ok {
			continue
		}

		peer, valid := netip.AddrFromSlice(network.IP)
		if !valid || peer.IsUnspecified() || peer.IsMulticast() {
			continue
		}

		host.addresses[peer.Unmap()] = struct{}{}
	}

	return host
}
