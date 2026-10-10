package dnssec

import (
	"crypto"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	DNSSECTTL      = 3600
	DNSSECLifetime = 14 * 24 * time.Hour
	DNSSECRenewal  = 24 * time.Hour
)

type Config struct {
	Nameservers []string
	Key         *dns.DNSKEY
	Signer      crypto.Signer
}

func CanonicalQueryName(name string) string {
	return canonicalQueryName(name)
}

func canonicalQueryName(name string) string {
	name = strings.ToLower(dns.Fqdn(name))
	if !strings.ContainsRune(name, '\\') {
		return name
	}

	var wire [256]byte

	_, err := dns.PackDomainName(name, wire[:], 0, nil, false)
	if err != nil {
		return name
	}

	for index, character := range wire {
		wire[index] = lowerDNSByte(character)
	}

	normalized, _, err := dns.UnpackDomainName(wire[:], 0)
	if err != nil {
		return name
	}

	return normalized
}
