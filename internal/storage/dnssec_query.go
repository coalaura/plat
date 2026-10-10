package storage

import (
	"fmt"
	"plat/internal/dnssec"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func (s *Storage) LookupDNS(request *dns.Msg) (*dns.Msg, bool, error) {
	question := request.Question[0]

	name := strings.TrimSuffix(canonicalQueryName(question.Name), ".")

	s.mx.RLock()

	var matched *Zone

	for _, zone := range s.zones {
		if !zone.MatchesName(name) || (question.Qtype == dns.TypeDS && name == zone.Name) {
			continue
		}

		if matched == nil || len(zone.Name) > len(matched.Name) {
			matched = zone
		}
	}

	if matched == nil {
		s.mx.RUnlock()

		return nil, false, nil
	}

	s.mx.RUnlock()

	matched.mx.Lock()

	config := matched.dnssec
	if config != nil && config.Enabled && config.Provider == "cloudflare" {
		matched.mx.Unlock()

		message, err := exchangeCloudflareDNS(request, config.Nameservers)

		return message, true, err
	}

	if config != nil && config.Enabled {
		now := time.Now()
		if matched.signed == nil || !now.Before(matched.signed.RenewAt) {
			snapshot, err := buildSignedZone(matched.Name, matched.Records, config, matched.serial, now)
			if err != nil {
				matched.mx.Unlock()

				return nil, true, err
			}

			matched.signed = snapshot
		}

		snapshot := matched.signed
		matched.mx.Unlock()

		return snapshot.Answer(request), true, nil
	}

	message := new(dns.Msg)

	message.SetReply(request)
	message.Authoritative = true
	message.Compress = true

	exists := name == matched.Name

	for _, record := range matched.Records {
		if record.MatchesName(name) {
			exists = true

			if record.GetRR() != nil && (record.GetRR().Header().Rrtype == question.Qtype || question.Qtype == dns.TypeANY) {
				message.Answer = append(message.Answer, dns.Copy(record.GetRR()))
			}
		}
	}

	matched.mx.Unlock()

	if !exists {
		message.Rcode = dns.RcodeNameError
	}

	return message, true, nil
}

func exchangeCloudflareDNS(request *dns.Msg, nameservers []string) (*dns.Msg, error) {
	client := dns.Client{
		Timeout: 3 * time.Second,
	}

	query := request.Copy()

	query.RecursionDesired = false
	query.AuthenticatedData = false

	var lastError error

	for _, nameserver := range nameservers {
		address := strings.TrimSuffix(nameserver, ".") + ":53"

		message, _, err := client.Exchange(query, address)
		if err == nil && message.Truncated {
			client.Net = "tcp"
			message, _, err = client.Exchange(query, address)
			client.Net = ""
		}

		if err != nil {
			lastError = err

			continue
		}

		if message.Rcode == dns.RcodeServerFailure || message.Rcode == dns.RcodeRefused {
			lastError = fmt.Errorf("cloudflare nameserver returned %s", dns.RcodeToString[message.Rcode])

			continue
		}

		message.AuthenticatedData = false

		return message, nil
	}

	return nil, fmt.Errorf("cloudflare authoritative DNS unavailable: %v", lastError)
}

func canonicalQueryName(name string) string {
	return dnssec.CanonicalQueryName(name)
}
