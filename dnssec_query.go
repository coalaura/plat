package main

import (
	"fmt"
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

	matched.mx.Lock()
	s.mx.RUnlock()

	config := matched.dnssec
	if config != nil && config.Enabled && config.Provider == "cloudflare" {
		matched.mx.Unlock()

		message, err := exchangeCloudflareDNS(request, config.Nameservers)

		return message, true, err
	}

	if config != nil && config.Enabled {
		now := time.Now()
		if matched.signed == nil || !now.Before(matched.signed.RenewAt) {
			serial := matched.serial
			if serial == 0 || matched.signed != nil {
				serial = matched.nextSerial()
			}

			snapshot, err := buildSignedZone(matched.Name, matched.Records, config, serial, now)
			if err != nil {
				matched.mx.Unlock()

				return nil, true, err
			}

			matched.serial = snapshot.Nodes[snapshot.Name].Sets[dns.TypeSOA].Records[0].(*dns.SOA).Serial
			matched.signed = snapshot
		}

		snapshot := matched.signed
		matched.mx.Unlock()

		return snapshot.answer(request), true, nil
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
