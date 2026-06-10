package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/dns"
	mdns "github.com/miekg/dns"
)

// A, AAAA, CAA, CERT, CNAME, DNSKEY, DS, HTTPS, LOC, MX, NAPTR, NS, OPENPGPKEY, PTR, SMIMEA, SRV, SSHFP, SVCB, TLSA, TXT, URI

type Record struct {
	ID      string `yaml:"id" json:"id"`
	Type    string `yaml:"type" json:"type"`
	Name    string `yaml:"name" json:"name"`
	Content string `yaml:"content" json:"content"`
	TTL     int64  `yaml:"ttl,omitempty" json:"ttl,omitempty"`

	full string
	rr   mdns.RR
}

func (r Record) GetFullName() string {
	return r.full
}

func (r Record) GetRR() mdns.RR {
	return r.rr
}

func (r Record) MatchesName(query string) bool {
	return r.full == query
}

func (r Record) MatchesType(typ string) bool {
	return r.Type == typ
}

func (r *Record) Update(zoneName string) error {
	if r.Name == "@" {
		r.full = zoneName
	} else {
		r.full = r.Name + "." + zoneName
	}

	rr, err := mdns.NewRR(fmt.Sprintf("%s %d IN %s %s", r.full, r.TTL, r.Type, r.Content))
	if err != nil {
		return err
	}

	r.rr = rr

	return nil
}

func (r Record) Equals(r2 Record) bool {
	if r.Name != r2.Name || r.Type != r2.Type {
		return false
	} else if r.TTL != r2.TTL {
		return false
	}

	return r.Content == r2.Content
}

func (r Record) ToCloudflareNew() (dns.RecordNewParamsBodyUnion, error) {
	// OPENPGPKEY is missing a regular RecordParam
	if strings.EqualFold(r.Type, "OPENPGPKEY") {
		return dns.RecordNewParamsBody{
			Name:    cloudflare.F(r.Name),
			TTL:     cloudflare.F(dns.TTL(r.TTL)),
			Type:    cloudflare.F(dns.RecordNewParamsBodyTypeOpenpgpkey),
			Content: cloudflare.F(r.Content),
		}, nil
	}

	param, err := r.ToCloudflare()
	if err != nil {
		return nil, err
	}

	return param.(dns.RecordNewParamsBodyUnion), nil
}

func (r Record) ToCloudflareEdit() (dns.RecordEditParamsBodyUnion, error) {
	// OPENPGPKEY is missing a regular RecordParam
	if strings.EqualFold(r.Type, "OPENPGPKEY") {
		return dns.RecordEditParamsBody{
			Name:    cloudflare.F(r.Name),
			TTL:     cloudflare.F(dns.TTL(r.TTL)),
			Type:    cloudflare.F(dns.RecordEditParamsBodyTypeOpenpgpkey),
			Content: cloudflare.F(r.Content),
		}, nil
	}

	param, err := r.ToCloudflare()
	if err != nil {
		return nil, err
	}

	return param.(dns.RecordEditParamsBodyUnion), nil
}

func (r Record) ToCloudflare() (any, error) {
	fields := parseFields(r.Content)

	switch strings.ToUpper(r.Type) {
	case "A":
		return dns.ARecordParam{
			Name:    cloudflare.F(r.Name),
			TTL:     cloudflare.F(dns.TTL(r.TTL)),
			Type:    cloudflare.F(dns.ARecordTypeA),
			Content: cloudflare.F(r.Content),
		}, nil
	case "AAAA":
		return dns.AAAARecordParam{
			Name:    cloudflare.F(r.Name),
			TTL:     cloudflare.F(dns.TTL(r.TTL)),
			Type:    cloudflare.F(dns.AAAARecordTypeAAAA),
			Content: cloudflare.F(r.Content),
		}, nil
	case "CNAME":
		return dns.CNAMERecordParam{
			Name:    cloudflare.F(r.Name),
			TTL:     cloudflare.F(dns.TTL(r.TTL)),
			Type:    cloudflare.F(dns.CNAMERecordTypeCNAME),
			Content: cloudflare.F(r.Content),
		}, nil
	case "MX":
		if len(fields) < 2 {
			return nil, fmt.Errorf("invalid MX record value: %q (expected <priority> <mail-server>)", r.Content)
		}

		prio, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid MX priority %q: %w", fields[0], err)
		}

		return dns.MXRecordParam{
			Name:     cloudflare.F(r.Name),
			TTL:      cloudflare.F(dns.TTL(r.TTL)),
			Type:     cloudflare.F(dns.MXRecordTypeMX),
			Priority: cloudflare.F(prio),
			Content:  cloudflare.F(fields[1]),
		}, nil
	case "NS":
		return dns.NSRecordParam{
			Name:    cloudflare.F(r.Name),
			TTL:     cloudflare.F(dns.TTL(r.TTL)),
			Type:    cloudflare.F(dns.NSRecordTypeNS),
			Content: cloudflare.F(r.Content),
		}, nil
	case "PTR":
		return dns.PTRRecordParam{
			Name:    cloudflare.F(r.Name),
			TTL:     cloudflare.F(dns.TTL(r.TTL)),
			Type:    cloudflare.F(dns.PTRRecordTypePTR),
			Content: cloudflare.F(r.Content),
		}, nil
	case "TXT":
		text := formatTXT(r.Content)

		return dns.TXTRecordParam{
			Name:    cloudflare.F(r.Name),
			TTL:     cloudflare.F(dns.TTL(r.TTL)),
			Type:    cloudflare.F(dns.TXTRecordTypeTXT),
			Content: cloudflare.F(text),
		}, nil
	case "CAA":
		if len(fields) < 3 {
			return nil, fmt.Errorf("invalid CAA record value: %q (expected <flags> <tag> <value>)", r.Content)
		}

		flags, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid CAA flags %q: %w", fields[0], err)
		}

		return dns.CAARecordParam{
			Name: cloudflare.F(r.Name),
			TTL:  cloudflare.F(dns.TTL(r.TTL)),
			Type: cloudflare.F(dns.CAARecordTypeCAA),
			Data: cloudflare.F(dns.CAARecordDataParam{
				Flags: cloudflare.F(flags),
				Tag:   cloudflare.F(fields[1]),
				Value: cloudflare.F(fields[2]),
			}),
		}, nil
	case "CERT":
		if len(fields) < 4 {
			return nil, fmt.Errorf("invalid CERT record value: %q (expected <type> <key_tag> <algorithm> <certificate>)", r.Content)
		}

		certType, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid CERT type %q: %w", fields[0], err)
		}

		keyTag, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid CERT key_tag %q: %w", fields[1], err)
		}

		algo, err := strconv.ParseFloat(fields[2], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid CERT algorithm %q: %w", fields[2], err)
		}

		return dns.CERTRecordParam{
			Name: cloudflare.F(r.Name),
			TTL:  cloudflare.F(dns.TTL(r.TTL)),
			Type: cloudflare.F(dns.CERTRecordTypeCERT),
			Data: cloudflare.F(dns.CERTRecordDataParam{
				Type:        cloudflare.F(certType),
				KeyTag:      cloudflare.F(keyTag),
				Algorithm:   cloudflare.F(algo),
				Certificate: cloudflare.F(fields[3]),
			}),
		}, nil
	case "DNSKEY":
		if len(fields) < 4 {
			return nil, fmt.Errorf("invalid DNSKEY record value: %q (expected <flags> <protocol> <algorithm> <public_key>)", r.Content)
		}

		flags, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid DNSKEY flags %q: %w", fields[0], err)
		}

		proto, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid DNSKEY protocol %q: %w", fields[1], err)
		}

		algo, err := strconv.ParseFloat(fields[2], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid DNSKEY algorithm %q: %w", fields[2], err)
		}

		return dns.DNSKEYRecordParam{
			Name: cloudflare.F(r.Name),
			TTL:  cloudflare.F(dns.TTL(r.TTL)),
			Type: cloudflare.F(dns.DNSKEYRecordTypeDNSKEY),
			Data: cloudflare.F(dns.DNSKEYRecordDataParam{
				Flags:     cloudflare.F(flags),
				Protocol:  cloudflare.F(proto),
				Algorithm: cloudflare.F(algo),
				PublicKey: cloudflare.F(fields[3]),
			}),
		}, nil
	case "DS":
		if len(fields) < 4 {
			return nil, fmt.Errorf("invalid DS record value: %q (expected <key_tag> <algorithm> <digest_type> <digest>)", r.Content)
		}

		keyTag, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid DS key_tag %q: %w", fields[0], err)
		}

		algo, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid DS algorithm %q: %w", fields[1], err)
		}

		digestType, err := strconv.ParseFloat(fields[2], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid DS digest_type %q: %w", fields[2], err)
		}

		return dns.DSRecordParam{
			Name: cloudflare.F(r.Name),
			TTL:  cloudflare.F(dns.TTL(r.TTL)),
			Type: cloudflare.F(dns.DSRecordTypeDS),
			Data: cloudflare.F(dns.DSRecordDataParam{
				KeyTag:     cloudflare.F(keyTag),
				Algorithm:  cloudflare.F(algo),
				DigestType: cloudflare.F(digestType),
				Digest:     cloudflare.F(fields[3]),
			}),
		}, nil
	case "HTTPS":
		if len(fields) < 2 {
			return nil, fmt.Errorf("invalid HTTPS record value: %q (expected <priority> <target> [value])", r.Content)
		}

		prio, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid HTTPS priority %q: %w", fields[0], err)
		}

		var val string

		if len(fields) > 2 {
			val = strings.Join(fields[2:], " ")
		}

		return dns.HTTPSRecordParam{
			Name: cloudflare.F(r.Name),
			TTL:  cloudflare.F(dns.TTL(r.TTL)),
			Type: cloudflare.F(dns.HTTPSRecordTypeHTTPS),
			Data: cloudflare.F(dns.HTTPSRecordDataParam{
				Priority: cloudflare.F(prio),
				Target:   cloudflare.F(fields[1]),
				Value:    cloudflare.F(val),
			}),
		}, nil
	case "LOC":
		data, err := parseLOC(r.Content)
		if err != nil {
			return nil, err
		}

		return dns.LOCRecordParam{
			Name: cloudflare.F(r.Name),
			TTL:  cloudflare.F(dns.TTL(r.TTL)),
			Type: cloudflare.F(dns.LOCRecordTypeLOC),
			Data: cloudflare.F(data),
		}, nil
	case "NAPTR":
		if len(fields) < 6 {
			return nil, fmt.Errorf("invalid NAPTR record value: %q (expected <order> <preference> <flags> <service> <regex> <replacement>)", r.Content)
		}

		order, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid NAPTR order %q: %w", fields[0], err)
		}

		pref, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid NAPTR preference %q: %w", fields[1], err)
		}

		return dns.NAPTRRecordParam{
			Name: cloudflare.F(r.Name),
			TTL:  cloudflare.F(dns.TTL(r.TTL)),
			Type: cloudflare.F(dns.NAPTRRecordTypeNAPTR),
			Data: cloudflare.F(dns.NAPTRRecordDataParam{
				Order:       cloudflare.F(order),
				Preference:  cloudflare.F(pref),
				Flags:       cloudflare.F(fields[2]),
				Service:     cloudflare.F(fields[3]),
				Regex:       cloudflare.F(fields[4]),
				Replacement: cloudflare.F(fields[5]),
			}),
		}, nil
	case "SMIMEA":
		if len(fields) < 4 {
			return nil, fmt.Errorf("invalid SMIMEA record value: %q (expected <usage> <selector> <matching_type> <certificate>)", r.Content)
		}

		usage, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid SMIMEA usage %q: %w", fields[0], err)
		}

		selector, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid SMIMEA selector %q: %w", fields[1], err)
		}

		matchType, err := strconv.ParseFloat(fields[2], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid SMIMEA matching_type %q: %w", fields[2], err)
		}

		return dns.SMIMEARecordParam{
			Name: cloudflare.F(r.Name),
			TTL:  cloudflare.F(dns.TTL(r.TTL)),
			Type: cloudflare.F(dns.SMIMEARecordTypeSMIMEA),
			Data: cloudflare.F(dns.SMIMEARecordDataParam{
				Usage:        cloudflare.F(usage),
				Selector:     cloudflare.F(selector),
				MatchingType: cloudflare.F(matchType),
				Certificate:  cloudflare.F(fields[3]),
			}),
		}, nil
	case "SRV":
		if len(fields) < 4 {
			return nil, fmt.Errorf("invalid SRV record value: %q (expected <priority> <weight> <port> <target>)", r.Content)
		}

		priority, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid SRV priority %q: %w", fields[0], err)
		}

		weight, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid SRV weight %q: %w", fields[1], err)
		}

		port, err := strconv.ParseFloat(fields[2], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid SRV port %q: %w", fields[2], err)
		}

		return dns.SRVRecordParam{
			Name: cloudflare.F(r.Name),
			TTL:  cloudflare.F(dns.TTL(r.TTL)),
			Type: cloudflare.F(dns.SRVRecordTypeSRV),
			Data: cloudflare.F(dns.SRVRecordDataParam{
				Priority: cloudflare.F(priority),
				Weight:   cloudflare.F(weight),
				Port:     cloudflare.F(port),
				Target:   cloudflare.F(fields[3]),
			}),
		}, nil
	case "SSHFP":
		if len(fields) < 3 {
			return nil, fmt.Errorf("invalid SSHFP record value: %q (expected <algorithm> <type> <fingerprint>)", r.Content)
		}

		algo, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid SSHFP algorithm %q: %w", fields[0], err)
		}

		fpType, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid SSHFP type %q: %w", fields[1], err)
		}

		return dns.SSHFPRecordParam{
			Name: cloudflare.F(r.Name),
			TTL:  cloudflare.F(dns.TTL(r.TTL)),
			Type: cloudflare.F(dns.SSHFPRecordTypeSSHFP),
			Data: cloudflare.F(dns.SSHFPRecordDataParam{
				Algorithm:   cloudflare.F(algo),
				Type:        cloudflare.F(fpType),
				Fingerprint: cloudflare.F(fields[2]),
			}),
		}, nil
	case "SVCB":
		if len(fields) < 2 {
			return nil, fmt.Errorf("invalid SVCB record value: %q (expected <priority> <target> [value])", r.Content)
		}

		prio, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid SVCB priority %q: %w", fields[0], err)
		}

		var val string

		if len(fields) > 2 {
			val = strings.Join(fields[2:], " ")
		}

		return dns.SVCBRecordParam{
			Name: cloudflare.F(r.Name),
			TTL:  cloudflare.F(dns.TTL(r.TTL)),
			Type: cloudflare.F(dns.SVCBRecordTypeSVCB),
			Data: cloudflare.F(dns.SVCBRecordDataParam{
				Priority: cloudflare.F(prio),
				Target:   cloudflare.F(fields[1]),
				Value:    cloudflare.F(val),
			}),
		}, nil
	case "TLSA":
		if len(fields) < 4 {
			return nil, fmt.Errorf("invalid TLSA record value: %q (expected <usage> <selector> <matching_type> <certificate>)", r.Content)
		}

		usage, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid TLSA usage %q: %w", fields[0], err)
		}

		selector, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid TLSA selector %q: %w", fields[1], err)
		}

		matchType, err := strconv.ParseFloat(fields[2], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid TLSA matching_type %q: %w", fields[2], err)
		}

		return dns.TLSARecordParam{
			Name: cloudflare.F(r.Name),
			TTL:  cloudflare.F(dns.TTL(r.TTL)),
			Type: cloudflare.F(dns.TLSARecordTypeTLSA),
			Data: cloudflare.F(dns.TLSARecordDataParam{
				Usage:        cloudflare.F(usage),
				Selector:     cloudflare.F(selector),
				MatchingType: cloudflare.F(matchType),
				Certificate:  cloudflare.F(fields[3]),
			}),
		}, nil
	case "URI":
		if len(fields) < 3 {
			return nil, fmt.Errorf("invalid URI record value: %q (expected <priority> <weight> <target>)", r.Content)
		}

		prio, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid URI priority %q: %w", fields[0], err)
		}

		weight, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid URI weight %q: %w", fields[1], err)
		}

		return dns.URIRecordParam{
			Name:     cloudflare.F(r.Name),
			TTL:      cloudflare.F(dns.TTL(r.TTL)),
			Type:     cloudflare.F(dns.URIRecordTypeURI),
			Priority: cloudflare.F(prio),
			Data: cloudflare.F(dns.URIRecordDataParam{
				Weight: cloudflare.F(weight),
				Target: cloudflare.F(fields[2]),
			}),
		}, nil
	}

	return nil, fmt.Errorf("unsupported record type: %q", r.Type)
}

func FormatRecordResponse(resp dns.RecordResponse) (string, error) {
	switch u := resp.AsUnion().(type) {
	case dns.RecordResponseA:
		return u.Content, nil
	case dns.RecordResponseAAAA:
		return u.Content, nil
	case dns.RecordResponseCNAME:
		return u.Content, nil
	case dns.RecordResponseMX:
		return fmt.Sprintf("%.0f %s", u.Priority, u.Content), nil
	case dns.RecordResponseNS:
		return u.Content, nil
	case dns.RecordResponseOpenpgpkey:
		return u.Content, nil
	case dns.RecordResponsePTR:
		return u.Content, nil
	case dns.RecordResponseTXT:
		return formatTXT(u.Content), nil
	case dns.RecordResponseCAA:
		return fmt.Sprintf("%.0f %s %q", u.Data.Flags, u.Data.Tag, u.Data.Value), nil
	case dns.RecordResponseCERT:
		return fmt.Sprintf("%.0f %.0f %.0f %s", u.Data.Type, u.Data.KeyTag, u.Data.Algorithm, u.Data.Certificate), nil
	case dns.RecordResponseDNSKEY:
		return fmt.Sprintf("%.0f %.0f %.0f %s", u.Data.Flags, u.Data.Protocol, u.Data.Algorithm, u.Data.PublicKey), nil
	case dns.RecordResponseDS:
		return fmt.Sprintf("%.0f %.0f %.0f %s", u.Data.KeyTag, u.Data.Algorithm, u.Data.DigestType, u.Data.Digest), nil
	case dns.RecordResponseHTTPS:
		target := u.Data.Target
		if target == "" {
			target = "."
		}

		if u.Data.Value != "" {
			return fmt.Sprintf("%.0f %s %s", u.Data.Priority, target, u.Data.Value), nil
		}

		return fmt.Sprintf("%.0f %s", u.Data.Priority, target), nil
	case dns.RecordResponseLOC:
		return u.Content, nil
	case dns.RecordResponseNAPTR:
		return fmt.Sprintf("%.0f %.0f %q %q %q %s", u.Data.Order, u.Data.Preference, u.Data.Flags, u.Data.Service, u.Data.Regex, u.Data.Replacement), nil
	case dns.RecordResponseSMIMEA:
		return fmt.Sprintf("%.0f %.0f %.0f %s", u.Data.Usage, u.Data.Selector, u.Data.MatchingType, u.Data.Certificate), nil
	case dns.RecordResponseSRV:
		return fmt.Sprintf("%.0f %.0f %.0f %s", u.Data.Priority, u.Data.Weight, u.Data.Port, u.Data.Target), nil
	case dns.RecordResponseSSHFP:
		return fmt.Sprintf("%.0f %.0f %s", u.Data.Algorithm, u.Data.Type, u.Data.Fingerprint), nil
	case dns.RecordResponseSVCB:
		target := u.Data.Target
		if target == "" {
			target = "."
		}

		if u.Data.Value != "" {
			return fmt.Sprintf("%.0f %s %s", u.Data.Priority, target, u.Data.Value), nil
		}

		return fmt.Sprintf("%.0f %s", u.Data.Priority, target), nil
	case dns.RecordResponseTLSA:
		return fmt.Sprintf("%.0f %.0f %.0f %s", u.Data.Usage, u.Data.Selector, u.Data.MatchingType, u.Data.Certificate), nil
	case dns.RecordResponseURI:
		return fmt.Sprintf("%.0f %.0f %q", u.Priority, u.Data.Weight, u.Data.Target), nil
	}

	return "", fmt.Errorf("unknown record type %q", resp.Type)
}

// formatTXT ensures the content is always correctly quoted
func formatTXT(content string) string {
	return encodeTXT(decodeTXT(content))
}

func parseFields(s string) []string {
	var (
		fields   []string
		current  strings.Builder
		inQuotes bool
		escaped  bool
	)

	for i := 0; i < len(s); i++ {
		r := s[i]

		if escaped {
			current.WriteByte(r)

			escaped = false

			continue
		}

		if r == '\\' {
			escaped = true

			continue
		}

		if r == '"' {
			inQuotes = !inQuotes

			continue
		}

		if (r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f') && !inQuotes {
			if current.Len() > 0 {
				fields = append(fields, current.String())

				current.Reset()
			}
		} else {
			current.WriteByte(r)
		}
	}

	if current.Len() > 0 {
		fields = append(fields, current.String())
	}

	return fields
}

func decodeTXT(s string) string {
	s = strings.TrimSpace(s)

	if !strings.HasPrefix(s, "\"") {
		return s // unquoted raw value
	}

	var (
		b        strings.Builder
		inQuotes bool
		escaped  bool
	)

	for i := 0; i < len(s); i++ {
		c := s[i]

		if escaped {
			b.WriteByte(c)

			escaped = false

			continue
		}

		switch {
		case inQuotes && c == '\\':
			escaped = true
		case c == '"':
			inQuotes = !inQuotes
		case inQuotes:
			b.WriteByte(c)
		}

		// bytes between quoted segments (spaces) are ignored
	}

	return b.String()
}

// encodeTXT renders raw payload bytes as one or more quoted character-strings,
// each at most 255 bytes, per RFC 1035 §3.3.14.
func encodeTXT(raw string) string {
	if raw == "" {
		return `""`
	}

	var parts []string

	for len(raw) > 0 {
		n := min(len(raw), 255)

		chunk := raw[:n]
		raw = raw[n:]

		var b strings.Builder

		b.WriteByte('"')

		for i := 0; i < len(chunk); i++ {
			c := chunk[i]

			if c == '"' || c == '\\' {
				b.WriteByte('\\')
			}

			b.WriteByte(c)
		}

		b.WriteByte('"')

		parts = append(parts, b.String())
	}

	return strings.Join(parts, " ")
}

func parseLOC(value string) (dns.LOCRecordDataParam, error) {
	fields := strings.Fields(value)
	if len(fields) < 5 {
		return dns.LOCRecordDataParam{}, fmt.Errorf("invalid LOC record value: %q (expected <lat> <N|S> <long> <E|W> <alt> [size hp vp])", value)
	}

	var pos int

	readCoord := func(a, b string) (deg, min, sec float64, dir string, err error) {
		var nums []float64

		for pos < len(fields) {
			tok := strings.ToUpper(fields[pos])

			if tok == a || tok == b {
				dir = tok

				pos++

				break
			}

			n, e := strconv.ParseFloat(fields[pos], 64)
			if e != nil {
				return 0, 0, 0, "", fmt.Errorf("invalid LOC number %q: %w", fields[pos], e)
			}

			nums = append(nums, n)
			pos++
		}

		if dir == "" {
			return 0, 0, 0, "", fmt.Errorf("missing LOC direction (expected %s or %s)", a, b)
		}

		if len(nums) > 0 {
			deg = nums[0]
		}

		if len(nums) > 1 {
			min = nums[1]
		}

		if len(nums) > 2 {
			sec = nums[2]
		}

		return deg, min, sec, dir, nil
	}

	latDeg, latMin, latSec, latDir, err := readCoord("N", "S")
	if err != nil {
		return dns.LOCRecordDataParam{}, err
	}

	longDeg, longMin, longSec, longDir, err := readCoord("E", "W")
	if err != nil {
		return dns.LOCRecordDataParam{}, err
	}

	// altitude (required) + optional size/hp/vp, each may carry a trailing 'm'
	readMeters := func(def float64) (float64, error) {
		if pos >= len(fields) {
			return def, nil
		}

		tok := strings.TrimSuffix(strings.ToLower(fields[pos]), "m")

		n, e := strconv.ParseFloat(tok, 64)
		if e != nil {
			return 0, fmt.Errorf("invalid LOC measurement %q: %w", fields[pos], e)
		}

		pos++

		return n, nil
	}

	alt, err := readMeters(0)
	if err != nil {
		return dns.LOCRecordDataParam{}, err
	}

	// RFC 1876 defaults: size 1m, horiz 10000m, vert 10m
	size, err := readMeters(1)
	if err != nil {
		return dns.LOCRecordDataParam{}, err
	}

	hp, err := readMeters(10000)
	if err != nil {
		return dns.LOCRecordDataParam{}, err
	}

	vp, err := readMeters(10)
	if err != nil {
		return dns.LOCRecordDataParam{}, err
	}

	return dns.LOCRecordDataParam{
		LatDegrees:    cloudflare.F(latDeg),
		LatMinutes:    cloudflare.F(latMin),
		LatSeconds:    cloudflare.F(latSec),
		LatDirection:  cloudflare.F(dns.LOCRecordDataLatDirection(latDir)),
		LongDegrees:   cloudflare.F(longDeg),
		LongMinutes:   cloudflare.F(longMin),
		LongSeconds:   cloudflare.F(longSec),
		LongDirection: cloudflare.F(dns.LOCRecordDataLongDirection(longDir)),
		Altitude:      cloudflare.F(alt),
		Size:          cloudflare.F(size),
		PrecisionHorz: cloudflare.F(hp),
		PrecisionVert: cloudflare.F(vp),
	}, nil
}
