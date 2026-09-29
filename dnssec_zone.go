package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type SignedRRSet struct {
	Records   []dns.RR
	Signature *dns.RRSIG
}

type SignedNode struct {
	Sets map[uint16]*SignedRRSet
}

// Immutable signed snapshots are reused until records change or renewal is due.
type SignedZone struct {
	Name    string
	Nodes   map[string]*SignedNode
	Names   []string
	Cuts    []string
	Dnames  []string
	Glue    map[string]*SignedNode
	RenewAt time.Time
}

func (z *SignedZone) answer(request *dns.Msg) *dns.Msg {
	message := new(dns.Msg)

	message.SetReply(request)
	message.Authoritative = true
	message.Compress = true

	question := request.Question[0]

	name := canonicalQueryName(question.Name)

	var dnssec bool

	option := request.IsEdns0()
	if option != nil {
		dnssec = option.Do()

		message.SetEdns0(min(max(option.UDPSize(), 512), 1232), dnssec)
	}

	for _, cut := range z.Cuts {
		if !dns.IsSubDomain(cut, name) {
			continue
		}

		if name == cut && question.Qtype == dns.TypeDS {
			break
		}

		message.Authoritative = false

		delegation := z.Nodes[cut]

		message.Ns = appendSignedSet(message.Ns, delegation.Sets[dns.TypeNS], cut, false)

		if dnssec {
			if delegation.Sets[dns.TypeDS] != nil {
				message.Ns = appendSignedSet(message.Ns, delegation.Sets[dns.TypeDS], cut, true)
			} else {
				z.appendProof(message, cut)
			}
		}

		for _, record := range delegation.Sets[dns.TypeNS].Records {
			target := strings.ToLower(record.(*dns.NS).Ns)
			if !dns.IsSubDomain(z.Name, target) {
				continue
			}

			node := z.Glue[target]
			if node != nil {
				message.Extra = appendSignedSet(message.Extra, node.Sets[dns.TypeA], target, false)
				message.Extra = appendSignedSet(message.Extra, node.Sets[dns.TypeAAAA], target, false)
			}
		}

		return message
	}

	// Chase in-zone aliases, stopping at external names and delegation boundaries.
	for range 16 {
		ancestor := parentDNSName(name)

		var redirected bool

		for dns.IsSubDomain(z.Name, ancestor) {
			node := z.Nodes[ancestor]
			if node != nil && node.Sets[dns.TypeDNAME] != nil {
				set := node.Sets[dns.TypeDNAME]
				target := name[:len(name)-len(ancestor)] + set.Records[0].(*dns.DNAME).Target

				message.Answer = appendSignedSet(message.Answer, set, ancestor, dnssec)

				_, valid := dns.IsDomainName(target)
				if !valid {
					message.Rcode = dns.RcodeYXDomain

					return message
				}

				// A DNAME-synthesized CNAME is authenticated by the signed DNAME;
				// it must not carry its own RRSIG (RFC 6672).
				message.Answer = append(message.Answer, &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   name,
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    set.Records[0].Header().Ttl,
					},
					Target: target,
				})

				name = canonicalQueryName(target)
				if !dns.IsSubDomain(z.Name, name) || z.belowCut(name) || question.Qtype == dns.TypeCNAME {
					return message
				}

				redirected = true

				break
			}

			if ancestor == z.Name {
				break
			}

			ancestor = parentDNSName(ancestor)
		}

		if redirected {
			continue
		}

		node := z.Nodes[name]
		owner := name
		closest := ""

		if node == nil {
			closest = z.closestEncloser(name)
			owner = "*." + closest
			node = z.Nodes[owner]
		}

		if node == nil {
			message.Rcode = dns.RcodeNameError

			z.appendNegative(message, dnssec)

			if dnssec {
				z.appendProof(message, closest)
				z.appendProof(message, nextCloser(name, closest))
				z.appendProof(message, "*."+closest)
			}

			return message
		}

		if closest != "" && dnssec {
			z.appendProof(message, closest)
			z.appendProof(message, nextCloser(name, closest))
		}

		switch question.Qtype {
		case dns.TypeANY:
			types := nodeTypes(node)

			slices.Sort(types)

			for _, typ := range types {
				if typ != dns.TypeNSEC || dnssec {
					message.Answer = appendSignedSet(message.Answer, node.Sets[typ], name, dnssec)
				}
			}

			return message
		case dns.TypeRRSIG:
			for _, typ := range nodeTypes(node) {
				set := node.Sets[typ]
				if set.Signature != nil {
					copy := dns.Copy(set.Signature)

					copy.Header().Name = name

					message.Answer = append(message.Answer, copy)
				}
			}

			return message
		}

		set := node.Sets[question.Qtype]
		if set != nil {
			message.Answer = appendSignedSet(message.Answer, set, name, dnssec)

			return message
		}

		alias := node.Sets[dns.TypeCNAME]
		if alias != nil {
			message.Answer = appendSignedSet(message.Answer, alias, name, dnssec)

			name = canonicalQueryName(alias.Records[0].(*dns.CNAME).Target)
			if !dns.IsSubDomain(z.Name, name) || z.belowCut(name) {
				return message
			}

			continue
		}

		z.appendNegative(message, dnssec)

		if dnssec {
			z.appendProof(message, owner)
		}

		return message
	}

	message.Answer = nil
	message.Ns = nil
	message.Rcode = dns.RcodeServerFailure

	return message
}

func (z *SignedZone) belowCut(name string) bool {
	for _, cut := range z.Cuts {
		if dns.IsSubDomain(cut, name) {
			return true
		}
	}

	return false
}

func (z *SignedZone) belowDNAME(name string) bool {
	for _, owner := range z.Dnames {
		if name != owner && dns.IsSubDomain(owner, name) {
			return true
		}
	}

	return false
}

func (z *SignedZone) closestEncloser(name string) string {
	for name != z.Name {
		name = parentDNSName(name)
		if z.Nodes[name] != nil {
			return name
		}
	}

	return z.Name
}

func (z *SignedZone) appendNegative(message *dns.Msg, dnssec bool) {
	soa := z.Nodes[z.Name].Sets[dns.TypeSOA]

	negative := make([]dns.RR, 0, len(message.Ns)+2)

	negative = appendSignedSet(negative, soa, z.Name, dnssec)

	ttl := min(soa.Records[0].Header().Ttl, soa.Records[0].(*dns.SOA).Minttl)

	for _, record := range negative {
		record.Header().Ttl = ttl
	}

	message.Ns = append(negative, message.Ns...)
}

func (z *SignedZone) appendProof(message *dns.Msg, name string) {
	index, exact := slices.BinarySearchFunc(z.Names, name, compareDNSNames)
	if !exact {
		index = (index + len(z.Names) - 1) % len(z.Names)
	}

	owner := z.Names[index]

	for _, record := range message.Ns {
		if record.Header().Rrtype == dns.TypeNSEC && record.Header().Name == owner {
			return
		}
	}

	message.Ns = appendSignedSet(message.Ns, z.Nodes[owner].Sets[dns.TypeNSEC], owner, true)
}

func buildSignedZone(name string, records map[string]*Record, config *DNSSECConfig, serial uint32, now time.Time) (*SignedZone, error) {
	if config.key == nil || config.signer == nil {
		return nil, errors.New("DNSSEC signing key unavailable")
	}

	name = dns.Fqdn(name)

	zone := &SignedZone{
		Name:    name,
		Nodes:   make(map[string]*SignedNode, len(records)+1),
		Glue:    make(map[string]*SignedNode, len(records)+1),
		RenewAt: now.Add(DNSSECRenewal),
	}

	for _, record := range records {
		rr := record.GetRR()
		if rr == nil {
			return nil, errors.New("invalid record in signed zone")
		}

		owner := strings.ToLower(rr.Header().Name)
		if !validSignedOwner(owner) || !dns.IsSubDomain(name, owner) {
			return nil, fmt.Errorf("invalid DNSSEC record owner %q", owner)
		}

		if rr.Header().Class != dns.ClassINET {
			return nil, errors.New("signed zones require IN records")
		}

		switch rr.Header().Rrtype {
		case dns.TypeDNSKEY, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM:
			return nil, errors.New("DNSKEY, RRSIG and denial records are managed automatically for plat DNSSEC")
		case dns.TypeDNAME:
			if strings.HasPrefix(owner, "*.") {
				return nil, errors.New("DNAME cannot have a wildcard owner")
			}
		case dns.TypeSOA:
			if owner != name {
				return nil, errors.New("SOA must be at the zone apex")
			}
		case dns.TypeDS:
			if owner == name {
				return nil, errors.New("publish the zone's DS in the parent zone, not at its own apex")
			}
		case dns.TypeNS:
			if strings.HasPrefix(owner, "*.") {
				return nil, errors.New("wildcard NS delegations are not supported")
			}

			if owner == name && len(config.Nameservers) > 0 {
				continue
			}
		}

		copy := dns.Copy(rr)

		copy.Header().Name = owner

		addZoneRecord(zone.Glue, copy)
	}

	for _, nameserver := range config.Nameservers {
		addZoneRecord(zone.Glue, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    DNSSECTTL,
			},
			Ns: nameserver,
		})
	}

	apex := zone.Glue[name]
	if apex == nil || apex.Sets[dns.TypeNS] == nil {
		return nil, errors.New("enter the authoritative nameservers that will serve this zone from plat")
	}

	if apex.Sets[dns.TypeSOA] == nil {
		addZoneRecord(zone.Glue, &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    DNSSECTTL,
			},
			Ns:      apex.Sets[dns.TypeNS].Records[0].(*dns.NS).Ns,
			Mbox:    "hostmaster." + name,
			Serial:  serial,
			Refresh: 3600,
			Retry:   600,
			Expire:  1209600,
			Minttl:  300,
		})
	} else if len(apex.Sets[dns.TypeSOA].Records) != 1 {
		return nil, errors.New("a zone must have exactly one SOA record")
	}

	soa := apex.Sets[dns.TypeSOA].Records[0].(*dns.SOA)

	soa.Serial = max(soa.Serial, serial)

	addZoneRecord(zone.Glue, dns.Copy(config.key))

	for owner, node := range zone.Glue {
		if node.Sets[dns.TypeDNAME] != nil {
			zone.Dnames = append(zone.Dnames, owner)
		}
	}

	for owner, node := range zone.Glue {
		if owner != name && node.Sets[dns.TypeNS] != nil && !zone.belowDNAME(owner) {
			zone.Cuts = append(zone.Cuts, owner)
		}
	}

	slices.SortFunc(zone.Cuts, func(first, second string) int {
		return dns.CountLabel(first) - dns.CountLabel(second)
	})

	// Only the first delegation on each path is authoritative in this zone.
	activeCuts := make([]string, 0, len(zone.Cuts))

	for _, cut := range zone.Cuts {
		var covered bool

		for _, parent := range activeCuts {
			if dns.IsSubDomain(parent, cut) {
				covered = true

				break
			}
		}

		if !covered {
			activeCuts = append(activeCuts, cut)
		}
	}

	zone.Cuts = activeCuts

	for owner, node := range zone.Glue {
		if zone.belowDNAME(owner) {
			continue
		}

		cutOwner := ""

		for _, cut := range zone.Cuts {
			if dns.IsSubDomain(cut, owner) {
				cutOwner = cut

				break
			}
		}

		if cutOwner != "" && owner != cutOwner {
			continue
		}

		if cutOwner != "" {
			delegation := &SignedNode{Sets: make(map[uint16]*SignedRRSet, 4)}

			delegation.Sets[dns.TypeNS] = node.Sets[dns.TypeNS]

			if node.Sets[dns.TypeDS] != nil {
				delegation.Sets[dns.TypeDS] = node.Sets[dns.TypeDS]
			}

			zone.Nodes[owner] = delegation
		} else {
			zone.Nodes[owner] = node

			if node.Sets[dns.TypeCNAME] != nil && (len(node.Sets) != 1 || len(node.Sets[dns.TypeCNAME].Records) != 1) {
				return nil, fmt.Errorf("CNAME must be the only record at %s", owner)
			}

			if node.Sets[dns.TypeDS] != nil {
				return nil, fmt.Errorf("DS requires an NS delegation at %s", owner)
			}

			if node.Sets[dns.TypeDNAME] != nil && len(node.Sets[dns.TypeDNAME].Records) != 1 {
				return nil, fmt.Errorf("DNAME requires exactly one target at %s", owner)
			}
		}
	}

	// Empty non-terminals exist and block wildcard synthesis, even without data.
	for owner := range zone.Glue {
		if zone.Nodes[owner] == nil {
			continue
		}

		for owner != name {
			owner = parentDNSName(owner)
			if zone.Nodes[owner] == nil {
				zone.Nodes[owner] = &SignedNode{Sets: make(map[uint16]*SignedRRSet, 1)}
			}
		}
	}

	zone.Names = make([]string, 0, len(zone.Nodes))

	for owner := range zone.Nodes {
		zone.Names = append(zone.Names, owner)
	}

	slices.SortFunc(zone.Names, compareDNSNames)

	for index, owner := range zone.Names {
		node := zone.Nodes[owner]
		types := nodeTypes(node)

		types = append(types, dns.TypeNSEC, dns.TypeRRSIG)

		slices.Sort(types)

		addZoneRecord(zone.Nodes, &dns.NSEC{
			Hdr: dns.RR_Header{
				Name:   owner,
				Rrtype: dns.TypeNSEC,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			NextDomain: zone.Names[(index+1)%len(zone.Names)],
			TypeBitMap: types,
		})

		for typ, set := range node.Sets {
			if typ == dns.TypeNS && owner != name {
				continue
			}

			ttl := set.Records[0].Header().Ttl

			for _, record := range set.Records {
				ttl = min(ttl, record.Header().Ttl)
			}

			for _, record := range set.Records {
				record.Header().Ttl = ttl
			}

			signature := &dns.RRSIG{
				Hdr: dns.RR_Header{
					Name:   owner,
					Rrtype: dns.TypeRRSIG,
					Class:  dns.ClassINET,
					Ttl:    ttl,
				},
				Algorithm:  config.key.Algorithm,
				KeyTag:     config.key.KeyTag(),
				SignerName: name,
				Inception:  uint32(now.Add(-time.Hour).Unix()),
				Expiration: uint32(now.Add(DNSSECLifetime).Unix()),
			}

			err := signature.Sign(config.signer, set.Records)
			if err != nil {
				return nil, fmt.Errorf("sign %s %s: %w", owner, dns.TypeToString[typ], err)
			}

			set.Signature = signature
		}
	}

	return zone, nil
}

func addZoneRecord(nodes map[string]*SignedNode, record dns.RR) {
	owner := record.Header().Name

	node := nodes[owner]
	if node == nil {
		node = &SignedNode{
			Sets: make(map[uint16]*SignedRRSet, 4),
		}

		nodes[owner] = node
	}

	typ := record.Header().Rrtype

	set := node.Sets[typ]
	if set == nil {
		set = &SignedRRSet{
			Records: make([]dns.RR, 0, 1),
		}

		node.Sets[typ] = set
	}

	for _, existing := range set.Records {
		if dns.IsDuplicate(existing, record) {
			return
		}
	}

	set.Records = append(set.Records, record)
}

func appendSignedSet(destination []dns.RR, set *SignedRRSet, owner string, dnssec bool) []dns.RR {
	if set == nil {
		return destination
	}

	for _, record := range set.Records {
		copy := dns.Copy(record)

		copy.Header().Name = owner

		destination = append(destination, copy)
	}

	if dnssec && set.Signature != nil {
		copy := dns.Copy(set.Signature)

		copy.Header().Name = owner

		destination = append(destination, copy)
	}

	return destination
}

func nodeTypes(node *SignedNode) []uint16 {
	types := make([]uint16, 0, len(node.Sets))

	for typ := range node.Sets {
		types = append(types, typ)
	}

	return types
}

func compareDNSNames(first, second string) int {
	// Compare decoded labels from the root, including escaped/binary query labels.
	// Fixed wire buffers keep proof selection allocation-free.
	var (
		firstWire     [256]byte
		secondWire    [256]byte
		firstOffsets  [128]int
		secondOffsets [128]int
	)

	_, _ = dns.PackDomainName(first, firstWire[:], 0, nil, false)
	_, _ = dns.PackDomainName(second, secondWire[:], 0, nil, false)

	firstCount := dnsLabelOffsets(firstWire[:], firstOffsets[:])
	secondCount := dnsLabelOffsets(secondWire[:], secondOffsets[:])

	for index := 1; index <= min(firstCount, secondCount); index++ {
		firstOffset := firstOffsets[firstCount-index]
		secondOffset := secondOffsets[secondCount-index]

		firstLabel := firstWire[firstOffset+1 : firstOffset+1+int(firstWire[firstOffset])]
		secondLabel := secondWire[secondOffset+1 : secondOffset+1+int(secondWire[secondOffset])]

		for character := range min(len(firstLabel), len(secondLabel)) {
			firstByte := lowerDNSByte(firstLabel[character])
			secondByte := lowerDNSByte(secondLabel[character])

			if firstByte != secondByte {
				return int(firstByte) - int(secondByte)
			}
		}

		if len(firstLabel) != len(secondLabel) {
			return len(firstLabel) - len(secondLabel)
		}
	}

	return firstCount - secondCount
}

func parentDNSName(name string) string {
	index, _ := dns.NextLabel(name, 0)

	return name[index:]
}

func nextCloser(name, closest string) string {
	for parentDNSName(name) != closest && name != closest {
		name = parentDNSName(name)
	}

	return name
}

func validSignedOwner(name string) bool {
	_, valid := dns.IsDomainName(name)
	if !valid {
		return false
	}

	for index, character := range name {
		if character == '*' && index == 0 && strings.HasPrefix(name, "*.") {
			continue
		}

		if character != '.' && character != '-' && character != '_' && (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') {
			return false
		}
	}

	return true
}

func dnsLabelOffsets(wire []byte, offsets []int) int {
	count := 0

	for offset := 0; offset < len(wire) && wire[offset] != 0; offset += int(wire[offset]) + 1 {
		offsets[count] = offset

		count++
	}

	return count
}

func lowerDNSByte(character byte) byte {
	if character >= 'A' && character <= 'Z' {
		return character + ('a' - 'A')
	}

	return character
}
