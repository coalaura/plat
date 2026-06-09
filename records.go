package main

import (
	"time"

	"github.com/libdns/libdns"
)

// A, AAAA, CAA, CERT, CNAME, DNSKEY, DS, HTTPS, LOC, MX, NAPTR, NS, OPENPGPKEY, PTR, SMIMEA, SRV, SSHFP, SVCB, TLSA, TXT, URI

type Record struct {
	Type  string `yaml:"type"`
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
	TTL   int64  `yaml:"ttl,omitempty"`
}

func (cr Record) ToLibdns() libdns.Record {
	return libdns.RR{
		Type: cr.Type,
		Name: cr.Name,
		Data: cr.Value,
		TTL:  time.Duration(cr.TTL) * time.Second,
	}
}

func FromLibdns(lr libdns.Record) Record {
	rr := lr.RR()

	return Record{
		Type:  rr.Type,
		Name:  rr.Name,
		Value: rr.Data,
		TTL:   int64(rr.TTL.Seconds()),
	}
}
