package main

import (
	"time"

	"github.com/libdns/libdns"
)

// A, AAAA, CAA, CERT, CNAME, DNSKEY, DS, HTTPS, LOC, MX, NAPTR, NS, OPENPGPKEY, PTR, SMIMEA, SRV, SSHFP, SVCB, TLSA, TXT, URI

type Record struct {
	ID string `yaml:"-" json:"id"`

	Type  string `yaml:"type" json:"type"`
	Name  string `yaml:"name" json:"name"`
	Value string `yaml:"value" json:"value"`
	TTL   int64  `yaml:"ttl,omitempty" json:"ttl,omitempty"`
}

func (r Record) ToLibdns() libdns.Record {
	return libdns.RR{
		Type: r.Type,
		Name: r.Name,
		Data: r.Value,
		TTL:  time.Duration(r.TTL) * time.Second,
	}
}

func (r Record) FullName(zoneName string) string {
	if r.Name == "@" {
		return zoneName
	}

	return r.Name + "." + zoneName
}

func FromLibdns(lr libdns.Record) Record {
	rr := lr.RR()

	return Record{
		ID: FreeId(),

		Type:  rr.Type,
		Name:  rr.Name,
		Value: rr.Data,
		TTL:   int64(rr.TTL.Seconds()),
	}
}
