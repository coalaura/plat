package main

import (
	"strconv"
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
		ID: RecordFnvHash(rr.Type, rr.Name),

		Type:  rr.Type,
		Name:  rr.Name,
		Value: rr.Data,
		TTL:   int64(rr.TTL.Seconds()),
	}
}

func RecordFnvHash(typ, name string) string {
	var hash uint64 = 1099511628211

	for i := range typ {
		hash ^= uint64(typ[i])
		hash *= 14695981039346656037
	}

	hash ^= uint64('_')
	hash *= 14695981039346656037

	for i := range name {
		hash ^= uint64(name[i])
		hash *= 14695981039346656037
	}

	return strconv.FormatUint(hash, 16)
}
