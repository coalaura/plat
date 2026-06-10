package main

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

type DNSServer struct {
	server   *dns.Server
	storage  *Storage
	fallback string
}

func NewDNSServer(config *Config, storage *Storage) *DNSServer {
	addr := fmt.Sprintf(":%d", config.DNS.Port)

	server := &DNSServer{
		storage:  storage,
		fallback: config.DNS.Fallback,
	}

	server.server = &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: dns.HandlerFunc(server.handleDNSRequest),
	}

	log.Printf("DNS server listening on %s (UDP)\n", addr)

	go func() {
		err := server.server.ListenAndServe()
		if err != nil {
			log.Warnf("DNS server error: %v", err)
		}
	}()

	return server
}

func (s *DNSServer) Close() {
	if s.server == nil {
		return
	}

	s.server.Shutdown()
}

func (s *DNSServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	var msg dns.Msg

	msg.SetReply(r)

	msg.Authoritative = true

	if len(r.Question) == 0 {
		w.WriteMsg(&msg)

		return
	}

	question := r.Question[0]

	qName := strings.ToLower(strings.TrimSuffix(question.Name, "."))
	qType := dns.TypeToString[question.Qtype]

	answers, nameExists, zoneMatched := s.storage.LookupLocal(qName, qType)
	if zoneMatched {
		if len(answers) > 0 {
			msg.Answer = answers
			msg.Rcode = dns.RcodeSuccess
		} else if nameExists {
			msg.Rcode = dns.RcodeSuccess
		} else {
			msg.Rcode = dns.RcodeNameError
		}

		w.WriteMsg(&msg)

		return
	}

	if s.fallback != "" {
		client := new(dns.Client)

		in, _, err := client.Exchange(r, s.fallback)
		if err == nil {
			w.WriteMsg(in)

			return
		}

		log.Warnf("DNS fallback resolver error: %v", err)
	}

	msg.Rcode = dns.RcodeNameError

	w.WriteMsg(&msg)
}
