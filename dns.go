package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

type DNSServer struct {
	udp *dns.Server
	tcp *dns.Server

	storage  *Storage
	fallback string
}

type DOHRequest struct {
	body []byte
}

func NewDOHRequest(r *http.Request) (*DOHRequest, error) {
	var (
		body []byte
		err  error
	)

	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			return nil, nil
		}

		body, err = base64.RawURLEncoding.DecodeString(strings.TrimSuffix(dnsParam, "="))
		if err != nil {
			body, err = base64.URLEncoding.DecodeString(dnsParam)
			if err != nil {
				return nil, errors.New("invalid base64 config")
			}
		}
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			return nil, nil
		}

		body, err = io.ReadAll(r.Body)
		if err != nil {
			return nil, errors.New("failed to read request body")
		}
	default:
		return nil, nil
	}

	return &DOHRequest{
		body: body,
	}, nil
}

func NewDNSServer(config *Config, storage *Storage) *DNSServer {
	addr := fmt.Sprintf(":%d", config.DNS.Port)

	server := &DNSServer{
		storage:  storage,
		fallback: config.DNS.Fallback,
	}

	server.udp = &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: dns.HandlerFunc(server.HandleDNSMessage),
	}

	server.tcp = &dns.Server{
		Addr:    addr,
		Net:     "tcp",
		Handler: dns.HandlerFunc(server.HandleDNSMessage),
	}

	log.Printf("DNS server listening on %s\n", addr)

	go server.udp.ListenAndServe()
	go server.tcp.ListenAndServe()

	return server
}

func (r *DOHRequest) Unpack() (*dns.Msg, error) {
	msg := new(dns.Msg)

	err := msg.Unpack(r.body)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

func (s *DNSServer) Close() {
	if s.udp != nil {
		s.udp.Shutdown()
	}

	if s.tcp != nil {
		s.tcp.Shutdown()
	}
}

func (s *DNSServer) ProcessQuery(r *dns.Msg) *dns.Msg {
	msg := new(dns.Msg)

	msg.SetReply(r)

	msg.Compress = true
	msg.Authoritative = true

	if s.fallback != "" {
		msg.RecursionAvailable = true
	}

	if len(r.Question) == 0 {
		return msg
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

		return msg
	}

	if s.fallback != "" {
		client := new(dns.Client)

		in, _, err := client.Exchange(r, s.fallback)
		if err == nil {
			in.Id = r.Id

			return in
		}

		log.Warnf("DNS fallback resolver error: %v", err)
	}

	msg.Rcode = dns.RcodeNameError

	return msg
}

func (s *DNSServer) HandleDNSMessage(w dns.ResponseWriter, r *dns.Msg) {
	resp := s.ProcessQuery(r)

	w.WriteMsg(resp)
}

func (s *DNSServer) HandleDoH(w http.ResponseWriter, r *DOHRequest) {
	msg, err := r.Unpack()
	if err != nil {
		abort(w, http.StatusBadRequest, "failed to unpack dns response")

		return
	}

	resp := s.ProcessQuery(msg)

	resp.Id = 0

	respBytes, err := resp.Pack()
	if err != nil {
		abort(w, http.StatusInternalServerError, "failed to pack dns response")

		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.WriteHeader(http.StatusOK)

	w.Write(respBytes)
}
