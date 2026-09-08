package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type DNSServer struct {
	udp *dns.Server
	tcp *dns.Server

	storage *Storage

	fallbackIP string
	dnsClient  *dns.Client

	fallbackHTTPS string
	httpClient    *http.Client
}

type DoHRequest struct {
	body []byte
}

func NewDoHHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   4 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   100,
			IdleConnTimeout:       10 * time.Second,
			TLSHandshakeTimeout:   4 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

func NewDoHRequest(r *http.Request) (*DoHRequest, error) {
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

	return &DoHRequest{
		body: body,
	}, nil
}

func NewDNSServer(config *Config, storage *Storage) *DNSServer {
	addr := fmt.Sprintf(":%d", config.DNS.Port)

	server := &DNSServer{
		storage: storage,

		fallbackIP: config.DNS.FallbackIP,
		dnsClient:  new(dns.Client),

		fallbackHTTPS: config.DNS.FallbackHTTPS,
		httpClient:    NewDoHHTTPClient(),
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

func (r *DoHRequest) Unpack() (*dns.Msg, error) {
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

	if s.fallbackIP != "" || s.fallbackHTTPS != "" {
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

	if s.fallbackHTTPS != "" {
		in, err := s.ExchangeDoH(r)
		if err == nil {
			in.Id = r.Id

			return in
		}

		log.Warnf("DNS fallback resolver (https) error: %v", err)
	} else if s.fallbackIP != "" {
		in, _, err := s.dnsClient.Exchange(r, s.fallbackIP)
		if err == nil {
			in.Id = r.Id

			return in
		}

		log.Warnf("DNS fallback resolver (ip) error: %v", err)
	}

	msg.Rcode = dns.RcodeNameError

	return msg
}

func (s *DNSServer) HandleDNSMessage(w dns.ResponseWriter, r *dns.Msg) {
	resp := s.ProcessQuery(r)

	w.WriteMsg(resp)
}

func (s *DNSServer) HandleDoH(w http.ResponseWriter, r *DoHRequest) {
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

func (s *DNSServer) ExchangeDoH(r *dns.Msg) (*dns.Msg, error) {
	reqBytes, err := r.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack dns query: %w", err)
	}

	var resp *http.Response

	for i := range 3 {
		var req *http.Request

		if len(reqBytes) <= 512 {
			b64 := base64.RawURLEncoding.EncodeToString(reqBytes)

			sep := "?"

			if strings.Contains(s.fallbackHTTPS, "?") {
				sep = "&"
			}

			url := s.fallbackHTTPS + sep + "dns=" + b64

			req, err = http.NewRequest(http.MethodGet, url, nil)
		} else {
			req, err = http.NewRequest(http.MethodPost, s.fallbackHTTPS, bytes.NewReader(reqBytes))
			req.Header.Set("Content-Type", "application/dns-message")
		}

		if err != nil {
			return nil, fmt.Errorf("failed to create DoH request: %w", err)
		}

		req.Header.Set("Accept", "application/dns-message")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PlatDNS/1.0")

		resp, err = s.httpClient.Do(req)
		if err == nil {
			break
		}

		if i < 2 {
			time.Sleep(50 * time.Millisecond)

			continue
		}

		return nil, fmt.Errorf("DoH exchange failed after retry: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH responder returned status: %s", resp.Status)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH response body: %w", err)
	}

	respMsg := new(dns.Msg)

	err = respMsg.Unpack(respBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack DoH response: %w", err)
	}

	return respMsg, nil
}
