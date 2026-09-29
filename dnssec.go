package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/miekg/dns"
)

const (
	DNSSECPath = "data/dnssec.yml"

	DNSSECTTL      = 3600
	DNSSECLifetime = 14 * 24 * time.Hour
	DNSSECRenewal  = 24 * time.Hour
)

// Keys are stored separately from editable records and never serialized to the API.
// Configurations are immutable after publication under the zone mutex.
type DNSSECConfig struct {
	Enabled     bool     `yaml:"enabled"`
	Provider    string   `yaml:"provider"`
	Nameservers []string `yaml:"nameservers,omitempty"`
	DNSKEY      string   `yaml:"dnskey,omitempty"`
	PrivateKey  string   `yaml:"private_key,omitempty"`
	signer      crypto.Signer
	key         *dns.DNSKEY
}

type DNSSECDetails struct {
	Configured   bool     `json:"configured"`
	Enabled      bool     `json:"enabled"`
	Provider     string   `json:"provider"`
	Status       string   `json:"status"`
	Nameservers  []string `json:"nameservers,omitempty"`
	DSRecord     string   `json:"ds_record,omitempty"`
	Digest       string   `json:"digest,omitempty"`
	DigestType   string   `json:"digest_type,omitempty"`
	Algorithm    string   `json:"algorithm,omitempty"`
	PublicKey    string   `json:"public_key,omitempty"`
	KeyTag       uint16   `json:"key_tag"`
	Flags        uint16   `json:"flags"`
	Protocol     uint8    `json:"protocol"`
	DNSKEYRecord string   `json:"dnskey_record,omitempty"`
}

type DNSSECRequest struct {
	Enabled         bool     `json:"enabled"`
	Provider        string   `json:"provider"`
	Nameservers     []string `json:"nameservers"`
	ParentDSRemoved bool     `json:"parent_ds_removed"`
}

func (s *Storage) LoadDNSSEC() error {
	file, err := OpenFileForReading(DNSSECPath)
	if os.IsNotExist(err) {
		return nil
	}

	if err != nil {
		return err
	}

	defer file.Close()

	var configurations map[string]*DNSSECConfig

	err = yaml.NewDecoder(file).Decode(&configurations)
	if err != nil {
		return fmt.Errorf("load DNSSEC: %w", err)
	}

	for id, config := range configurations {
		zone, exists := s.zones[id]
		if !exists {
			continue
		}

		if config == nil || (config.Provider != "plat" && config.Provider != "cloudflare") {
			return fmt.Errorf("invalid DNSSEC configuration for %s", zone.Name)
		}

		config.Nameservers, err = normalizeNameservers(config.Nameservers)
		if err != nil {
			return err
		}

		if config.Provider == "plat" || config.DNSKEY != "" || config.PrivateKey != "" {
			err = config.loadKey(zone.Name)
			if err != nil {
				return fmt.Errorf("DNSSEC key for %s: %w", zone.Name, err)
			}
		}

		if config.Provider == "cloudflare" && (zone.IsLocal() || len(config.Nameservers) == 0) {
			return fmt.Errorf("invalid Cloudflare DNSSEC configuration for %s", zone.Name)
		}

		zone.dnssec = config
	}

	return nil
}

func (s *Storage) DNSSECDetails(ctx context.Context, id, provider string) (DNSSECDetails, error) {
	s.mx.RLock()
	zone, exists := s.zones[id]
	if !exists {
		s.mx.RUnlock()

		return DNSSECDetails{}, errLocalZoneNotFound
	}

	zone.mx.RLock()

	config := zone.dnssec

	zone.mx.RUnlock()
	s.mx.RUnlock()

	if provider == "cloudflare" || (provider == "" && config != nil && config.Provider == "cloudflare") {
		if s.client == nil || zone.IsLocal() {
			return DNSSECDetails{}, errors.New("cloudflare DNSSEC requires a connected Cloudflare zone")
		}

		details, err := s.client.GetDNSSEC(ctx, id)
		if err != nil {
			return DNSSECDetails{}, err
		}

		details.Nameservers, err = s.client.DNSSECNameservers(ctx, id)
		if err != nil {
			return DNSSECDetails{}, err
		}

		details.Configured = config != nil && config.Enabled && config.Provider == "cloudflare"

		return details, nil
	}

	if provider != "" && provider != "plat" {
		return DNSSECDetails{}, errors.New("unknown DNSSEC provider")
	}

	if config == nil || config.Provider != "plat" {
		return DNSSECDetails{Provider: "plat", Status: "disabled"}, nil
	}

	return config.details(), nil
}

func (s *Storage) ConfigureDNSSEC(ctx context.Context, id string, request DNSSECRequest) (DNSSECDetails, error) {
	s.dsmx.Lock()
	defer s.dsmx.Unlock()

	s.mx.RLock()
	zone, exists := s.zones[id]
	s.mx.RUnlock()

	if !exists {
		return DNSSECDetails{}, errLocalZoneNotFound
	}

	zone.mx.RLock()
	previous := zone.dnssec
	zone.mx.RUnlock()

	if request.Provider == "" {
		request.Provider = "plat"
	}

	if request.Provider != "plat" && request.Provider != "cloudflare" {
		return DNSSECDetails{}, errors.New("unknown DNSSEC provider")
	}

	if previous != nil && previous.Enabled {
		if request.Provider != previous.Provider {
			return DNSSECDetails{}, errors.New("disable DNSSEC and remove the parent DS before changing signer")
		}

		if !request.Enabled && !request.ParentDSRemoved {
			return DNSSECDetails{}, errors.New("remove the DS record from the parent zone before disabling DNSSEC")
		}
	}

	config := &DNSSECConfig{Enabled: request.Enabled, Provider: request.Provider}

	if previous != nil {
		config.DNSKEY = previous.DNSKEY
		config.PrivateKey = previous.PrivateKey
		config.key = previous.key
		config.signer = previous.signer
	}

	if previous != nil && previous.Provider == request.Provider {
		*config = *previous
		config.Enabled = request.Enabled
	}

	var (
		err           error
		remoteDetails DNSSECDetails
	)

	if config.Provider == "cloudflare" {
		if zone.IsLocal() || s.client == nil {
			return DNSSECDetails{}, errors.New("cloudflare DNSSEC requires a connected Cloudflare zone")
		}

		if !request.Enabled && !request.ParentDSRemoved {
			remoteDetails, err = s.client.GetDNSSEC(ctx, id)
			if err != nil {
				return DNSSECDetails{}, err
			}

			if remoteDetails.Enabled {
				return DNSSECDetails{}, errors.New("remove the DS record from the parent zone before disabling DNSSEC")
			}
		}

		config.Nameservers, err = s.client.DNSSECNameservers(ctx, id)
		if err != nil {
			return DNSSECDetails{}, err
		}
	} else {
		if request.Enabled {
			config.Nameservers, err = normalizeNameservers(request.Nameservers)
			if err != nil {
				return DNSSECDetails{}, err
			}
		}

		if config.key == nil {
			err = config.generateKey(zone.Name)
			if err != nil {
				return DNSSECDetails{}, err
			}
		}
	}

	// Serialize record edits through the transition, including durable persistence.
	// storeDNSSEC takes no zone locks; its snapshot is captured before this lock.
	configurations := s.dnssecSnapshot()

	configurations[id] = config

	zone.mx.Lock()
	defer zone.mx.Unlock()

	if config.Enabled && config.Provider == "plat" {
		var snapshot *SignedZone

		snapshot, err = buildSignedZone(zone.Name, zone.Records, config, zone.nextSerial(), time.Now())
		if err != nil {
			return DNSSECDetails{}, err
		}

		zone.serial = snapshot.Nodes[snapshot.Name].Sets[dns.TypeSOA].Records[0].(*dns.SOA).Serial
	}

	if config.Provider == "cloudflare" {
		remoteDetails, err = s.client.SetDNSSEC(ctx, id, config.Enabled)
		if err != nil {
			return DNSSECDetails{}, err
		}
	}

	err = storeDNSSEC(configurations)
	if err != nil {
		// A remote enable may already have succeeded. Report it explicitly; a GET
		// to Cloudflare remains the source of truth, and retrying is idempotent.
		return DNSSECDetails{}, fmt.Errorf("persist DNSSEC configuration: %w", err)
	}

	zone.dnssec = config
	zone.signed = nil

	if config.Provider == "cloudflare" {
		remoteDetails.Configured = config.Enabled
		remoteDetails.Nameservers = config.Nameservers

		return remoteDetails, nil
	}

	return config.details(), nil
}

func (s *Storage) dnssecSnapshot() map[string]*DNSSECConfig {
	s.mx.RLock()
	defer s.mx.RUnlock()

	configurations := make(map[string]*DNSSECConfig, len(s.zones))

	for id, zone := range s.zones {
		zone.mx.RLock()

		if zone.dnssec != nil {
			configurations[id] = zone.dnssec
		}

		zone.mx.RUnlock()
	}

	return configurations
}

func (c *DNSSECConfig) generateKey(name string) error {
	c.key = &dns.DNSKEY{
		Hdr:   dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: DNSSECTTL},
		Flags: 257, Protocol: 3, Algorithm: dns.ED25519,
	}

	private, err := c.key.Generate(256)
	if err != nil {
		return err
	}

	c.signer = private.(crypto.Signer)
	c.DNSKEY = strings.ReplaceAll(c.key.String(), "\t", " ")
	c.PrivateKey = c.key.PrivateKeyString(private)

	return nil
}

func (c *DNSSECConfig) loadKey(name string) error {
	record, err := dns.NewRR(c.DNSKEY)
	if err != nil {
		return err
	}

	key, ok := record.(*dns.DNSKEY)
	if !ok || key.Hdr.Name != dns.Fqdn(name) || key.Flags != 257 || key.Protocol != 3 || key.Algorithm != dns.ED25519 {
		return errors.New("invalid signing DNSKEY")
	}

	private, err := key.NewPrivateKey(c.PrivateKey)
	if err != nil {
		return err
	}

	signer, ok := private.(ed25519.PrivateKey)
	if !ok || len(signer) != ed25519.PrivateKeySize {
		return errors.New("invalid Ed25519 private key")
	}

	// NewPrivateKey reconstructs this key from its seed; its suffix is the derived public key.
	public := signer[ed25519.SeedSize:]

	if base64.StdEncoding.EncodeToString(public) != key.PublicKey {
		return errors.New("private key does not match DNSKEY")
	}

	c.key = key
	c.signer = signer

	return nil
}

func (c *DNSSECConfig) details() DNSSECDetails {
	details := DNSSECDetails{
		Configured:  c.Enabled,
		Enabled:     c.Enabled,
		Provider:    c.Provider,
		Status:      "disabled",
		Nameservers: c.Nameservers,
	}

	if c.Enabled {
		details.Status = "signing"
	}

	if c.key != nil && c.Provider == "plat" {
		delegation := c.key.ToDS(dns.SHA256)

		details.DSRecord = delegation.String()
		details.Digest = delegation.Digest
		details.DigestType = "2"
		details.Algorithm = strconv.Itoa(int(c.key.Algorithm))
		details.PublicKey = c.key.PublicKey
		details.KeyTag = c.key.KeyTag()
		details.Flags = c.key.Flags
		details.Protocol = c.key.Protocol
		details.DNSKEYRecord = c.key.String()
	}

	return details
}

func (z *Zone) nextSerial() uint32 {
	return max(z.serial+1, uint32(time.Now().Unix()))
}

func (z *Zone) validateSignedChange(record *Record, removed string) error {
	if z.dnssec == nil || !z.dnssec.Enabled || z.dnssec.Provider != "plat" {
		return nil
	}

	records := make(map[string]*Record, len(z.Records)+1)

	for id, existing := range z.Records {
		if id != removed && (record == nil || id != record.ID) {
			records[id] = existing
		}
	}

	if record != nil {
		records[record.ID] = record
	}

	_, err := buildSignedZone(z.Name, records, z.dnssec, z.nextSerial(), time.Now())
	return err
}

func normalizeNameservers(nameservers []string) ([]string, error) {
	normalized := make([]string, 0, len(nameservers))
	seen := make(map[string]bool, len(nameservers))

	for _, name := range nameservers {
		name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
		if !validDNSName(name) {
			return nil, fmt.Errorf("invalid nameserver %q", name)
		}

		if !seen[name] {
			normalized = append(normalized, dns.Fqdn(name))

			seen[name] = true
		}
	}

	return normalized, nil
}

func storeDNSSEC(configurations map[string]*DNSSECConfig) error {
	tempPath := DNSSECPath + ".tmp"

	file, err := os.OpenFile(tempPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	defer file.Close()
	defer os.Remove(tempPath)

	err = file.Chmod(0600)
	if err != nil {
		return err
	}

	err = yaml.NewEncoder(file).Encode(configurations)
	if err != nil {
		return err
	}

	err = file.Sync()
	if err != nil {
		return err
	}

	err = file.Close()
	if err != nil {
		return err
	}

	return os.Rename(tempPath, DNSSECPath)
}
