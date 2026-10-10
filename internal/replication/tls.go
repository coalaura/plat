package replication

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type TLSFiles struct {
	Certificate string `yaml:"certificate"`
	Key         string `yaml:"key"`
	CA          string `yaml:"ca,omitempty"`
}

type MasterConfig struct {
	Enabled        bool              `yaml:"enabled"`
	TLS            TLSFiles          `yaml:"tls"`
	Clients        map[string]string `yaml:"clients"`
	TrustedClients string            `yaml:"trusted_clients"`
}

type ClientConfig struct {
	Address       string   `yaml:"address"`
	ServerName    string   `yaml:"server_name"`
	TLS           TLSFiles `yaml:"tls"`
	TrustedMaster string   `yaml:"trusted_master"`
}

func (c MasterConfig) TLSConfig() (*tls.Config, error) {
	err := c.Prepare()
	if err != nil {
		return nil, err
	}

	settings, err := loadTLS(c.TLS)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()

	authorized := make(map[string]bool, len(c.Clients))

	if c.TLS.CA == "" {
		err = loadTrustedClients(c.TrustedClients, pool, authorized)
	} else {
		if c.TrustedClients != "" {
			return nil, errors.New("trusted_clients cannot be combined with tls.ca")
		}

		if len(c.Clients) == 0 {
			return nil, errors.New("at least one slave certificate must be individually authorized")
		}

		for name, fingerprint := range c.Clients {
			fingerprint = strings.ToLower(fingerprint)
			decoded, decodeErr := hex.DecodeString(fingerprint)

			if decodeErr != nil || len(decoded) != sha256.Size || name == "" || authorized[fingerprint] {
				return nil, fmt.Errorf("invalid or duplicate certificate fingerprint for %q", name)
			}

			authorized[fingerprint] = true
		}

		err = loadTrustFile(c.TLS.CA, pool, nil)
	}

	if err != nil {
		return nil, err
	}

	settings.ClientAuth = tls.RequireAndVerifyClientCert
	settings.ClientCAs = pool

	settings.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 || !authorized[Fingerprint(state.PeerCertificates[0])] {
			return errors.New("slave certificate is not authorized")
		}

		if state.NegotiatedProtocol != ProtocolName {
			return errors.New("replication protocol negotiation failed")
		}

		return nil
	}

	return settings, nil
}

func (c ClientConfig) TLSConfig() (*tls.Config, error) {
	err := c.Prepare()
	if err != nil {
		return nil, err
	}

	if c.ServerName == "" {
		return nil, errors.New("verified master server_name is required")
	}

	settings, err := loadTLS(c.TLS)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()

	var authorized map[string]bool

	if c.TLS.CA == "" {
		authorized = make(map[string]bool, 1)

		err = loadTrustFile(c.TrustedMaster, pool, authorized)
	} else {
		if c.TrustedMaster != "" {
			return nil, errors.New("trusted_master cannot be combined with tls.ca")
		}

		err = loadTrustFile(c.TLS.CA, pool, nil)
	}

	if err != nil {
		if c.TLS.CA == "" {
			return nil, fmt.Errorf("copy the master's public certificate to %q: %w", c.TrustedMaster, err)
		}

		return nil, fmt.Errorf("load master CA: %w", err)
	}

	settings.RootCAs = pool
	settings.ServerName = c.ServerName

	settings.VerifyConnection = func(state tls.ConnectionState) error {
		if authorized != nil && (len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 || !authorized[Fingerprint(state.PeerCertificates[0])]) {
			return errors.New("master certificate is not authorized")
		}

		if state.NegotiatedProtocol != ProtocolName {
			return errors.New("replication protocol negotiation failed")
		}

		return nil
	}

	return settings, nil
}

func Fingerprint(certificate *x509.Certificate) string {
	digest := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(digest[:])
}

func loadTLS(files TLSFiles) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(files.Certificate, files.Key)
	if err != nil {
		return nil, err
	}

	settings := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{ProtocolName},
	}

	return settings, nil
}

func loadTrustedClients(directory string, pool *x509.CertPool, authorized map[string]bool) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		extension := strings.ToLower(filepath.Ext(entry.Name()))
		if entry.IsDir() || (extension != ".crt" && extension != ".pem") {
			continue
		}

		err = loadTrustFile(filepath.Join(directory, entry.Name()), pool, authorized)
		if err != nil {
			return err
		}
	}

	return nil
}

func loadTrustFile(path string, pool *x509.CertPool, authorized map[string]bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	count := 0

	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			if len(bytes.TrimSpace(data)) != 0 {
				return fmt.Errorf("invalid certificate PEM in %q", path)
			}

			break
		}

		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("expected only public certificates in %q", path)
		}

		certificate, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return fmt.Errorf("parse certificate in %q: %w", path, parseErr)
		}

		pool.AddCert(certificate)

		if authorized != nil {
			authorized[Fingerprint(certificate)] = true
		}

		count++
		data = rest
	}

	if count == 0 {
		return fmt.Errorf("no certificates in %q", path)
	}

	return nil
}
