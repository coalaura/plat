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

	"plat/internal/storage"
)

type TLSFiles struct {
	Certificate string `yaml:"certificate"`
	Key         string `yaml:"key"`
}

type MasterConfig struct {
	Enabled        bool     `yaml:"enabled"`
	TLS            TLSFiles `yaml:"tls"`
	TrustedClients string   `yaml:"trusted_clients"`
}

type ClientConfig struct {
	Address       string   `yaml:"address"`
	TLS           TLSFiles `yaml:"tls"`
	TrustedMaster string   `yaml:"trusted_master"`
}

func (c MasterConfig) NewMaster(data *storage.Storage) (*Master, error) {
	err := c.Prepare()
	if err != nil {
		return nil, err
	}

	settings, err := loadTLS(c.TLS)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	authorized := make(map[string]string)

	err = loadTrustedClients(c.TrustedClients, pool, authorized)
	if err != nil {
		return nil, err
	}

	if len(authorized) == 0 {
		log.Printf("No trusted slave certificates in %s; copy slave public certificates there and restart to authorize replication\n", c.TrustedClients)
	}

	settings.ClientAuth = tls.RequireAndVerifyClientCert
	settings.ClientCAs = pool

	settings.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return errors.New("slave certificate is not authorized")
		}

		if _, ok := authorized[Fingerprint(state.PeerCertificates[0])]; !ok {
			return errors.New("slave certificate is not authorized")
		}

		if state.NegotiatedProtocol != ProtocolName {
			return errors.New("replication protocol negotiation failed")
		}

		return nil
	}

	statuses := make(map[string]*health, len(authorized))

	for id, name := range authorized {
		statuses[id] = &health{status: Status{Name: name}}
	}

	master := &Master{
		Storage:  data,
		TLS:      settings,
		statuses: statuses,
	}

	return master, nil
}

func (c ClientConfig) TLSConfig() (*tls.Config, error) {
	err := c.Prepare()
	if err != nil {
		return nil, err
	}

	settings, err := loadTLS(c.TLS)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	authorized := make(map[string]string, 1)

	err = loadTrustFile(c.TrustedMaster, pool, authorized)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("copy the master's public certificate to %q: %w", c.TrustedMaster, err)
	}

	if err != nil {
		return nil, fmt.Errorf("load trusted master certificate %q: %w", c.TrustedMaster, err)
	}

	settings.RootCAs = pool
	settings.ServerName = MasterServerName

	settings.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return errors.New("master certificate is not authorized")
		}

		if _, ok := authorized[Fingerprint(state.PeerCertificates[0])]; !ok {
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

func loadTrustedClients(directory string, pool *x509.CertPool, authorized map[string]string) error {
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

func loadTrustFile(path string, pool *x509.CertPool, authorized map[string]string) error {
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
		authorized[Fingerprint(certificate)] = filepath.Base(path)

		count++
		data = rest
	}

	if count == 0 {
		return fmt.Errorf("no certificates in %q", path)
	}

	return nil
}
