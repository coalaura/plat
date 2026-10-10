package replication

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"plat/internal/storage"
)

const defaultServerName = "plat-master"

func (c *MasterConfig) Prepare() error {
	if c.TLS.CA != "" {
		return nil
	}

	if len(c.Clients) != 0 {
		return errors.New("cluster.clients requires tls.ca; otherwise authorize slaves by copying their certificates into trusted_clients")
	}

	c.TLS.defaults("certs/master.crt", "certs/master.key")

	if c.TrustedClients == "" {
		c.TrustedClients = "certs/slaves"
	}

	err := os.MkdirAll(c.TrustedClients, 0700)
	if err != nil {
		return err
	}

	return c.TLS.EnsureCertificate([]string{defaultServerName}, x509.ExtKeyUsageServerAuth)
}

func (c *ClientConfig) Prepare() error {
	if c.TLS.CA != "" {
		return nil
	}

	c.TLS.defaults("certs/slave.crt", "certs/slave.key")

	if c.ServerName == "" {
		c.ServerName = defaultServerName
	}

	if c.TrustedMaster == "" {
		c.TrustedMaster = "certs/master.crt"
	}

	return c.TLS.EnsureCertificate(nil, x509.ExtKeyUsageClientAuth)
}

// EnsureCertificate creates an identity only when both files are absent. Existing
// identities, including expired or incomplete pairs, are never silently replaced.
func (f TLSFiles) EnsureCertificate(names []string, usage x509.ExtKeyUsage) error {
	if f.Certificate == "" || f.Key == "" || f.Certificate == f.Key {
		return errors.New("distinct certificate and key paths are required")
	}

	certificateExists, err := identityFileExists(f.Certificate)
	if err != nil {
		return err
	}

	keyExists, err := identityFileExists(f.Key)
	if err != nil {
		return err
	}

	if certificateExists != keyExists {
		return fmt.Errorf("incomplete TLS identity: restore the missing file from %q and %q; neither file will be replaced", f.Certificate, f.Key)
	}

	if certificateExists {
		_, err = tls.LoadX509KeyPair(f.Certificate, f.Key)
		return err
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return err
	}

	serialNumber.Add(serialNumber, big.NewInt(1))

	now := time.Now()

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "plat"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
	}

	for _, name := range names {
		address := net.ParseIP(name)
		if address != nil {
			template.IPAddresses = append(template.IPAddresses, address)
		} else if name != "" {
			template.DNSNames = append(template.DNSNames, name)
		}
	}

	certificate, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return err
	}

	key, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}

	// Publish the key first and fail closed after an interrupted pair creation.
	err = storage.WriteExclusive(f.Key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	if err != nil {
		return fmt.Errorf("create TLS key: %w", err)
	}

	err = storage.WriteExclusive(f.Certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}))
	if err != nil {
		return fmt.Errorf("create TLS certificate (key retained at %q): %w", f.Key, err)
	}

	return nil
}

func (f *TLSFiles) defaults(certificate, key string) {
	if f.Certificate == "" && f.Key == "" {
		f.Certificate = certificate
		f.Key = key
	}
}

func identityFileExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}

	return err == nil, err
}
