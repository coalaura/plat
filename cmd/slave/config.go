package main

import (
	"crypto/x509"
	"errors"
	"net"
	"os"

	"plat/internal/dnsserver"
	"plat/internal/replication"
	"plat/internal/storage"

	"github.com/goccy/go-yaml"
)

type HTTPSConfig struct {
	Address     string   `yaml:"address"`
	Certificate string   `yaml:"certificate"`
	Key         string   `yaml:"key"`
	Names       []string `yaml:"names,omitempty"`
}

type Config struct {
	Master     replication.ClientConfig `yaml:"master"`
	Checkpoint string                   `yaml:"checkpoint"`
	DNS        dnsserver.Config         `yaml:"dns"`
	HTTPS      HTTPSConfig              `yaml:"https"`
}

func (c *Config) Prepare() error {
	err := c.Master.Prepare()
	if err != nil {
		return err
	}

	names := c.HTTPS.Names
	if len(names) == 0 {
		hostname, hostnameErr := os.Hostname()
		if hostnameErr != nil {
			return hostnameErr
		}

		names = []string{hostname, "localhost", "127.0.0.1", "::1"}
	}

	files := replication.TLSFiles{Certificate: c.HTTPS.Certificate, Key: c.HTTPS.Key}
	return files.EnsureCertificate(names, x509.ExtKeyUsageServerAuth)
}

func (c *Config) Validate() error {
	if c.Master.Address == "" {
		return errors.New("set master.address to the master's existing http:// or https:// base URL in slave.yml and exchange the generated public certificates, then restart")
	}

	err := c.Master.ValidateAddress()
	if err != nil {
		return err
	}

	if c.Checkpoint == "" || c.DNS.Port < 1 || c.DNS.Port > 65535 || !c.DNS.Enabled {
		return errors.New("checkpoint path and enabled DNS port (1-65535) are required")
	}

	if c.HTTPS.Address == "" {
		return errors.New("https.address is required")
	}

	if c.DNS.FallbackIP != "" {
		if net.ParseIP(c.DNS.FallbackIP) != nil {
			c.DNS.FallbackIP = net.JoinHostPort(c.DNS.FallbackIP, "53")
		}

		_, err := net.ResolveUDPAddr("udp", c.DNS.FallbackIP)
		if err != nil {
			return err
		}
	}

	return nil
}

func loadConfig() (Config, error) {
	config := Config{
		Master: replication.ClientConfig{
			ServerName:    "plat-master",
			TLS:           replication.TLSFiles{Certificate: "certs/slave.crt", Key: "certs/slave.key"},
			TrustedMaster: "certs/master.crt",
		},
		Checkpoint: "data/slave.json",
		DNS:        dnsserver.Config{Enabled: true, Port: 53},
		HTTPS:      HTTPSConfig{Address: ":443", Certificate: "certs/doh.crt", Key: "certs/doh.key"},
	}

	data, err := os.ReadFile("slave.yml")
	if errors.Is(err, os.ErrNotExist) {
		data, err = yaml.Marshal(config)
		if err != nil {
			return Config{}, err
		}

		err = storage.WriteExclusive("slave.yml", data)
		return config, err
	}

	if err != nil {
		return Config{}, err
	}

	// Leave replication defaults to Prepare so existing CA configurations do not
	// inherit automatic-mode trust settings from the first-run template.
	config.Master = replication.ClientConfig{}

	err = yaml.UnmarshalWithOptions(data, &config, yaml.Strict())
	if err != nil {
		return Config{}, err
	}

	return config, nil
}
