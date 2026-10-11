package main

import (
	"errors"
	"net"
	"os"

	"plat/internal/dnsserver"
	"plat/internal/replication"
	"plat/internal/storage"

	"github.com/goccy/go-yaml"
)

type HTTPConfig struct {
	Address string `yaml:"address"`
}

type Config struct {
	Master replication.ClientConfig `yaml:"master"`
	DNS    dnsserver.Config         `yaml:"dns"`
	HTTP   HTTPConfig               `yaml:"http"`
}

func (c *Config) Prepare() error {
	return c.Master.Prepare()
}

func (c *Config) Validate() error {
	if c.Master.Address == "" {
		return errors.New("set master.address to the master's existing http:// or https:// base URL in slave.yml, then restart")
	}

	err := c.Master.ValidateAddress()
	if err != nil {
		return err
	}

	if c.DNS.Port < 1 || c.DNS.Port > 65535 || !c.DNS.Enabled {
		return errors.New("enabled DNS port (1-65535) is required")
	}

	if c.HTTP.Address == "" {
		return errors.New("http.address is required")
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

func LoadConfig() (Config, error) {
	config := Config{
		Master: replication.ClientConfig{
			TLS:           replication.TLSFiles{Certificate: "data/certs/slave.crt", Key: "data/certs/slave.key"},
			TrustedMaster: "data/certs/master.crt",
		},
		DNS: dnsserver.Config{
			Enabled:       true,
			Port:          53,
			FallbackIP:    "9.9.9.9",
			FallbackHTTPS: "https://dns.quad9.net/dns-query",
		},
		HTTP: HTTPConfig{Address: ":8080"},
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

	// Apply identity path defaults together in Prepare so partial overrides fail validation.
	config.Master = replication.ClientConfig{}

	err = yaml.UnmarshalWithOptions(data, &config, yaml.Strict())
	if err != nil {
		return Config{}, err
	}

	return config, nil
}
