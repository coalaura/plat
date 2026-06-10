package main

import (
	"fmt"
	"net"
	"os"

	"github.com/goccy/go-yaml"
)

type ConfigServer struct {
	Port  int    `yaml:"port"`
	Token string `yaml:"token"`
}

type ConfigCloudflare struct {
	Token string `yaml:"token"`
}

type ConfigDNS struct {
	Enabled  bool   `yaml:"enabled"`
	Port     int    `yaml:"port"`
	Fallback string `yaml:"fallback"`
}

type Config struct {
	Debug bool `yaml:"debug"`

	Server     ConfigServer     `yaml:"server"`
	Cloudflare ConfigCloudflare `yaml:"cloudflare"`
	DNS        ConfigDNS        `yaml:"dns"`
}

func NewDefaultConfig() Config {
	return Config{
		Server: ConfigServer{
			Port:  8080,
			Token: "p4$$w0rd",
		},
		DNS: ConfigDNS{
			Enabled:  true,
			Port:     531,
			Fallback: "9.9.9.9",
		},
	}
}

func LoadConfig() (*Config, error) {
	cfg := NewDefaultConfig()

	file, err := OpenFileForReading("config.yml")
	if os.IsNotExist(err) {
		file.Close()

		err = cfg.Store()
		if err != nil {
			return nil, err
		}
	} else {
		if err != nil {
			return nil, err
		}

		defer file.Close()

		err = yaml.NewDecoder(file).Decode(&cfg)
		if err != nil {
			return nil, err
		}
	}

	err = cfg.Validate()
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *Config) Validate() error {
	// server
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port must be 1-65535, got %d", c.Server.Port)
	}

	if c.Server.Token == "" {
		return fmt.Errorf("server.token is empty")
	}

	// cloudflare
	if c.Cloudflare.Token == "" {
		return fmt.Errorf("cloudflare.token is empty")
	}

	// dns
	if c.DNS.Enabled {
		if c.DNS.Port < 1 || c.DNS.Port > 65535 {
			return fmt.Errorf("dns.port must be 1-65535, got %d", c.DNS.Port)
		}

		if c.DNS.Fallback != "" {
			ip := net.ParseIP(c.DNS.Fallback)

			if ip.To16() == nil {
				return fmt.Errorf("dns.fallback is an invalid ip address")
			}
		}
	}

	return nil
}

func (c *Config) Addr() string {
	return fmt.Sprintf(":%d", c.Server.Port)
}

func (e *Config) Store() error {
	def := NewDefaultConfig()

	comments := yaml.CommentMap{
		"$.debug": {yaml.HeadComment(" enable verbose logging and diagnostics"), yaml.FootComment()},

		"$.server":       {yaml.FootComment()},
		"$.server.port":  {yaml.HeadComment(fmt.Sprintf(" port to run plat on (default: %v)", def.Server.Port))},
		"$.server.token": {yaml.HeadComment(fmt.Sprintf(" token for authentication, (default: %q)", def.Server.Token))},

		"$.cloudflare":       {yaml.FootComment()},
		"$.cloudflare.token": {yaml.HeadComment(fmt.Sprintf(" cloudflare api token (default: %q)", def.Cloudflare.Token))},

		"$.dns.enabled":  {yaml.HeadComment(fmt.Sprintf(" enable built-in dns server (default: %v)", def.DNS.Enabled))},
		"$.dns.port":     {yaml.HeadComment(fmt.Sprintf(" dns server port (default: %v)", def.DNS.Port))},
		"$.dns.fallback": {yaml.HeadComment(fmt.Sprintf(" optional fallback resolver for unknown queries (default: %q)", def.DNS.Fallback))},
	}

	file, err := OpenFileForWriting("config.yml")
	if err != nil {
		return err
	}

	defer file.Close()

	return yaml.NewEncoder(file, yaml.WithComment(comments)).Encode(e)
}
