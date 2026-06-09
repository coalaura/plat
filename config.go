package main

import (
	"fmt"
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

type Config struct {
	Debug bool `yaml:"debug"`

	Server     ConfigServer     `yaml:"server"`
	Cloudflare ConfigCloudflare `yaml:"cloudflare"`
}

func NewDefaultConfig() Config {
	return Config{
		Server: ConfigServer{
			Port:  8080,
			Token: "p4$$w0rd",
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

	if c.Cloudflare.Token == "" {
		return fmt.Errorf("cloudflare.token is empty")
	}

	return nil
}

func (c *Config) Addr() string {
	return fmt.Sprintf(":%d", c.Server.Port)
}

func (e *Config) Store() error {
	def := NewDefaultConfig()

	comments := yaml.CommentMap{
		"$.debug": {yaml.HeadComment(" enable verbose logging and diagnostics")},

		"$.server.port":  {yaml.HeadComment(fmt.Sprintf(" port to run plat on (default: %v)", def.Server.Port))},
		"$.server.token": {yaml.HeadComment(fmt.Sprintf(" token for authentication, (default: %q)", def.Server.Token))},

		"$.cloudflare.token": {yaml.HeadComment(fmt.Sprintf(" cloudflare api token (default: %q)", def.Cloudflare.Token))},
	}

	file, err := OpenFileForWriting("config.yml")
	if err != nil {
		return err
	}

	defer file.Close()

	return yaml.NewEncoder(file, yaml.WithComment(comments)).Encode(e)
}
