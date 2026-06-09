package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/goccy/go-yaml"
	"github.com/libdns/cloudflare"
)

type Storage struct {
	mx sync.RWMutex
	fx sync.Mutex

	provider cloudflare.Provider

	zones   []string
	domains map[string][]Record `yaml:"domains"`
}

func LoadStorage(config *Config) (*Storage, error) {
	storage := Storage{
		provider: cloudflare.Provider{
			APIToken: config.Cloudflare.Token,
		},

		domains: make(map[string][]Record),
	}

	file, err := OpenFileForReading("records.yml")
	if err != nil {
		if os.IsNotExist(err) {
			return &storage, nil
		}

		return nil, err
	}

	defer file.Close()

	err = yaml.NewDecoder(file).Decode(&storage.domains)
	if err != nil {
		return nil, err
	}

	return &storage, nil
}

func (s *Storage) GetZones() []string {
	s.mx.RLock()
	defer s.mx.RUnlock()

	return s.zones
}

func (s *Storage) GetRecords(domain string) ([]Record, error) {
	s.mx.RLock()
	defer s.mx.RUnlock()

	list, exists := s.domains[domain]
	if !exists {
		return nil, fmt.Errorf("unknown domain %q", domain)
	}

	return list, nil
}

func (s *Storage) GetRecord(domain string, recordName string) (Record, error) {
	s.mx.RLock()
	defer s.mx.RUnlock()

	list, exists := s.domains[domain]
	if !exists {
		return Record{}, fmt.Errorf("unknown domain %q", domain)
	}

	for _, entry := range list {
		if entry.Name == recordName {
			return entry, nil
		}
	}

	return Record{}, errors.New("record not found")
}

func (s *Storage) SetRecord(domain string, record Record, override bool) error {
	s.mx.Lock()
	defer s.mx.Unlock()

	list, exists := s.domains[domain]
	if !exists {
		return fmt.Errorf("unknown domain %q", domain)
	}

	for i, entry := range list {
		if entry.Name == record.Name {
			if !override {
				return errors.New("record already exists")
			}

			list[i] = record

			return nil
		}
	}

	s.domains[domain] = append(list, record)

	return nil
}

func (s *Storage) UnsetRecord(domain string, name string) error {
	s.mx.Lock()
	defer s.mx.Unlock()

	list, exists := s.domains[domain]
	if !exists {
		return fmt.Errorf("unknown domain %q", domain)
	}

	for i, entry := range list {
		if entry.Name == name {
			s.domains[domain] = append(list[:i], list[i+1:]...)

			return nil
		}
	}

	return errors.New("record not found")
}

func (s *Storage) Store() error {
	s.fx.Lock()
	defer s.fx.Unlock()

	file, err := OpenFileForWriting("records.tmp")
	if err != nil {
		return err
	}

	defer file.Close()
	defer os.Remove("records.tmp")

	s.mx.RLock()
	err = yaml.NewEncoder(file).Encode(s.domains)
	s.mx.RUnlock()

	if err != nil {
		return err
	}

	file.Close()

	return os.Rename("records.tmp", "records.yml")
}

func (s *Storage) FetchZones(config *Config) error {
	zones, err := s.provider.ListZones(context.Background())
	if err != nil {
		return err
	}

	s.mx.Lock()
	defer s.mx.Unlock()

	s.zones = make([]string, 0, len(zones))

	for _, zone := range zones {
		domain := zone.Name

		s.zones = append(s.zones, domain)

		if _, ok := s.domains[domain]; !ok {
			s.domains[domain] = make([]Record, 0)
		}
	}

	return nil
}

func (s *Storage) Fetch(config *Config, domain string, override bool) error {
	records, err := s.provider.GetRecords(context.Background(), domain)
	if err != nil {
		return err
	}

	for _, record := range records {
		s.SetRecord(domain, FromLibdns(record), override)
	}

	return nil
}
