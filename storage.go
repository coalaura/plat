package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/goccy/go-yaml"
	"github.com/libdns/cloudflare"
)

type Storage struct {
	mx sync.RWMutex
	fx sync.Mutex

	provider cloudflare.Provider

	zoneNames []string
	zoneMap   map[string]*Zone
}

func LoadStorage(config *Config) (*Storage, error) {
	storage := Storage{
		provider: cloudflare.Provider{
			APIToken: config.Cloudflare.Token,
		},

		zoneMap: make(map[string]*Zone),
	}

	file, err := OpenFileForReading("records.yml")
	if err != nil {
		if os.IsNotExist(err) {
			return &storage, nil
		}

		return nil, err
	}

	defer file.Close()

	err = yaml.NewDecoder(file).Decode(&storage.zoneMap)
	if err != nil {
		return nil, err
	}

	return &storage, nil
}

func (s *Storage) GetZoneNames() []string {
	s.mx.RLock()
	defer s.mx.RUnlock()

	return s.zoneNames
}

func (s *Storage) GetRecords(zoneName string) ([]Record, error) {
	s.mx.RLock()

	zone, exists := s.zoneMap[zoneName]
	if !exists {
		s.mx.RUnlock()

		return nil, fmt.Errorf("unknown zone %q", zoneName)
	}

	zone.mx.RLock()
	defer zone.mx.RUnlock()

	s.mx.RUnlock()

	return zone.RecordsList(), nil
}

func (s *Storage) GetRecord(zoneName string, recordName string) (Record, error) {
	s.mx.RLock()

	zone, exists := s.zoneMap[zoneName]
	if !exists {
		s.mx.RUnlock()

		return Record{}, fmt.Errorf("unknown zone %q", zoneName)
	}

	zone.mx.RLock()
	defer zone.mx.RUnlock()

	s.mx.RUnlock()

	rec, exists := zone.Records[recordName]
	if !exists {
		return Record{}, errors.New("record not found")
	}

	return rec, nil
}

func (s *Storage) SetRecord(zoneName string, record Record, override bool) error {
	s.mx.RLock()

	zone, exists := s.zoneMap[zoneName]
	if !exists {
		s.mx.RUnlock()

		return fmt.Errorf("unknown zone %q", zoneName)
	}

	zone.mx.Lock()
	defer zone.mx.Unlock()

	s.mx.RUnlock()

	if !override {
		if _, exists := zone.Records[record.Name]; exists {
			return errors.New("record already exists")
		}
	}

	zone.Records[record.Name] = record

	return nil
}

func (s *Storage) UnsetRecord(zoneName string, name string) error {
	s.mx.RLock()

	zone, exists := s.zoneMap[zoneName]
	if !exists {
		s.mx.RUnlock()

		return fmt.Errorf("unknown zone %q", zoneName)
	}

	zone.mx.Lock()
	defer zone.mx.Unlock()

	s.mx.RUnlock()

	if _, exists := zone.Records[name]; !exists {
		return errors.New("record not found")
	}

	delete(zone.Records, name)

	return nil
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

	snap := make(map[string]*Zone, len(s.zoneMap))

	for name, zone := range s.zoneMap {
		zone.mx.RLock()

		recordsCopy := make(map[string]Record, len(zone.Records))
		maps.Copy(recordsCopy, zone.Records)

		snap[name] = &Zone{
			Name:    zone.Name,
			Records: recordsCopy,
		}

		zone.mx.RUnlock()
	}

	s.mx.RUnlock()

	err = yaml.NewEncoder(file).Encode(snap)
	if err != nil {
		return err
	}

	file.Close()

	return os.Rename("records.tmp", "records.yml")
}

func (s *Storage) FetchZones() error {
	zones, err := s.provider.ListZones(context.Background())
	if err != nil {
		return err
	}

	s.mx.Lock()
	defer s.mx.Unlock()

	s.zoneNames = make([]string, 0, len(zones))

	for name, zone := range s.zoneMap {
		zone.mx.RLock()
		empty := len(zone.Records) == 0
		zone.mx.RUnlock()

		if empty {
			delete(s.zoneMap, name)
		}
	}

	for _, zone := range zones {
		s.zoneNames = append(s.zoneNames, zone.Name)
	}

	sort.Strings(s.zoneNames)

	for _, name := range s.zoneNames {
		if _, ok := s.zoneMap[name]; ok {
			continue
		}

		s.zoneMap[name] = &Zone{
			Name:    strings.TrimSuffix(name, "."),
			Records: make(map[string]Record),
		}
	}

	return nil
}

func (s *Storage) FetchAllRecords(override bool) error {
	s.mx.RLock()
	names := s.zoneNames
	s.mx.RUnlock()

	for i, name := range names {
		log.Printf("Fetching %d/%d...\r", i+1, len(names))

		err := s.FetchRecords(name, override)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Storage) FetchRecords(zoneName string, override bool) error {
	records, err := s.provider.GetRecords(context.Background(), zoneName)
	if err != nil {
		return err
	}

	s.mx.RLock()

	zone, exists := s.zoneMap[zoneName]
	if !exists {
		s.mx.RUnlock()

		return fmt.Errorf("unknown zone %q", zoneName)
	}

	zone.mx.Lock()
	defer zone.mx.Unlock()

	s.mx.RUnlock()

	for _, lr := range records {
		record := FromLibdns(lr)

		if !override {
			if _, exists := zone.Records[record.Name]; exists {
				continue
			}
		}

		zone.Records[record.Name] = record
	}

	return nil
}
