package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"sort"
	"sync"

	"github.com/coalaura/etch"
	"github.com/coalaura/tape"
	"github.com/goccy/go-yaml"
)

type Storage struct {
	mx sync.RWMutex
	fx sync.Mutex

	client *CloudflareClient

	zoneNames []string
	zoneMap   map[string]*Zone
}

func LoadStorage(config *Config) (*Storage, error) {
	storage := Storage{
		client: NewCloudflareClient(config.Cloudflare.Token),

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

func (s *Storage) GetZones() map[string]string {
	s.mx.RLock()
	defer s.mx.RUnlock()

	zones := make(map[string]string, len(s.zoneMap))

	for id, zone := range s.zoneMap {
		zones[id] = zone.Name
	}

	return zones
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

func (s *Storage) GetRecord(zoneName string, id string) (*Record, error) {
	s.mx.RLock()

	zone, exists := s.zoneMap[zoneName]
	if !exists {
		s.mx.RUnlock()

		return nil, fmt.Errorf("unknown zone %q", zoneName)
	}

	zone.mx.RLock()
	defer zone.mx.RUnlock()

	s.mx.RUnlock()

	rec, exists := zone.Records[id]
	if !exists {
		return nil, errors.New("record not found")
	}

	return rec, nil
}

func (s *Storage) SetRecord(zoneName string, record *Record, override bool) error {
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
		if _, exists := zone.Records[record.ID]; exists {
			return errors.New("record already exists")
		}
	}

	zone.Records[record.ID] = record

	return nil
}

func (s *Storage) UnsetRecord(zoneName string, id string) error {
	s.mx.RLock()

	zone, exists := s.zoneMap[zoneName]
	if !exists {
		s.mx.RUnlock()

		return fmt.Errorf("unknown zone %q", zoneName)
	}

	zone.mx.Lock()
	defer zone.mx.Unlock()

	s.mx.RUnlock()

	if _, exists := zone.Records[id]; !exists {
		return errors.New("record not found")
	}

	delete(zone.Records, id)

	return nil
}

func (s *Storage) FetchZones() error {
	zones, err := s.client.ListZones(context.Background())
	if err != nil {
		return err
	}

	s.mx.Lock()
	defer s.mx.Unlock()

	for name, zone := range s.zoneMap {
		zone.mx.RLock()
		empty := len(zone.Records) == 0
		zone.mx.RUnlock()

		if empty {
			delete(s.zoneMap, name)
		}
	}

	s.zoneNames = make([]string, 0, len(zones))

	for _, zone := range zones {
		s.zoneNames = append(s.zoneNames, zone.Name)
	}

	sort.Strings(s.zoneNames)

	return nil
}

func (s *Storage) FetchRecords(zoneName string, override bool) error {
	records, err := s.client.GetRecords(context.Background(), zoneName)
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
	s.mx.RUnlock()

	for _, record := range records {
		if !override {
			if _, exists := zone.Records[record.ID]; exists {
				continue
			}
		}

		zone.Records[record.ID] = record
	}

	zone.mx.Unlock()

	return s.Store()
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

	snap := make(map[string]zoneData, len(s.zoneMap))
	comments := make(yaml.CommentMap, len(s.zoneMap))

	names := slices.Sorted(maps.Keys(s.zoneMap))

	var buf tape.Buffer

	for _, name := range names {
		zone := s.zoneMap[name]

		zone.mx.RLock()
		list := zone.RecordsList()
		zone.mx.RUnlock()

		snap[name] = zoneData{
			Name:    zone.Name,
			Records: list,
		}

		buf.Reset()
		buf.Grow(len(name) + 4)

		buf.WriteString("$.'")
		etch.Replace(&buf, name, "'", `\'`, -1)
		buf.WriteByte('\'')

		zonePath := buf.String()

		comments[zonePath] = []*yaml.Comment{
			yaml.HeadComment(" " + zone.Name),
			yaml.FootComment(),
		}

		for i, rec := range list {
			buf.Reset()
			buf.Grow(len(zonePath) + 24)

			buf.WriteString(zonePath)
			buf.WriteString(".records[")
			buf.WriteInt(int64(i), 10)
			buf.WriteByte(']')

			comments[buf.String()] = []*yaml.Comment{
				yaml.HeadComment(" " + rec.FullName(zone.Name)),
			}
		}
	}

	s.mx.RUnlock()

	enc := yaml.NewEncoder(file, yaml.WithComment(comments))

	err = enc.Encode(snap)
	if err != nil {
		return err
	}

	err = enc.Close()
	if err != nil {
		return err
	}

	file.Close()

	return os.Rename("records.tmp", "records.yml")
}
