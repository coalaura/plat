package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/coalaura/etch"
	"github.com/coalaura/tape"
	"github.com/goccy/go-yaml"
	"github.com/miekg/dns"
)

type Storage struct {
	mx  sync.RWMutex
	fx  sync.Mutex
	dmx sync.RWMutex

	client *CloudflareClient

	zones       map[string]*Zone
	dyndnsUsers map[string]*DynDNSUser
}

var (
	errInvalidZoneName   = errors.New("invalid zone name")
	errZoneExists        = errors.New("zone already exists")
	errLocalZoneNotFound = errors.New("local zone not found")
	errZoneAssigned      = errors.New("remove DynDNS assignments before deleting this zone")
)

func LoadStorage(config *Config) (*Storage, error) {
	storage := Storage{
		zones:       make(map[string]*Zone),
		dyndnsUsers: make(map[string]*DynDNSUser),
	}

	if config.Cloudflare.Token != "" {
		storage.client = NewCloudflareClient(config.Cloudflare.Token)
	}

	file, err := OpenFileForReading("records.yml")
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
	} else {
		defer file.Close()

		err = yaml.NewDecoder(file).Decode(&storage.zones)
		if err != nil {
			return nil, err
		}
	}

	err = storage.loadDynDNS()
	if err != nil {
		return nil, err
	}

	return &storage, nil
}

func (s *Storage) CreateZone(name string) (*Zone, error) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if !validDNSName(name) {
		return nil, errInvalidZoneName
	}

	var random [16]byte

	_, err := rand.Read(random[:])
	if err != nil {
		return nil, err
	}

	zone := &Zone{
		ID:      "local-" + hex.EncodeToString(random[:]),
		Name:    name,
		Records: make(map[string]*Record),
	}

	s.mx.Lock()

	for _, existing := range s.zones {
		if strings.EqualFold(existing.Name, name) {
			s.mx.Unlock()

			return nil, errZoneExists
		}
	}

	s.zones[zone.ID] = zone
	s.mx.Unlock()

	err = s.Store()
	if err != nil {
		s.mx.Lock()
		delete(s.zones, zone.ID)
		s.mx.Unlock()

		return nil, err
	}

	return zone, nil
}

func (s *Storage) DeleteZone(zoneId string) error {
	s.dmx.RLock()
	defer s.dmx.RUnlock()

	for _, user := range s.dyndnsUsers {
		for _, assignment := range user.Records {
			if assignment.Zone == zoneId {
				return errZoneAssigned
			}
		}
	}

	s.mx.Lock()

	zone, exists := s.zones[zoneId]
	if !exists || !zone.IsLocal() {
		s.mx.Unlock()

		return errLocalZoneNotFound
	}

	delete(s.zones, zoneId)
	s.mx.Unlock()

	err := s.Store()
	if err != nil {
		s.mx.Lock()
		s.zones[zoneId] = zone
		s.mx.Unlock()
	}

	return err
}

func (s *Storage) GetZones() map[string]string {
	s.mx.RLock()
	defer s.mx.RUnlock()

	zones := make(map[string]string, len(s.zones))

	for id, zone := range s.zones {
		zones[id] = zone.Name
	}

	return zones
}

func (s *Storage) GetRecords(zoneId string) ([]Record, error) {
	s.mx.RLock()

	zone, exists := s.zones[zoneId]
	if !exists {
		s.mx.RUnlock()

		return nil, fmt.Errorf("unknown zone %q", zoneId)
	}

	zone.mx.RLock()
	defer zone.mx.RUnlock()

	s.mx.RUnlock()

	return zone.RecordsList(), nil
}

func (s *Storage) GetRecord(zoneId string, id string) (*Record, error) {
	s.mx.RLock()

	zone, exists := s.zones[zoneId]
	if !exists {
		s.mx.RUnlock()

		return nil, fmt.Errorf("unknown zone %q", zoneId)
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

func (s *Storage) SetRecord(zoneId string, record *Record) error {
	s.mx.RLock()

	zone, exists := s.zones[zoneId]
	if !exists {
		s.mx.RUnlock()

		return fmt.Errorf("unknown zone %q", zoneId)
	}

	zone.mx.Lock()
	defer zone.mx.Unlock()

	s.mx.RUnlock()

	return s.setRecordLocked(zoneId, zone, record)
}

func (s *Storage) setRecordLocked(zoneId string, zone *Zone, record *Record) error {
	err := record.Update(zone.Name)
	if err != nil {
		return err
	}

	if s.client != nil && !zone.IsLocal() {
		if record.ID == "" || isLocalZoneID(record.ID) {
			previousID := record.ID

			err = s.client.CreateRecord(context.Background(), zoneId, record)
			if err == nil && previousID != "" {
				delete(zone.Records, previousID)
			}
		} else {
			err = s.client.UpdateRecord(context.Background(), zoneId, record)
		}

		if err != nil {
			return err
		}
	} else if record.ID == "" {
		var random [16]byte

		_, err = rand.Read(random[:])
		if err != nil {
			return err
		}

		record.ID = "local-" + hex.EncodeToString(random[:])
	} else if _, exists := zone.Records[record.ID]; !exists {
		return errors.New("record not found")
	}

	zone.Records[record.ID] = record

	return nil
}

func (s *Storage) UnsetRecord(zoneId, recordId string) error {
	s.mx.RLock()

	zone, exists := s.zones[zoneId]
	if !exists {
		s.mx.RUnlock()

		return fmt.Errorf("unknown zone %q", zoneId)
	}

	zone.mx.Lock()
	defer zone.mx.Unlock()

	s.mx.RUnlock()

	if _, exists := zone.Records[recordId]; !exists {
		return errors.New("record not found")
	}

	if s.client != nil && !zone.IsLocal() && !isLocalZoneID(recordId) {
		err := s.client.DeleteRecord(context.Background(), zoneId, recordId)
		if err != nil {
			return err
		}
	}

	delete(zone.Records, recordId)

	return nil
}

func (s *Storage) FetchZones() error {
	if s.client == nil {
		return errors.New("cloudflare is not configured")
	}

	zones, err := s.client.ListZones(context.Background())
	if err != nil {
		return err
	}

	s.mx.Lock()

	localNames := make(map[string]struct{}, len(s.zones))

	for _, existing := range s.zones {
		if existing.IsLocal() {
			localNames[strings.ToLower(existing.Name)] = struct{}{}
		}
	}

	for _, zone := range zones {
		if _, exists := localNames[strings.ToLower(zone.Name)]; exists {
			continue
		}

		exists, ok := s.zones[zone.ID]
		if ok {
			exists.mx.Lock()
			exists.Name = zone.Name
			exists.mx.Unlock()
		} else {
			s.zones[zone.ID] = zone
		}
	}

	s.mx.Unlock()

	return s.Store()
}

func (s *Storage) FetchRecords(zoneId string) error {
	if s.client == nil {
		return errors.New("cloudflare is not configured")
	}

	s.mx.RLock()

	zone, exists := s.zones[zoneId]
	if !exists {
		s.mx.RUnlock()

		return fmt.Errorf("unknown zone %q", zoneId)
	}

	if zone.IsLocal() {
		s.mx.RUnlock()

		return errors.New("local zones cannot be synced from Cloudflare")
	}

	zone.mx.Lock()
	s.mx.RUnlock()

	records, err := s.client.GetRecords(context.Background(), zone.ID, zone.Name)
	if err != nil {
		zone.mx.Unlock()

		return err
	}

	for _, record := range records {
		record.Update(zone.Name)

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

	snap := make(map[string]zoneData, len(s.zones))
	comments := make(yaml.CommentMap, len(s.zones))

	ids := slices.Sorted(maps.Keys(s.zones))

	var buf tape.Buffer

	for _, id := range ids {
		zone := s.zones[id]

		zone.mx.RLock()
		data := zone.ZoneData()
		zone.mx.RUnlock()

		snap[id] = data

		buf.Reset()
		buf.Grow(len(id) + 4)

		buf.WriteString("$.'")
		etch.Replace(&buf, id, "'", `\'`, -1)
		buf.WriteByte('\'')

		zonePath := buf.String()

		comments[zonePath] = []*yaml.Comment{
			yaml.HeadComment(" " + data.Name),
			yaml.FootComment(),
		}

		for i, rec := range data.Records {
			buf.Reset()
			buf.Grow(len(zonePath) + 24)

			buf.WriteString(zonePath)
			buf.WriteString(".records[")
			buf.WriteInt(int64(i), 10)
			buf.WriteByte(']')

			comments[buf.String()] = []*yaml.Comment{
				yaml.HeadComment(" " + rec.GetFullName()),
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

func (s *Storage) LookupLocal(qName string, qType string) ([]dns.RR, bool, bool) {
	s.mx.RLock()
	defer s.mx.RUnlock()

	var (
		answers     []dns.RR
		nameExists  bool
		zoneMatched bool
	)

	for _, zone := range s.zones {
		zone.mx.RLock()

		if !zone.MatchesName(qName) {
			zone.mx.RUnlock()

			continue
		}

		zoneMatched = true

		for _, rec := range zone.Records {
			if rec.MatchesName(qName) {
				nameExists = true

				if rec.MatchesType(qType) {
					rr := rec.GetRR()

					if rr != nil {
						answers = append(answers, rr)
					}
				}
			}
		}

		zone.mx.RUnlock()
	}

	return answers, nameExists, zoneMatched
}
