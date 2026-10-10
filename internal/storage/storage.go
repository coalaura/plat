package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-yaml"
)

const RecordsFile = "data/records.yml"

type Storage struct {
	mx          sync.RWMutex
	commitMu    sync.Mutex
	fx          sync.Mutex
	dmx         sync.RWMutex
	client      *CloudflareClient
	logDB       *sql.DB
	zones       map[string]*Zone
	dyndnsUsers map[string]*DynDNSUser
	epoch       string
	sequence    uint64
	subscribers map[*Subscription]struct{}
	path        string
	readOnly    bool
	ready       bool
	persist     func(string, []byte) error
}

var (
	errInvalidZoneName   = errors.New("invalid zone name")
	errZoneExists        = errors.New("zone already exists")
	errLocalZoneNotFound = errors.New("local zone not found")
	errZoneAssigned      = errors.New("remove DynDNS assignments before deleting this zone")
	ErrReadOnly          = errors.New("slave storage is read-only")
)

func (s *Storage) CreateZone(name string) (*Zone, error) {
	s.commitMu.Lock()
	defer s.commitMu.Unlock()

	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if !validDNSName(name) {
		return nil, errInvalidZoneName
	}

	for _, existing := range s.zones {
		if strings.EqualFold(existing.Name, name) {
			return nil, errZoneExists
		}
	}

	zone := &Zone{ID: "local-" + randomID(), Name: name, Records: make(map[string]*Record)}

	err := s.commitZone(zone.ID, zone, Event{Kind: "replace"})
	if err != nil {
		return nil, err
	}

	return cloneZone(zone), nil
}

func (s *Storage) DeleteZone(zoneID string) error {
	s.commitMu.Lock()
	defer s.commitMu.Unlock()

	s.dmx.RLock()
	defer s.dmx.RUnlock()

	for _, user := range s.dyndnsUsers {
		for _, assignment := range user.Records {
			if assignment.Zone == zoneID {
				return errZoneAssigned
			}
		}
	}

	zone := s.zones[zoneID]
	if zone == nil || !zone.IsLocal() {
		return errLocalZoneNotFound
	}

	if zone.dnssec != nil && zone.dnssec.Enabled {
		return errors.New("disable DNSSEC after removing the parent DS before deleting this zone")
	}

	return s.commitZone(zoneID, nil, Event{Kind: "delete-zone"})
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

func (s *Storage) GetRecords(zoneID string) ([]Record, error) {
	s.mx.RLock()
	zone := s.zones[zoneID]
	s.mx.RUnlock()

	if zone == nil {
		return nil, fmt.Errorf("unknown zone %q", zoneID)
	}

	return zone.RecordsList(), nil
}

func (s *Storage) GetRecord(zoneID, id string) (*Record, error) {
	s.mx.RLock()
	zone := s.zones[zoneID]
	s.mx.RUnlock()

	if zone == nil || zone.Records[id] == nil {
		return nil, errors.New("record not found")
	}

	return new(*zone.Records[id]), nil
}

func (s *Storage) SetRecord(zoneID string, record *Record) error {
	s.commitMu.Lock()
	defer s.commitMu.Unlock()

	zone := cloneZone(s.zones[zoneID])
	if zone == nil {
		return fmt.Errorf("unknown zone %q", zoneID)
	}

	return s.setRecordLocked(zoneID, zone, record)
}

func (s *Storage) setRecordLocked(zoneID string, zone *Zone, record *Record) error {
	if s.readOnly {
		return ErrReadOnly
	}

	input := record
	record = new(*record)

	err := record.Update(zone.Name)
	if err != nil {
		return err
	}

	err = zone.validateSignedChange(record, "")
	if err != nil {
		return err
	}

	kind := "upsert"

	if s.client != nil && !zone.IsLocal() {
		if record.ID == "" || isLocalZoneID(record.ID) {
			previousID := record.ID
			err = s.client.CreateRecord(context.Background(), zoneID, record)

			if err == nil && previousID != "" {
				delete(zone.Records, previousID)
				kind = "replace"
			}
		} else {
			err = s.client.UpdateRecord(context.Background(), zoneID, record)
		}

		if err != nil {
			return err
		}
	} else if record.ID == "" {
		record.ID = "local-" + randomID()
	} else if _, exists := zone.Records[record.ID]; !exists {
		return errors.New("record not found")
	}

	zone.Records[record.ID] = record
	zone.serial = zone.nextSerial()
	zone.signed = nil

	err = s.commitZone(zoneID, zone, Event{Kind: kind, Record: record})
	if err != nil {
		return err
	}

	*input = *record

	return nil
}

func (s *Storage) UnsetRecord(zoneID, recordID string) error {
	s.commitMu.Lock()
	defer s.commitMu.Unlock()

	if s.readOnly {
		return ErrReadOnly
	}

	zone := cloneZone(s.zones[zoneID])
	if zone == nil || zone.Records[recordID] == nil {
		return errors.New("record not found")
	}

	err := zone.validateSignedChange(nil, recordID)
	if err != nil {
		return err
	}

	if s.client != nil && !zone.IsLocal() && !isLocalZoneID(recordID) {
		err = s.client.DeleteRecord(context.Background(), zoneID, recordID)
		if err != nil {
			return err
		}
	}

	delete(zone.Records, recordID)
	zone.serial = zone.nextSerial()
	zone.signed = nil

	return s.commitZone(zoneID, zone, Event{Kind: "delete-record", RecordID: recordID})
}

func (s *Storage) FetchZones() error {
	s.commitMu.Lock()
	defer s.commitMu.Unlock()

	if s.client == nil {
		return errors.New("cloudflare is not configured")
	}

	zones, err := s.client.ListZones(context.Background())
	if err != nil {
		return err
	}

	for _, zone := range zones {
		conflict := false

		for _, existing := range s.zones {
			if existing.IsLocal() && strings.EqualFold(existing.Name, zone.Name) {
				conflict = true

				break
			}
		}

		if conflict {
			continue
		}

		existing := s.zones[zone.ID]
		if existing != nil {
			if existing.Name == zone.Name {
				continue
			}

			updated := cloneZone(existing)
			updated.Name = zone.Name
			zone = updated
		}

		err = s.commitZone(zone.ID, zone, Event{Kind: "replace"})
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Storage) FetchRecords(zoneID string) error {
	s.commitMu.Lock()
	defer s.commitMu.Unlock()

	if s.client == nil {
		return errors.New("cloudflare is not configured")
	}

	zone := cloneZone(s.zones[zoneID])
	if zone == nil || zone.IsLocal() {
		return errors.New("unknown or local Cloudflare zone")
	}

	records, err := s.client.GetRecords(context.Background(), zone.ID, zone.Name)
	if err != nil {
		return err
	}

	zone.Records = make(map[string]*Record, len(records))

	for _, record := range records {
		err = record.Update(zone.Name)
		if err != nil {
			return err
		}

		zone.Records[record.ID] = record
	}

	zone.serial = zone.nextSerial()
	if zone.dnssec != nil && zone.dnssec.Enabled && zone.dnssec.Provider == "plat" {
		_, err = buildSignedZone(zone.Name, zone.Records, zone.dnssec, zone.serial, time.Now())
		if err != nil {
			return err
		}
	}

	return s.commitZone(zoneID, zone, Event{Kind: "replace"})
}

// Store remains available to management callers; every mutation is already durable.
func (s *Storage) Store() error {
	return nil
}

func LoadStorage(token string) (*Storage, error) {
	storage, err := LoadMaster(RecordsFile)
	if err != nil {
		return nil, err
	}

	if token != "" {
		storage.client = NewCloudflareClient(token)
	}

	err = storage.LoadDynDNS()
	if err != nil {
		return nil, err
	}

	storage.logDB, err = OpenDynDNSLogDatabase()
	if err != nil {
		return nil, err
	}

	return storage, nil
}

func LoadMaster(path string) (*Storage, error) {
	storage := NewStorage(path)

	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	if len(data) > 0 {
		err = yaml.Unmarshal(data, &storage.zones)
		if err != nil {
			return nil, err
		}
	}

	if storage.zones == nil {
		storage.zones = make(map[string]*Zone)
	}

	err = storage.LoadDNSSEC()
	if err != nil {
		return nil, err
	}

	names := make(map[string]bool, len(storage.zones))

	for id, zone := range storage.zones {
		if zone == nil || zone.ID != id || names[zone.Name] {
			return nil, errors.New("invalid or duplicate saved zone")
		}

		names[zone.Name] = true

		err = zone.prepareState()
		if err != nil {
			return nil, err
		}
	}

	return storage, nil
}

func NewStorage(path string) *Storage {
	return &Storage{
		zones:       make(map[string]*Zone),
		dyndnsUsers: make(map[string]*DynDNSUser),
		subscribers: make(map[*Subscription]struct{}),
		epoch:       randomID(),
		path:        path,
		ready:       true,
		persist:     WriteAtomic,
	}
}

func cloneZone(zone *Zone) *Zone {
	if zone == nil {
		return nil
	}

	return &Zone{
		ID:      zone.ID,
		Name:    zone.Name,
		Records: maps.Clone(zone.Records),
		dnssec:  zone.dnssec,
		serial:  zone.serial,
	}
}

func randomID() string {
	var random [16]byte

	rand.Read(random[:])

	return hex.EncodeToString(random[:])
}
