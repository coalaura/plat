package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/goccy/go-yaml"
)

const (
	StateVersion  = 1
	QueueCapacity = 256
	QueueBytes    = 16 << 20
	MaxZoneBytes  = 64 << 20
	MaxStateBytes = 128 << 20
	MaxZones      = 100000
)

// ZoneState is an immutable authoritative value. Derived RRs and signatures are excluded.
type ZoneState struct {
	Version int           `json:"version"`
	ID      string        `json:"id"`
	Name    string        `json:"name"`
	Serial  uint32        `json:"serial"`
	Records []Record      `json:"records"`
	DNSSEC  *DNSSECConfig `json:"dnssec,omitempty"`
	Hash    string        `json:"-"`
	Size    int           `json:"-"`
}

type Snapshot struct {
	Version  int                   `json:"version"`
	Epoch    string                `json:"epoch"`
	Sequence uint64                `json:"sequence"`
	Zones    map[string]*ZoneState `json:"zones"`
}

type Event struct {
	Epoch    string     `json:"epoch"`
	Sequence uint64     `json:"sequence"`
	Kind     string     `json:"kind"`
	ZoneID   string     `json:"zone_id,omitempty"`
	Hash     string     `json:"hash,omitempty"`
	Serial   uint32     `json:"serial,omitempty"`
	Record   *Record    `json:"record,omitempty"`
	RecordID string     `json:"record_id,omitempty"`
	Zone     *ZoneState `json:"zone,omitempty"`
	size     int64
}

type Subscription struct {
	Events  chan *Event
	Done    chan struct{}
	bytes   atomic.Int64
	storage *Storage
	closed  bool
}

func (s *Storage) Capture() (Snapshot, *Subscription) {
	s.commitMu.Lock()
	defer s.commitMu.Unlock()

	snapshot := s.snapshot()
	subscription := &Subscription{
		Events:  make(chan *Event, QueueCapacity),
		Done:    make(chan struct{}),
		storage: s,
	}
	s.subscribers[subscription] = struct{}{}

	return snapshot, subscription
}

func (s *Storage) Snapshot() Snapshot {
	s.commitMu.Lock()
	defer s.commitMu.Unlock()

	return s.snapshot()
}

func (s *Storage) snapshot() Snapshot {
	states := make(map[string]*ZoneState, len(s.zones))

	for id, zone := range s.zones {
		states[id] = zone.state
	}

	return Snapshot{Version: StateVersion, Epoch: s.epoch, Sequence: s.sequence, Zones: states}
}

// commitZone runs under commitMu, but never holds a query lock during persistence or I/O.
func (s *Storage) commitZone(id string, zone *Zone, event Event) error {
	if s.readOnly {
		return ErrReadOnly
	}

	updated := maps.Clone(s.zones)

	if zone == nil {
		delete(updated, id)
	} else {
		zone = cloneZone(zone)

		err := zone.prepareState()
		if err != nil {
			return err
		}

		updated[id] = zone

		event.Hash = zone.state.Hash
		event.Serial = zone.serial

		if event.Kind == "replace" {
			event.Zone = zone.state
		}
	}

	event.Epoch = s.epoch
	event.Sequence = s.sequence + 1
	event.ZoneID = id

	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}

	event.size = int64(len(encoded))

	data, err := yaml.Marshal(updated)
	if err != nil {
		return err
	}

	err = s.persist(s.path, data)
	if err != nil {
		return err
	}

	s.mx.Lock()
	s.zones = updated
	s.sequence = event.Sequence
	s.mx.Unlock()

	for subscription := range s.subscribers {
		subscription.enqueue(&event)
	}

	return nil
}

func (s *Subscription) Release(event *Event) {
	s.bytes.Add(-event.size)
}

func (s *Subscription) Close() {
	s.storage.commitMu.Lock()
	defer s.storage.commitMu.Unlock()

	s.closeLocked()
}

// Fence is ordered with commits, so it cannot overtake a queued mutation.
func (s *Subscription) Fence() {
	s.storage.commitMu.Lock()
	defer s.storage.commitMu.Unlock()

	event := &Event{Kind: "complete", Epoch: s.storage.epoch, Sequence: s.storage.sequence}
	s.enqueue(event)
}

func (s *Subscription) enqueue(event *Event) {
	if s.closed {
		return
	}

	if s.bytes.Add(event.size) > QueueBytes {
		s.closeLocked()

		return
	}

	select {
	case s.Events <- event:
	default:
		s.closeLocked()
	}
}

func (s *Subscription) closeLocked() {
	if !s.closed {
		s.closed = true
		delete(s.storage.subscribers, s)
		close(s.Done)
	}
}

func (z *Zone) prepareState() error {
	state := &ZoneState{
		Version: StateVersion,
		ID:      z.ID,
		Name:    z.Name,
		Serial:  z.serial,
		Records: z.RecordsList(),
		DNSSEC:  cloneDNSSEC(z.dnssec),
	}

	err := state.validate()
	if err != nil {
		return err
	}

	z.dnssec = state.DNSSEC
	z.state = state
	z.Records = make(map[string]*Record, len(state.Records))

	for index := range state.Records {
		record := &state.Records[index]
		z.Records[record.ID] = record
	}

	return nil
}

func (state *ZoneState) validate() error {
	if state.Version != StateVersion || state.ID == "" || len(state.ID) > 256 || !validDNSName(state.Name) {
		return errors.New("invalid zone state")
	}

	slices.SortFunc(state.Records, func(first, second Record) int {
		return strings.Compare(first.ID, second.ID)
	})

	for index := range state.Records {
		record := &state.Records[index]
		if record.ID == "" || (index > 0 && state.Records[index-1].ID == record.ID) {
			return errors.New("invalid or duplicate record ID")
		}

		err := record.Update(state.Name)
		if err != nil {
			return err
		}
	}

	config := state.DNSSEC
	if config != nil {
		if config.Provider != "plat" && config.Provider != "cloudflare" {
			return errors.New("invalid DNSSEC provider")
		}

		if config.Provider == "plat" || config.PrivateKey != "" || config.DNSKEY != "" {
			err := config.loadKey(state.Name)
			if err != nil {
				return err
			}
		}

		if config.Provider == "cloudflare" && (isLocalZoneID(state.ID) || len(config.Nameservers) == 0) {
			return errors.New("invalid Cloudflare DNSSEC state")
		}

		nameservers, err := normalizeNameservers(config.Nameservers)
		if err != nil {
			return err
		}

		config.Nameservers = nameservers
	}

	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}

	if len(encoded) > MaxZoneBytes {
		return errors.New("zone exceeds replication size limit")
	}

	hash := sha256.Sum256(encoded)
	state.Hash = hex.EncodeToString(hash[:])
	state.Size = len(encoded)

	return nil
}

func cloneDNSSEC(config *DNSSECConfig) *DNSSECConfig {
	if config == nil {
		return nil
	}

	copy := *config
	copy.Nameservers = slices.Clone(config.Nameservers)

	return &copy
}

func DecodeZone(data []byte, hash string) (*ZoneState, error) {
	var state ZoneState

	err := json.Unmarshal(data, &state)
	if err != nil {
		return nil, err
	}

	err = state.validate()
	if err != nil {
		return nil, err
	}

	if state.Hash != hash {
		return nil, fmt.Errorf("zone hash mismatch for %s", state.ID)
	}

	return &state, nil
}
