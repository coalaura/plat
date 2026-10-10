package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
)

const MaxCheckpointBytes = 256 << 20

type checkpoint struct {
	Digest string          `json:"digest"`
	State  json.RawMessage `json:"state"`
}

func (snapshot Snapshot) CheckSize() error {
	if len(snapshot.Zones) > MaxZones {
		return errors.New("snapshot zone limit exceeded")
	}

	total := 0

	for _, state := range snapshot.Zones {
		if state == nil || state.Size <= 0 {
			return errors.New("unvalidated zone state")
		}

		total += state.Size
		if total > MaxStateBytes {
			return errors.New("snapshot size limit exceeded")
		}
	}

	return nil
}

func (s *Storage) Ready() bool {
	s.mx.RLock()
	defer s.mx.RUnlock()

	return s.ready
}

// PublishReplica is the only slave apply path: persist first, then swap the whole serving map.
func (s *Storage) PublishReplica(snapshot Snapshot) error {
	s.commitMu.Lock()
	defer s.commitMu.Unlock()

	if !s.readOnly || snapshot.Version != StateVersion || snapshot.Epoch == "" {
		return errors.New("invalid replica publication")
	}

	zones, err := s.replicaZones(snapshot)
	if err != nil {
		return err
	}

	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}

	digest := sha256.Sum256(data)

	encoded, err := json.Marshal(checkpoint{Digest: hex.EncodeToString(digest[:]), State: data})
	if err != nil {
		return err
	}

	if len(encoded) > MaxCheckpointBytes {
		return errors.New("checkpoint size limit exceeded")
	}

	err = s.persist(s.path, encoded)
	if err != nil {
		return err
	}

	s.mx.Lock()
	s.zones = zones
	s.epoch = snapshot.Epoch
	s.sequence = snapshot.Sequence
	s.ready = true
	s.mx.Unlock()

	return nil
}

func (s *Storage) replicaZones(snapshot Snapshot) (map[string]*Zone, error) {
	err := snapshot.CheckSize()
	if err != nil {
		return nil, err
	}

	zones := make(map[string]*Zone, len(snapshot.Zones))
	names := make(map[string]bool, len(snapshot.Zones))

	for id, state := range snapshot.Zones {
		if state == nil || state.ID != id || state.Hash == "" || names[state.Name] {
			return nil, errors.New("invalid replica zone")
		}

		names[state.Name] = true

		existing := s.zones[id]
		if existing != nil && existing.state.Hash == state.Hash {
			zones[id] = existing

			continue
		}

		zone := &Zone{
			ID:      id,
			Name:    state.Name,
			serial:  state.Serial,
			dnssec:  state.DNSSEC,
			state:   state,
			Records: make(map[string]*Record, len(state.Records)),
		}

		for index := range state.Records {
			record := &state.Records[index]
			zone.Records[record.ID] = record
		}

		zones[id] = zone
	}

	return zones, nil
}

func LoadReplica(path string) (*Storage, error) {
	storage := NewStorage(path)
	storage.readOnly = true
	storage.ready = false

	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return storage, nil
	}

	if err != nil {
		return nil, err
	}

	if info.Size() > MaxCheckpointBytes {
		return nil, errors.New("checkpoint size limit exceeded")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var saved checkpoint

	err = json.Unmarshal(data, &saved)
	if err != nil {
		return nil, err
	}

	digest := sha256.Sum256(saved.State)
	if hex.EncodeToString(digest[:]) != saved.Digest {
		return nil, errors.New("checkpoint checksum mismatch")
	}

	var snapshot Snapshot

	err = json.Unmarshal(saved.State, &snapshot)
	if err != nil {
		return nil, err
	}

	if snapshot.Version != StateVersion || snapshot.Epoch == "" || snapshot.Zones == nil {
		return nil, errors.New("invalid checkpoint")
	}

	for _, state := range snapshot.Zones {
		if state == nil {
			return nil, errors.New("nil checkpoint zone")
		}

		err = state.validate()
		if err != nil {
			return nil, err
		}
	}

	storage.zones, err = storage.replicaZones(snapshot)
	if err != nil {
		return nil, err
	}

	storage.epoch = snapshot.Epoch
	storage.sequence = snapshot.Sequence
	storage.ready = true

	return storage, nil
}

// Advance uses copy-on-write so failed events cannot damage the last complete state.
func Advance(snapshot Snapshot, event *Event) (Snapshot, error) {
	if event.Epoch != snapshot.Epoch || event.Sequence != snapshot.Sequence+1 {
		return Snapshot{}, errors.New("replication epoch or sequence gap")
	}

	updated := Snapshot{Version: StateVersion, Epoch: snapshot.Epoch, Sequence: event.Sequence, Zones: maps.Clone(snapshot.Zones)}

	if event.Kind == "delete-zone" {
		if updated.Zones[event.ZoneID] == nil || event.Hash != "" {
			return Snapshot{}, errors.New("invalid zone deletion")
		}

		delete(updated.Zones, event.ZoneID)

		return updated, nil
	}

	var state *ZoneState

	switch event.Kind {
	case "replace":
		if event.Zone == nil || event.Zone.ID != event.ZoneID {
			return Snapshot{}, errors.New("invalid replacement")
		}

		state = new(*event.Zone)
		state.Records = slices.Clone(state.Records)
		state.DNSSEC = cloneDNSSEC(state.DNSSEC)
	case "upsert", "delete-record":
		previous := updated.Zones[event.ZoneID]
		if previous == nil {
			return Snapshot{}, errors.New("event for missing zone")
		}

		state = new(*previous)
		state.Records = slices.Clone(previous.Records)
		state.DNSSEC = cloneDNSSEC(previous.DNSSEC)
		state.Serial = event.Serial
		recordID := event.RecordID

		if event.Kind == "upsert" {
			if event.Record == nil {
				return Snapshot{}, errors.New("missing upsert record")
			}

			recordID = event.Record.ID
		}

		index := slices.IndexFunc(state.Records, func(record Record) bool {
			return record.ID == recordID
		})

		if event.Kind == "delete-record" {
			if index < 0 {
				return Snapshot{}, errors.New("missing deleted record")
			}

			state.Records = slices.Delete(state.Records, index, index+1)
		} else if index < 0 {
			state.Records = append(state.Records, *event.Record)
		} else {
			state.Records[index] = *event.Record
		}
	default:
		return Snapshot{}, fmt.Errorf("unknown event %q", event.Kind)
	}

	err := state.validate()
	if err != nil {
		return Snapshot{}, err
	}

	if state.Hash != event.Hash || state.Serial != event.Serial {
		return Snapshot{}, errors.New("resulting zone hash mismatch")
	}

	updated.Zones[event.ZoneID] = state

	err = updated.CheckSize()
	if err != nil {
		return Snapshot{}, err
	}

	return updated, nil
}
