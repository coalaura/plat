package replication

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"time"

	"plat/internal/storage"
)

type Slave struct {
	Storage *storage.Storage
	Address string
	TLS     *tls.Config
	Timing  Timing
	health  health
}

func (s *Slave) Status() Status {
	return s.health.snapshot()
}

func (s *Slave) Run(ctx context.Context) error {
	timing, err := s.Timing.normalized()
	if err != nil {
		return err
	}

	if s.TLS == nil || s.TLS.InsecureSkipVerify || s.TLS.ServerName == "" || s.TLS.MinVersion != tls.VersionTLS13 {
		return errors.New("verified TLS 1.3 master identity required")
	}

	_, err = replicationURL(s.Address)
	if err != nil {
		return err
	}

	backoff := 250 * time.Millisecond

	for ctx.Err() == nil {
		started := time.Now()

		err = s.connect(ctx, timing)

		s.health.connection(false, err)

		if time.Since(started) > 30*time.Second {
			backoff = 250 * time.Millisecond
		}

		jitter := time.Duration(rand.Int64N(int64(backoff / 2)))
		timer := time.NewTimer(backoff + jitter)

		select {
		case <-ctx.Done():
			timer.Stop()

			return ctx.Err()
		case <-timer.C:
		}

		backoff = min(backoff*2, 15*time.Second)
	}

	return ctx.Err()
}

func (s *Slave) connect(ctx context.Context, timing Timing) error {
	connection, err := dialReplication(ctx, s.Address, s.TLS, timing.Timeout)
	if err != nil {
		return err
	}

	s.health.connection(true, nil)

	peer := newSession(connection, timing, &s.health)
	defer peer.Close()

	stop := context.AfterFunc(ctx, peer.fail)
	defer stop()

	return s.synchronize(ctx, peer)
}

func (s *Slave) synchronize(ctx context.Context, peer *session) error {
	syncCtx, cancel := context.WithTimeout(ctx, SyncTimeout)
	defer cancel()

	staged, err := receiveSnapshot(syncCtx, peer, s.Storage.Snapshot())
	if err != nil {
		return err
	}

	complete := false
	receivingContext := syncCtx

	for {
		kind, data, receiveErr := peer.Receive(receivingContext)
		if receiveErr != nil {
			return receiveErr
		}

		var event storage.Event

		err = json.Unmarshal(data, &event)
		if err != nil || kind != "event" {
			return errors.New("expected ordered replication event")
		}

		if event.Kind == "complete" {
			if complete || event.Epoch != staged.Epoch || event.Sequence != staged.Sequence {
				return errors.New("invalid synchronization completion marker")
			}

			complete = true
			receivingContext = ctx

			cancel()
		} else {
			staged, err = storage.Advance(staged, &event)
			if err != nil {
				return err
			}
		}

		if complete {
			err = s.Storage.PublishReplica(staged)
			if err != nil {
				return err
			}

			s.health.applied(staged.Epoch, staged.Sequence)
		}

		ack := acknowledgment{Epoch: staged.Epoch, Sequence: staged.Sequence, Applied: complete}

		err = peer.Send(receivingContext, "ack", ack)
		if err != nil {
			return err
		}
	}
}

func receiveSnapshot(ctx context.Context, peer *session, previous storage.Snapshot) (storage.Snapshot, error) {
	kind, data, err := peer.Receive(ctx)
	if err != nil {
		return storage.Snapshot{}, err
	}

	var start revision

	err = json.Unmarshal(data, &start)
	if err != nil || kind != "begin" || start.Epoch == "" {
		return storage.Snapshot{}, errors.New("invalid snapshot revision")
	}

	manifest := make(map[string]ManifestEntry)

	for {
		kind, data, err = peer.Receive(ctx)
		if err != nil {
			return storage.Snapshot{}, err
		}

		if kind == "manifest-end" {
			var end revision

			err = json.Unmarshal(data, &end)
			if err != nil || end != start {
				return storage.Snapshot{}, errors.New("manifest revision mismatch")
			}

			break
		}

		var page []ManifestEntry

		err = json.Unmarshal(data, &page)
		if err != nil || kind != "manifest" || len(page) == 0 || len(page) > ManifestPageSize || len(manifest)+len(page) > storage.MaxZones {
			return storage.Snapshot{}, errors.New("invalid manifest page")
		}

		for _, entry := range page {
			if entry.ID == "" || entry.Name == "" || len(entry.Hash) != 64 || manifest[entry.ID].ID != "" {
				return storage.Snapshot{}, errors.New("invalid or duplicate manifest entry")
			}

			manifest[entry.ID] = entry
		}
	}

	staged := storage.Snapshot{
		Version:  storage.StateVersion,
		Epoch:    start.Epoch,
		Sequence: start.Sequence,
		Zones:    make(map[string]*storage.ZoneState, len(manifest)),
	}

	total := 0

	for id, entry := range manifest {
		zone := previous.Zones[id]
		if zone == nil || zone.Hash != entry.Hash || zone.Name != entry.Name {
			zone, err = requestZone(ctx, peer, entry)
			if err != nil {
				return storage.Snapshot{}, err
			}
		}

		total += zone.Size
		if total > storage.MaxStateBytes {
			return storage.Snapshot{}, errors.New("snapshot size limit exceeded")
		}

		staged.Zones[id] = zone
	}

	err = peer.Send(ctx, "snapshot-end", start)
	return staged, err
}

func requestZone(ctx context.Context, peer *session, entry ManifestEntry) (*storage.ZoneState, error) {
	err := peer.Send(ctx, "get-zone", entry.ID)
	if err != nil {
		return nil, err
	}

	kind, data, err := peer.Receive(ctx)
	if err != nil {
		return nil, err
	}

	if kind != "zone" {
		return nil, errors.New("expected snapshot zone")
	}

	zone, err := storage.DecodeZone(data, entry.Hash)
	if err != nil {
		return nil, err
	}

	if zone.ID != entry.ID || zone.Name != entry.Name {
		return nil, errors.New("snapshot zone identity mismatch")
	}

	return zone, nil
}
