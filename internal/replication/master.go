package replication

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"plat/internal/storage"
)

const (
	ManifestPageSize = 128
	SyncTimeout      = 5 * time.Minute
)

type ManifestEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Hash string `json:"hash"`
}

type revision struct {
	Epoch    string `json:"epoch"`
	Sequence uint64 `json:"sequence"`
}

type acknowledgment struct {
	Epoch    string `json:"epoch"`
	Sequence uint64 `json:"sequence"`
	Applied  bool   `json:"applied"`
}

type Status struct {
	Connected   bool
	LastReceive time.Time
	LastApplied time.Time
	Epoch       string
	Sequence    uint64
	Error       string
}

type health struct {
	mx     sync.Mutex
	status Status
}

type Master struct {
	Storage     *storage.Storage
	TLS         *tls.Config
	Timing      Timing
	mx          sync.Mutex
	connections map[string]net.Conn
	statuses    map[string]*health
}

func (s *health) received() {
	s.mx.Lock()
	s.status.LastReceive = time.Now()
	s.mx.Unlock()
}

func (s *health) connection(connected bool, err error) {
	s.mx.Lock()
	s.status.Connected = connected

	if err != nil {
		s.status.Error = err.Error()
	} else {
		s.status.Error = ""
	}

	s.mx.Unlock()
}

func (s *health) applied(epoch string, sequence uint64) {
	s.mx.Lock()
	s.status.Epoch = epoch
	s.status.Sequence = sequence
	s.status.LastApplied = time.Now()
	s.mx.Unlock()
}

func (s *health) snapshot() Status {
	s.mx.Lock()
	defer s.mx.Unlock()

	return s.status
}

func (m *Master) Status() map[string]Status {
	m.mx.Lock()
	defer m.mx.Unlock()

	statuses := make(map[string]Status, len(m.statuses))

	for id, state := range m.statuses {
		statuses[id] = state.snapshot()
	}

	return statuses
}

func (m *Master) accept(ctx context.Context, connection net.Conn, timing Timing) {
	defer connection.Close()

	stop := context.AfterFunc(ctx, func() {
		connection.Close()
	})

	defer stop()

	err := connection.SetDeadline(time.Now().Add(timing.Timeout))
	if err != nil {
		return
	}

	secure := tls.Server(connection, m.TLS)

	handshakeCtx, cancel := context.WithTimeout(ctx, timing.Timeout)

	err = secure.HandshakeContext(handshakeCtx)

	cancel()

	if err != nil {
		return
	}

	err = connection.SetDeadline(time.Time{})
	if err != nil {
		return
	}

	id := Fingerprint(secure.ConnectionState().PeerCertificates[0])

	m.mx.Lock()

	previous := m.connections[id]
	if previous != nil {
		previous.Close()
	}

	state := &health{}

	m.connections[id] = connection
	m.statuses[id] = state

	m.mx.Unlock()

	state.connection(true, nil)

	peer := newSession(secure, timing, state)
	defer peer.Close()

	err = m.synchronize(ctx, peer, state)

	state.connection(false, err)

	m.mx.Lock()

	if m.connections[id] == connection {
		delete(m.connections, id)
	}

	m.mx.Unlock()
}

func (m *Master) synchronize(ctx context.Context, peer *session, state *health) error {
	snapshot, subscription := m.Storage.Capture()
	defer subscription.Close()

	go func() {
		select {
		case <-ctx.Done():
			peer.fail()
		case <-subscription.Done:
			peer.fail()
		case <-peer.done:
		}
	}()

	syncCtx, cancel := context.WithTimeout(ctx, SyncTimeout)
	defer cancel()

	err := sendManifest(syncCtx, peer, snapshot)
	if err != nil {
		return err
	}

	err = serveSnapshot(syncCtx, peer, snapshot)
	if err != nil {
		return err
	}

	// Release the captured map after transfer. Subsequent events own their immutable state.
	snapshot = storage.Snapshot{}

	subscription.Fence()

	sendingContext := syncCtx

	for {
		select {
		case <-sendingContext.Done():
			return sendingContext.Err()
		case <-peer.done:
			return errors.New("replication connection closed")
		case <-subscription.Done:
			return errors.New("replication queue overflow")
		case event := <-subscription.Events:
			err = peer.Send(sendingContext, "event", event)

			subscription.Release(event)

			if err != nil {
				return err
			}

			err = receiveAcknowledgment(sendingContext, peer, event, state)
			if err != nil {
				return err
			}

			if event.Kind == "complete" {
				sendingContext = ctx

				cancel()
			}
		}
	}
}

func sendManifest(ctx context.Context, peer *session, snapshot storage.Snapshot) error {
	err := snapshot.CheckSize()
	if err != nil {
		return err
	}

	err = peer.Send(ctx, "begin", revision{Epoch: snapshot.Epoch, Sequence: snapshot.Sequence})
	if err != nil {
		return err
	}

	page := make([]ManifestEntry, 0, ManifestPageSize)

	for _, zone := range snapshot.Zones {
		page = append(page, ManifestEntry{ID: zone.ID, Name: zone.Name, Hash: zone.Hash})
		if len(page) == cap(page) {
			err = peer.Send(ctx, "manifest", page)
			if err != nil {
				return err
			}

			page = page[:0]
		}
	}

	if len(page) > 0 {
		err = peer.Send(ctx, "manifest", page)
		if err != nil {
			return err
		}
	}

	return peer.Send(ctx, "manifest-end", revision{Epoch: snapshot.Epoch, Sequence: snapshot.Sequence})
}

func serveSnapshot(ctx context.Context, peer *session, snapshot storage.Snapshot) error {
	requested := make(map[string]bool)

	for {
		kind, data, err := peer.Receive(ctx)
		if err != nil {
			return err
		}

		if kind == "snapshot-end" {
			var end revision

			err = json.Unmarshal(data, &end)
			if err != nil || end.Epoch != snapshot.Epoch || end.Sequence != snapshot.Sequence {
				return errors.New("snapshot revision mismatch")
			}

			return nil
		}

		var id string

		err = json.Unmarshal(data, &id)
		if err != nil || kind != "get-zone" || requested[id] {
			return errors.New("invalid zone request")
		}

		zone := snapshot.Zones[id]
		if zone == nil {
			return errors.New("zone not in captured snapshot")
		}

		requested[id] = true

		err = peer.Send(ctx, "zone", zone)
		if err != nil {
			return err
		}
	}
}

func receiveAcknowledgment(ctx context.Context, peer *session, event *storage.Event, state *health) error {
	kind, data, err := peer.Receive(ctx)
	if err != nil {
		return err
	}

	var acknowledgment acknowledgment

	err = json.Unmarshal(data, &acknowledgment)
	if err != nil || kind != "ack" || acknowledgment.Epoch != event.Epoch || acknowledgment.Sequence != event.Sequence {
		return errors.New("invalid replication acknowledgment")
	}

	if event.Kind == "complete" && !acknowledgment.Applied {
		return errors.New("snapshot not published")
	}

	if acknowledgment.Applied {
		state.applied(acknowledgment.Epoch, acknowledgment.Sequence)
	}

	return nil
}
