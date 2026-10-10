package replication

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	ProtocolVersion  = 1
	ProtocolName     = "plat-replication/1"
	MaxFrame         = 64 << 10
	ChunkSize        = 32 << 10
	MaxTransfer      = 65 << 20
	DefaultHeartbeat = time.Second
	DefaultTimeout   = 5 * time.Second
)

type Timing struct {
	Heartbeat time.Duration
	Timeout   time.Duration
}

type frame struct {
	Version int             `json:"version"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type transfer struct {
	Kind string `json:"kind"`
	Size int    `json:"size"`
}

type chunk struct {
	Offset int    `json:"offset"`
	Data   []byte `json:"data"`
}

type outgoing struct {
	frame  frame
	result chan error
}

type session struct {
	connection net.Conn
	timing     Timing
	done       chan struct{}
	incoming   chan frame
	credits    chan int
	outgoing   chan outgoing
	closeOnce  sync.Once
	sendMu     sync.Mutex
	workers    sync.WaitGroup
	health     *health
}

func (t Timing) normalized() (Timing, error) {
	if t.Heartbeat == 0 {
		t.Heartbeat = DefaultHeartbeat
	}

	if t.Timeout == 0 {
		t.Timeout = DefaultTimeout
	}

	if t.Heartbeat <= 0 || t.Timeout <= t.Heartbeat {
		return Timing{}, errors.New("replication timeout must exceed positive heartbeat interval")
	}

	return t, nil
}

func (p *session) Close() {
	p.fail()
	p.workers.Wait()
}

func (p *session) fail() {
	p.closeOnce.Do(func() {
		if p.health != nil {
			p.health.connection(false, io.ErrClosedPipe)
		}

		close(p.done)
		p.connection.Close()
	})
}

func (p *session) readLoop() {
	defer p.workers.Done()
	defer p.fail()

	for {
		err := p.connection.SetReadDeadline(time.Now().Add(p.timing.Timeout))
		if err != nil {
			return
		}

		message, err := readFrame(p.connection)
		if err != nil {
			return
		}

		if p.health != nil {
			p.health.received()
		}

		if message.Type == "heartbeat" {
			continue
		}

		if message.Type == "chunk-ack" {
			var offset int

			err = json.Unmarshal(message.Payload, &offset)
			if err != nil {
				return
			}

			select {
			case p.credits <- offset:
			default:
				return
			}

			continue
		}

		select {
		case p.incoming <- message:
		case <-p.done:
			return
		default:
			// A bounded receive queue also protects against an authenticated flooding peer.
			return
		}
	}
}

func (p *session) writeLoop() {
	defer p.workers.Done()
	defer p.fail()

	ticker := time.NewTicker(p.timing.Heartbeat)
	defer ticker.Stop()

	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			err := p.write(frame{Version: ProtocolVersion, Type: "heartbeat"})
			if err != nil {
				return
			}
		case request := <-p.outgoing:
			err := p.write(request.frame)
			request.result <- err

			if err != nil {
				return
			}
		}
	}
}

func (p *session) write(message frame) error {
	err := p.connection.SetWriteDeadline(time.Now().Add(p.timing.Timeout))
	if err != nil {
		return err
	}

	return writeFrame(p.connection, message)
}

func (p *session) sendFrame(ctx context.Context, kind string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}

	request := outgoing{
		frame:  frame{Version: ProtocolVersion, Type: kind, Payload: payload},
		result: make(chan error, 1),
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.done:
		return io.ErrClosedPipe
	case p.outgoing <- request:
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.done:
		return io.ErrClosedPipe
	case err = <-request.result:
		return err
	}
}

func (p *session) Send(ctx context.Context, kind string, value any) error {
	p.sendMu.Lock()
	defer p.sendMu.Unlock()

	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	if len(data) > MaxTransfer {
		return errors.New("transfer exceeds size limit")
	}

	err = p.sendFrame(ctx, "start", transfer{Kind: kind, Size: len(data)})
	if err != nil {
		return err
	}

	for offset := 0; offset < len(data); offset += ChunkSize {
		end := min(offset+ChunkSize, len(data))

		err = p.sendFrame(ctx, "chunk", chunk{Offset: offset, Data: data[offset:end]})
		if err != nil {
			return err
		}

		// Chunk credit bounds transport buffering while the independent loops keep heartbeats alive.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.done:
			return io.ErrClosedPipe
		case acknowledged := <-p.credits:
			if acknowledged != end {
				return errors.New("invalid chunk acknowledgment")
			}
		}
	}

	return nil
}

func (p *session) receiveFrame(ctx context.Context) (frame, error) {
	select {
	case <-ctx.Done():
		return frame{}, ctx.Err()
	case <-p.done:
		return frame{}, io.ErrClosedPipe
	case message := <-p.incoming:
		return message, nil
	}
}

func (p *session) Receive(ctx context.Context) (string, []byte, error) {
	message, err := p.receiveFrame(ctx)
	if err != nil {
		return "", nil, err
	}

	var header transfer

	err = json.Unmarshal(message.Payload, &header)
	if err != nil || message.Type != "start" || header.Size <= 0 || header.Size > MaxTransfer {
		return "", nil, errors.New("invalid transfer header")
	}

	data := make([]byte, 0, header.Size)

	for len(data) < header.Size {
		message, err = p.receiveFrame(ctx)
		if err != nil {
			return "", nil, err
		}

		var part chunk

		err = json.Unmarshal(message.Payload, &part)

		invalidSize := len(part.Data) == 0 || len(part.Data) > ChunkSize || len(data)+len(part.Data) > header.Size

		if err != nil || message.Type != "chunk" || part.Offset != len(data) || invalidSize {
			return "", nil, errors.New("invalid transfer chunk")
		}

		data = append(data, part.Data...)

		err = p.sendFrame(ctx, "chunk-ack", len(data))
		if err != nil {
			return "", nil, err
		}
	}

	return header.Kind, data, nil
}

func newSession(connection net.Conn, timing Timing, state *health) *session {
	peer := &session{
		connection: connection,
		timing:     timing,
		done:       make(chan struct{}),
		incoming:   make(chan frame, 128),
		credits:    make(chan int, 1),
		outgoing:   make(chan outgoing),
		health:     state,
	}

	peer.workers.Add(2)

	go peer.readLoop()
	go peer.writeLoop()

	return peer
}

func readFrame(reader io.Reader) (frame, error) {
	var header [4]byte

	_, err := io.ReadFull(reader, header[:])
	if err != nil {
		return frame{}, err
	}

	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > MaxFrame {
		return frame{}, errors.New("invalid frame length")
	}

	data := make([]byte, int(length))

	_, err = io.ReadFull(reader, data)
	if err != nil {
		return frame{}, err
	}

	var message frame

	err = json.Unmarshal(data, &message)
	if err != nil {
		return frame{}, err
	}

	if message.Version != ProtocolVersion {
		return frame{}, fmt.Errorf("unsupported protocol version %d", message.Version)
	}

	return message, nil
}

func writeFrame(writer io.Writer, message frame) error {
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}

	if len(data) > MaxFrame {
		return errors.New("frame size limit exceeded")
	}

	var header [4]byte

	binary.BigEndian.PutUint32(header[:], uint32(len(data)))

	buffers := net.Buffers{header[:], data}

	_, err = buffers.WriteTo(writer)

	return err
}
