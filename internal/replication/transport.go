package replication

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/websocket"
)

const (
	EndpointPath      = "/-/replication"
	websocketProtocol = "plat-replication-v1"
)

type websocketStream struct {
	*websocket.Conn
}

func (connection websocketStream) Close() error {
	// Abort blocked writes before WebSocket Close tries to send its own close frame.
	connection.SetDeadline(time.Now())

	return connection.Conn.Close()
}

func (c ClientConfig) ValidateAddress() error {
	_, err := replicationURL(c.Address)
	return err
}

func (m *Master) HTTPHandler(ctx context.Context) (http.Handler, error) {
	timing, err := m.Timing.normalized()
	if err != nil {
		return nil, err
	}

	if m.TLS == nil || m.TLS.ClientAuth != tls.RequireAndVerifyClientCert || m.TLS.VerifyConnection == nil || m.TLS.MinVersion != tls.VersionTLS13 {
		return nil, errors.New("mutually authenticated TLS 1.3 configuration required")
	}

	m.connections = make(map[string]net.Conn)

	if m.statuses == nil {
		m.statuses = make(map[string]*health)
	}

	capacity := make(chan struct{}, 32)

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if ctx.Err() != nil {
			http.Error(writer, "replication is shutting down", http.StatusServiceUnavailable)

			return
		}

		if request.Method != http.MethodGet {
			writer.Header().Set("Allow", http.MethodGet)
			http.Error(writer, "WebSocket GET required", http.StatusMethodNotAllowed)

			return
		}

		if _, ok := writer.(http.Hijacker); !ok {
			http.Error(writer, "HTTP/1.1 WebSocket upgrade required", http.StatusBadRequest)

			return
		}

		select {
		case capacity <- struct{}{}:
			defer func() {
				<-capacity
			}()
		default:
			http.Error(writer, "replication connection limit reached", http.StatusServiceUnavailable)

			return
		}

		connectionContext, cancel := context.WithCancel(request.Context())
		defer cancel()

		stop := context.AfterFunc(ctx, cancel)
		defer stop()

		controller := http.NewResponseController(writer)

		deadlineErr := controller.SetWriteDeadline(time.Now().Add(timing.Timeout))
		if deadlineErr != nil {
			http.Error(writer, "cannot set replication deadline", http.StatusInternalServerError)

			return
		}

		server := websocket.Server{
			Handshake: acceptWebSocket,
			Handler: func(connection *websocket.Conn) {
				connection.PayloadType = websocket.BinaryFrame
				m.accept(connectionContext, websocketStream{Conn: connection}, timing)
			},
		}

		server.ServeHTTP(writer, request)
	}), nil
}

func dialReplication(ctx context.Context, address string, settings *tls.Config, timeout time.Duration) (net.Conn, error) {
	endpoint, err := replicationURL(address)
	if err != nil {
		return nil, err
	}

	config, err := websocket.NewConfig(endpoint.String(), address)
	if err != nil {
		return nil, err
	}

	config.Protocol = []string{websocketProtocol}
	config.Dialer = &net.Dialer{Timeout: timeout}

	config.Header.Set("User-Agent", "plat-slave")

	connectionContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	connection, err := config.DialContext(connectionContext)
	if err != nil {
		return nil, fmt.Errorf("open replication WebSocket: %w", err)
	}

	connection.PayloadType = websocket.BinaryFrame

	stream := websocketStream{Conn: connection}
	secure := tls.Client(stream, settings)

	// This inner TLS session authenticates both nodes even through an HTTPS-terminating proxy.
	err = secure.HandshakeContext(connectionContext)
	if err != nil {
		stream.Close()

		return nil, fmt.Errorf("replication TLS handshake: %w", err)
	}

	return secure, nil
}

func acceptWebSocket(config *websocket.Config, request *http.Request) error {
	if len(config.Protocol) != 1 || config.Protocol[0] != websocketProtocol {
		return errors.New("replication WebSocket protocol required")
	}

	// Origin is not an identity: authorization happens in the inner mutual TLS handshake.
	return nil
}

func replicationURL(address string) (*url.URL, error) {
	endpoint, err := url.Parse(address)
	if err != nil {
		return nil, fmt.Errorf("invalid master.address: %w", err)
	}

	if endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return nil, errors.New("master.address must be the master's existing http:// or https:// base URL")
	}

	if endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" {
		return nil, errors.New("master.address requires a host and must not contain credentials, a query or a fragment")
	}

	port := endpoint.Port()
	if port != "" {
		value, portErr := strconv.Atoi(port)
		if portErr != nil || value < 1 || value > 65535 {
			return nil, errors.New("master.address port must be 1-65535")
		}
	} else {
		if strings.HasSuffix(endpoint.Host, ":") {
			return nil, errors.New("master.address contains an empty port")
		}

		port = "80"

		if endpoint.Scheme == "https" {
			port = "443"
		}
	}

	endpoint.Host = net.JoinHostPort(endpoint.Hostname(), port)

	if endpoint.Scheme == "https" {
		endpoint.Scheme = "wss"
	} else {
		endpoint.Scheme = "ws"
	}

	return endpoint.JoinPath(EndpointPath), nil
}
