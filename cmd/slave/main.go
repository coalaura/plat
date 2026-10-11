package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"plat/internal/dnsserver"
	"plat/internal/replication"
	"plat/internal/storage"

	"github.com/coalaura/plain"
)

const CheckpointPath = "data/checkpoint.json"

var Version = "dev"

var log = plain.New(plain.WithDate(plain.RFC3339Local))

func main() {
	for _, argument := range os.Args[1:] {
		if argument == "--version" || argument == "-v" {
			fmt.Println(Version)

			return
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	err := run(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		log.MustFail(err)
	}
}

func run(ctx context.Context) error {
	config, err := LoadConfig()
	if err != nil {
		return err
	}

	err = config.Prepare()
	if err != nil {
		return err
	}

	err = config.Validate()
	if err != nil {
		return err
	}

	settings, err := config.Master.TLSConfig()
	if err != nil {
		return err
	}

	data, err := storage.LoadReplica(CheckpointPath)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	slave := &replication.Slave{Storage: data, Address: config.Master.Address, TLS: settings}

	finished := make(chan error, 1)

	go func() {
		finished <- slave.Run(ctx)
	}()

	if !data.Ready() {
		log.Println("Waiting for first complete synchronization")
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for !data.Ready() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err = <-finished:
			return err
		case <-ticker.C:
		}
	}

	dns := dnsserver.NewDNSServer(config.DNS, data)
	defer dns.Close()

	server := &http.Server{
		Addr:              config.HTTP.Address,
		Handler:           log.Middleware()(dohHandler(dns)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       time.Minute,
	}

	defer server.Close()

	httpErrors := make(chan error, 1)

	go func() {
		httpErrors <- server.ListenAndServe()
	}()

	log.Printf("Serving DNS on :%d and DoH over HTTP on %s/dns-query\n", config.DNS.Port, config.HTTP.Address)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err = <-finished:
		return err
	case err = <-httpErrors:
		return err
	case err = <-dns.Errors():
		return err
	}
}

func dohHandler(server *dnsserver.DNSServer) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/dns-query" {
			http.NotFound(writer, request)

			return
		}

		request.Body = http.MaxBytesReader(writer, request.Body, 65535)

		doh, err := dnsserver.NewDoHRequest(request)
		if err != nil || doh == nil {
			http.Error(writer, "expected a DNS wire-format GET or POST", http.StatusBadRequest)

			return
		}

		server.HandleDoH(writer, doh)
	})
}
