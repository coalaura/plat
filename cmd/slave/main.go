package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"plat/internal/dnsserver"
	"plat/internal/replication"
	"plat/internal/storage"
)

var Version = "dev"

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
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	config, err := loadConfig()
	if err != nil {
		return err
	}

	err = config.Prepare()
	if err != nil {
		return err
	}

	if config.Master.TLS.CA == "" {
		log.Printf("Replication identity: %s; copy it to the master's trusted_clients directory under a unique name", config.Master.TLS.Certificate)
		log.Printf("Copy the master's public certificate to %s, set master.address in slave.yml, then restart both nodes", config.Master.TrustedMaster)
	}

	err = config.Validate()
	if err != nil {
		return err
	}

	settings, err := config.Master.TLSConfig()
	if err != nil {
		return err
	}

	certificate, err := tls.LoadX509KeyPair(config.HTTPS.Certificate, config.HTTPS.Key)
	if err != nil {
		return err
	}

	data, err := storage.LoadReplica(config.Checkpoint)
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
		log.Print("Waiting for first complete synchronization")
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
		Addr:              config.HTTPS.Address,
		Handler:           dohHandler(dns),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       time.Minute,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}},
	}

	defer server.Close()

	httpsErrors := make(chan error, 1)

	go func() {
		httpsErrors <- server.ListenAndServeTLS("", "")
	}()

	log.Printf("Serving DNS on :%d and DoH on https://%s/dns-query", config.DNS.Port, config.HTTPS.Address)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err = <-finished:
		return err
	case err = <-httpsErrors:
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
