package main

import (
	"context"
	_ "embed"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"plat/internal/replication"

	"github.com/coalaura/plain"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

var Version = "dev"

var log = plain.New(plain.WithDate(plain.RFC3339Local))

func main() {
	log.Println("Loading config...")

	config, err := LoadConfig()
	log.MustFail(err)

	err = config.Cluster.Prepare()
	log.MustFail(err)

	log.Println("Loading storage...")

	storage, err := LoadStorage(config)
	log.MustFail(err)

	defer storage.Close()

	clusterContext, stopCluster := context.WithCancel(context.Background())
	defer stopCluster()

	if storage.Client() != nil {
		log.Println("Fetching zones from Cloudflare...")

		err = storage.FetchZones()
		if err != nil {
			log.Warnf("Cloudflare zone fetch failed; using saved zones: %v", err)
		}
	}

	var dns *DNSServer

	if config.DNS.Enabled {
		log.Println("Starting DNS server...")

		dns = NewDNSServer(config, storage)

		defer dns.Close()
	}

	log.Println("Preparing router...")

	r := chi.NewRouter()

	r.Use(middleware.Recoverer)
	r.Use(log.Middleware())

	r.Use(HandleDNSRequests(config.DNS.Domain, dns))

	r.Handle("/*", frontend(config))

	var master *replication.Master

	if config.Cluster.Enabled {
		master, err = config.Cluster.NewMaster(storage)
		log.MustFail(err)

		handler, err := master.HTTPHandler(clusterContext)
		log.MustFail(err)

		r.Handle(replication.EndpointPath, handler)

		log.Printf("Replication available at %s on the HTTP listener\n", replication.EndpointPath)
	}

	r.Get("/nic/update", HandleDynDNSUpdate(storage))

	r.Get("/-/info", func(w http.ResponseWriter, r *http.Request) {
		var (
			authenticated = isAuthenticated(config, r)
			zones         map[string]string
		)

		if authenticated {
			zones = storage.GetZones()
		}

		okay(w, map[string]any{
			"authenticated": authenticated,
			"cloudflare":    storage.Client() != nil,
			"zones":         zones,
		})
	})

	r.Group(func(gr chi.Router) {
		gr.Use(authenticate(config))

		gr.Get("/-/slaves", HandleListSlaves(master))
		gr.Patch("/-/zones", HandleFetchAllZones(storage))
		gr.Patch("/-/records", HandleFetchAllRecords(storage))
		gr.Post("/-/zones", HandleCreateZone(storage))
		gr.Delete("/-/zones/{zone}", HandleDeleteZone(storage))
		gr.Get("/-/dyndns", HandleListDynDNSUsers(storage))
		gr.Get("/-/dyndns/{username}/logs", HandleListDynDNSLogs(storage))
		gr.Post("/-/dyndns", HandleCreateDynDNSUser(storage))
		gr.Put("/-/dyndns/{username}", HandleUpdateDynDNSUser(storage))
		gr.Delete("/-/dyndns/{username}", HandleDeleteDynDNSUser(storage))
		gr.Get("/-/{zone}/dnssec", HandleDNSSEC(storage, config, false))
		gr.Put("/-/{zone}/dnssec", HandleDNSSEC(storage, config, true))
		gr.Post("/-/{zone}/email-protection", HandleProtectEmail(storage))

		gr.Get("/-/{zone}", HandleListRecords(storage))
		gr.Patch("/-/{zone}", HandleFetchRecords(storage))

		gr.Put("/-/{zone}", HandleSetRecord(storage, false))
		gr.Post("/-/{zone}", HandleSetRecord(storage, true))

		gr.Delete("/-/{zone}/{record}", HandleUnsetRecord(storage))
	})

	addr := config.Addr()

	server := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	go func() {
		log.Printf("Listening at http://localhost%s/\n", addr)

		err = server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Warnln(err)
		}
	}()

	log.WaitForInterrupt()

	log.Warnln("Shutting down...")

	server.Close()
}

func frontend(config *Config) http.Handler {
	if !config.Debug {
		return http.FileServer(http.Dir("./public"))
	}

	target, _ := url.Parse("http://localhost:3000")
	proxy := httputil.NewSingleHostReverseProxy(target)

	log.Println("Proxying frontend requests to Rsbuild (:3000)")

	return proxy
}
