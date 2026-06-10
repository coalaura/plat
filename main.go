package main

import (
	_ "embed"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"

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

	log.Println("Loading storage...")

	storage, err := LoadStorage(config)
	log.MustFail(err)

	log.Println("Fetching zones...")

	err = storage.FetchZones()
	log.MustFail(err)

	log.Println("Preparing router...")

	r := chi.NewRouter()

	r.Use(middleware.Recoverer)
	r.Use(log.Middleware())

	r.Handle("/*", frontend(config))

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
			"zones":         zones,
		})
	})

	r.Group(func(gr chi.Router) {
		gr.Use(authenticate(config))

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
