package main

import (
	"net/http"

	"plat/internal/replication"
)

type SlavesResponse struct {
	Enabled  bool                          `json:"enabled"`
	Epoch    string                        `json:"epoch"`
	Sequence uint64                        `json:"sequence,string"`
	Slaves   map[string]replication.Status `json:"slaves"`
}

func HandleListSlaves(master *replication.Master) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")

		response := SlavesResponse{Enabled: master != nil}

		if master != nil {
			response.Slaves = master.Status()
			response.Epoch, response.Sequence = master.Storage.Revision()
		}

		okay(writer, response)
	}
}
