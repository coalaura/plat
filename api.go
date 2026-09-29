package main

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
)

type CreateZoneRequest struct {
	Name string `json:"name"`
}

func DoListRecords(storage *Storage, w http.ResponseWriter, zone string) {
	list, err := storage.GetRecords(zone)
	if err != nil {
		abort(w, http.StatusNotFound, err.Error())

		return
	}

	okay(w, list)
}

func HandleListRecords(storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		zone, err := resolveZone(r)
		if err != nil {
			abort(w, http.StatusBadRequest, err.Error())

			return
		}

		DoListRecords(storage, w, zone)
	}
}

func HandleFetchRecords(storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		zone, err := resolveZone(r)
		if err != nil {
			abort(w, http.StatusBadRequest, err.Error())

			return
		}

		if storage.client == nil {
			abort(w, http.StatusServiceUnavailable, "cloudflare is not configured")

			return
		}

		err = storage.FetchRecords(zone)
		if err != nil {
			status := http.StatusInternalServerError

			if errors.Is(err, errCloudflareZoneUnavailable) {
				status = http.StatusConflict
			}

			abort(w, status, err.Error())

			return
		}

		DoListRecords(storage, w, zone)
	}
}

func HandleFetchAllZones(storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if storage.client == nil {
			abort(w, http.StatusServiceUnavailable, "cloudflare is not configured")

			return
		}

		err := storage.FetchZones()
		if err != nil {
			abort(w, http.StatusInternalServerError, err.Error())

			return
		}

		okay(w, storage.GetZones())
	}
}

func HandleCreateZone(storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request CreateZoneRequest

		err := json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			abort(w, http.StatusBadRequest, err.Error())

			return
		}

		zone, err := storage.CreateZone(request.Name)
		if err != nil {
			status := http.StatusInternalServerError

			if errors.Is(err, errInvalidZoneName) {
				status = http.StatusBadRequest
			} else if errors.Is(err, errZoneExists) {
				status = http.StatusConflict
			}

			abort(w, status, err.Error())

			return
		}

		okay(w, map[string]string{"id": zone.ID, "name": zone.Name})
	}
}

func HandleDeleteZone(storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		zone, err := resolveZone(r)
		if err != nil {
			abort(w, http.StatusBadRequest, err.Error())

			return
		}

		err = storage.DeleteZone(zone)
		if err != nil {
			status := http.StatusInternalServerError

			if errors.Is(err, errLocalZoneNotFound) {
				status = http.StatusNotFound
			} else if errors.Is(err, errZoneAssigned) {
				status = http.StatusConflict
			}

			abort(w, status, err.Error())

			return
		}

		okay(w, nil)
	}
}

func HandleFetchAllRecords(storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if storage.client == nil {
			abort(w, http.StatusServiceUnavailable, "cloudflare is not configured")

			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			abort(w, http.StatusInternalServerError, "unable to flush")

			return
		}

		availableZones, err := storage.client.ListZones(r.Context())
		if err != nil {
			abort(w, http.StatusBadGateway, err.Error())

			return
		}

		availableIDs := make(map[string]struct{}, len(availableZones))

		for _, zone := range availableZones {
			availableIDs[zone.ID] = struct{}{}
		}

		zones := storage.GetZones()

		for zone := range zones {
			if isLocalZoneID(zone) {
				delete(zones, zone)
			}
		}

		var (
			index   = 1
			total   = len(zones)
			ctx     = r.Context()
			skipped int
		)

		for zone, name := range zones {
			select {
			case <-ctx.Done():
				return
			default:
			}

			writeNDJson(w, flusher, map[string]any{
				"status": "progress",
				"zone":   zone,
				"index":  index,
				"total":  total,
			})

			if _, available := availableIDs[zone]; available {
				err = storage.FetchRecords(zone)
			} else {
				err = unavailableCloudflareZone(zone, name)
			}

			if err != nil {
				if errors.Is(err, errCloudflareZoneUnavailable) {
					writeNDJson(w, flusher, map[string]string{
						"status": "skipped",
						"zone":   zone,
						"name":   name,
						"error":  err.Error(),
					})

					skipped++
					index++

					continue
				}

				writeNDJson(w, flusher, map[string]string{
					"status": "failed",
					"zone":   zone,
					"error":  err.Error(),
				})

				return
			}

			index++
		}

		writeNDJson(w, flusher, map[string]any{
			"status":  "done",
			"synced":  total - skipped,
			"skipped": skipped,
		})
	}
}

func HandleSetRecord(storage *Storage, isCreate bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		zone, err := resolveZone(r)
		if err != nil {
			abort(w, http.StatusBadRequest, err.Error())

			return
		}

		var record Record

		err = json.NewDecoder(r.Body).Decode(&record)
		if err != nil {
			abort(w, http.StatusBadRequest, err.Error())

			return
		}

		if isCreate {
			record.ID = ""
		} else if record.ID == "" {
			abort(w, http.StatusBadRequest, "missing record id")

			return
		}

		err = storage.SetRecord(zone, &record)
		if err != nil {
			abort(w, http.StatusInternalServerError, err.Error())

			return
		}

		err = storage.Store()
		if err != nil {
			abort(w, http.StatusInternalServerError, err.Error())

			return
		}

		okay(w, nil)
	}
}

func HandleUnsetRecord(storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		zone, err := resolveZone(r)
		if err != nil {
			abort(w, http.StatusBadRequest, err.Error())

			return
		}

		name := chi.URLParam(r, "record")
		if name == "" {
			abort(w, http.StatusBadRequest, "missing record name")

			return
		}

		err = storage.UnsetRecord(zone, name)
		if err != nil {
			abort(w, http.StatusInternalServerError, err.Error())

			return
		}

		err = storage.Store()
		if err != nil {
			abort(w, http.StatusInternalServerError, err.Error())

			return
		}

		okay(w, nil)
	}
}

func resolveZone(r *http.Request) (string, error) {
	zoneID := chi.URLParam(r, "zone")
	if zoneID == "" {
		return "", errors.New("missing zone")
	}

	zone := zoneID
	if isLocalZoneID(zone) {
		zone = zone[len("local-"):]
	}

	if len(zone) != 32 {
		return "", errors.New("invalid zone")
	}

	for _, r := range zone {
		if (r < 'a' || r > 'f') && (r < '0' || r > '9') {
			return "", errors.New("invalid zone")
		}
	}

	return zoneID, nil
}
