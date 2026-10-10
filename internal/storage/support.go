package storage

import (
	"os"

	"github.com/coalaura/plain"
)

var log = plain.New(plain.WithDate(plain.RFC3339Local))

var (
	ErrInvalidZoneName           = errInvalidZoneName
	ErrZoneExists                = errZoneExists
	ErrLocalZoneNotFound         = errLocalZoneNotFound
	ErrZoneAssigned              = errZoneAssigned
	ErrCloudflareZoneUnavailable = errCloudflareZoneUnavailable
	ErrDynDNSUserNotFound        = errDynDNSUserNotFound
)

func IsLocalZoneID(id string) bool {
	return isLocalZoneID(id)
}

func UnavailableCloudflareZone(id, name string) error {
	return unavailableCloudflareZone(id, name)
}

func (s *Storage) Client() *CloudflareClient {
	return s.client
}

func (s *Storage) Close() error {
	if s.logDB != nil {
		return s.logDB.Close()
	}

	return nil
}

func OpenFileForReading(path string) (*os.File, error) {
	return os.Open(path)
}
