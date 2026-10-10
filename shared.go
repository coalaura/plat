package main

import (
	"plat/internal/dnsserver"
	"plat/internal/storage"
)

type Storage = storage.Storage
type Zone = storage.Zone
type Record = storage.Record
type DynDNSUserRequest = storage.DynDNSUserRequest
type DNSSECRequest = storage.DNSSECRequest
type DNSServer = dnsserver.DNSServer
type ConfigDNS = dnsserver.Config

var (
	errInvalidZoneName           = storage.ErrInvalidZoneName
	errZoneExists                = storage.ErrZoneExists
	errLocalZoneNotFound         = storage.ErrLocalZoneNotFound
	errZoneAssigned              = storage.ErrZoneAssigned
	errCloudflareZoneUnavailable = storage.ErrCloudflareZoneUnavailable
	errDynDNSUserNotFound        = storage.ErrDynDNSUserNotFound
	isLocalZoneID                = storage.IsLocalZoneID
	unavailableCloudflareZone    = storage.UnavailableCloudflareZone
	HandleDynDNSUpdate           = storage.HandleDynDNSUpdate
	NewDoHRequest                = dnsserver.NewDoHRequest
)

func LoadStorage(config *Config) (*Storage, error) {
	return storage.LoadStorage(config.Cloudflare.Token)
}

func NewDNSServer(config *Config, data *Storage) *DNSServer {
	return dnsserver.NewDNSServer(config.DNS, data)
}
