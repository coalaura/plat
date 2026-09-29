package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/dns"
	"github.com/cloudflare/cloudflare-go/v7/option"
	"github.com/cloudflare/cloudflare-go/v7/zones"
)

type CloudflareClient struct {
	client *cloudflare.Client
}

func (c *CloudflareClient) ListZones(ctx context.Context) ([]*Zone, error) {
	var list []*Zone

	results, err := c.client.Zones.List(ctx, zones.ZoneListParams{
		Order:   cloudflare.F(zones.ZoneListParamsOrderName),
		PerPage: cloudflare.F(50.0),
	})

	for {
		if err != nil {
			return nil, err
		}

		if results == nil {
			break
		}

		for _, result := range results.Result {
			list = append(list, &Zone{
				ID:      result.ID,
				Name:    result.Name,
				Records: make(map[string]*Record),
			})
		}

		results, err = results.GetNextPage()
	}

	return list, nil
}

func (c *CloudflareClient) GetRecords(ctx context.Context, zoneId, zoneName string) ([]*Record, error) {
	var list []*Record

	results, err := c.client.DNS.Records.List(ctx, dns.RecordListParams{
		ZoneID:  cloudflare.F(zoneId),
		Order:   cloudflare.F(dns.RecordListParamsOrderName),
		PerPage: cloudflare.F(5000000.0),
	})

	for {
		if err != nil {
			return nil, err
		}

		if results == nil {
			break
		}

		for _, result := range results.Result {
			value, err := FormatRecordResponse(result)
			if err != nil {
				return nil, err
			}

			name := result.Name

			if name == zoneName {
				name = "@"
			} else if strings.HasSuffix(name, "."+zoneName) {
				name = name[:len(name)-(len(zoneName)+1)]
			}

			list = append(list, &Record{
				ID:      result.ID,
				Type:    string(result.Type),
				Name:    name,
				Content: value,
				TTL:     int64(result.TTL),
			})
		}

		results, err = results.GetNextPage()
	}

	return list, nil
}

func (c *CloudflareClient) CreateRecord(ctx context.Context, zoneId string, record *Record) error {
	param, err := record.ToCloudflareNew()
	if err != nil {
		return err
	}

	result, err := c.client.DNS.Records.New(ctx, dns.RecordNewParams{
		ZoneID: cloudflare.F(zoneId),
		Body:   param,
	})

	if err != nil {
		return err
	}

	record.ID = result.ID

	return err
}

func (c *CloudflareClient) UpdateRecord(ctx context.Context, zoneId string, record *Record) error {
	param, err := record.ToCloudflareEdit()
	if err != nil {
		return err
	}

	_, err = c.client.DNS.Records.Edit(ctx, record.ID, dns.RecordEditParams{
		ZoneID: cloudflare.F(zoneId),
		Body:   param,
	})

	return err
}

func (c *CloudflareClient) DeleteRecord(ctx context.Context, zoneId, recordId string) error {
	_, err := c.client.DNS.Records.Delete(ctx, recordId, dns.RecordDeleteParams{
		ZoneID: cloudflare.F(zoneId),
	})

	return err
}

func (c *CloudflareClient) GetDNSSEC(ctx context.Context, zoneID string) (DNSSECDetails, error) {
	result, err := c.client.DNS.DNSSEC.Get(ctx, dns.DNSSECGetParams{ZoneID: cloudflare.F(zoneID)})
	if err != nil {
		return DNSSECDetails{}, err
	}

	return asCloudflareDNSSECDetails(result), nil
}

func (c *CloudflareClient) SetDNSSEC(ctx context.Context, zoneID string, enabled bool) (DNSSECDetails, error) {
	status := dns.DNSSECEditParamsStatusDisabled

	if enabled {
		status = dns.DNSSECEditParamsStatusActive
	}

	result, err := c.client.DNS.DNSSEC.Edit(ctx, dns.DNSSECEditParams{
		ZoneID: cloudflare.F(zoneID), Status: cloudflare.F(status),
	})

	if err != nil {
		return DNSSECDetails{}, err
	}

	return asCloudflareDNSSECDetails(result), nil
}

func (c *CloudflareClient) DNSSECNameservers(ctx context.Context, zoneID string) ([]string, error) {
	zone, err := c.client.Zones.Get(ctx, zones.ZoneGetParams{ZoneID: cloudflare.F(zoneID)})
	if err != nil {
		return nil, err
	}

	nameservers, err := normalizeNameservers(zone.NameServers)
	if err != nil {
		return nil, err
	}

	if len(nameservers) == 0 {
		return nil, fmt.Errorf("cloudflare did not provide authoritative nameservers")
	}

	return nameservers, nil
}

func NewCloudflareClient(token string) *CloudflareClient {
	client := cloudflare.NewClient(option.WithAPIToken(token))

	return &CloudflareClient{client: client}
}

func asCloudflareDNSSECDetails(result *dns.DNSSEC) DNSSECDetails {
	details := DNSSECDetails{
		Provider:   "cloudflare",
		Enabled:    result.Status == dns.DNSSECStatusActive || result.Status == dns.DNSSECStatusPending,
		Status:     string(result.Status),
		DSRecord:   result.DS,
		Digest:     result.Digest,
		DigestType: result.DigestType,
		Algorithm:  result.Algorithm,
		PublicKey:  result.PublicKey,
		KeyTag:     uint16(result.KeyTag),
		Flags:      uint16(result.Flags),
		Protocol:   3,
	}

	return details
}
