package main

import (
	"context"

	"github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/dns"
	"github.com/cloudflare/cloudflare-go/v7/option"
	"github.com/cloudflare/cloudflare-go/v7/zones"
)

type CloudflareClient struct {
	client *cloudflare.Client
}

func NewCloudflareClient(token string) *CloudflareClient {
	client := cloudflare.NewClient(option.WithAPIToken(token))

	return &CloudflareClient{
		client: client,
	}
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
				ID:   result.ID,
				Name: result.Name,
			})
		}

		results, err = results.GetNextPage()
	}

	return list, nil
}

func (c *CloudflareClient) GetRecords(ctx context.Context, zoneId string) ([]*Record, error) {
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
			list = append(list, &Record{
				ID:    result.ID,
				Type:  string(result.Type),
				Name:  result.Name,
				Value: result.Content,
				TTL:   int64(result.TTL),
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
