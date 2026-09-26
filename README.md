# plat

`plat` manages DNS zones and answers queries from its own records in `records.yml`. It works without Cloudflare; connect Cloudflare only if you want to import and sync Cloudflare zones. The name is from cadastral plats: clear maps of boundaries and lots; here, the same idea is applied to DNS zones and records.

## Installation

Download a pre-built release from the [releases page](https://github.com/coalaura/plat/releases/latest).

![Records view](.github/records.png)
*Browse zones and records in one view.*

![Edit record](.github/editing.png)
*Edit records with typed fields for DNS record types.*

![Syncing all zones](.github/syncing.png)
*Optionally sync Cloudflare zones with progress and logs.*

## Configuration

`config.yml` is created automatically on first run with defaults.

```yml
# enable verbose logging and diagnostics
debug: false

server:
  # port to run plat on (default: 8080)
  port: 8080
  # token for authentication, (default: "p4$$w0rd")
  token: p4$$w0rd

cloudflare:
  # optional cloudflare api token; leave empty to run plat on its own
  token: ""

dns:
  # enable built-in dns server (default: true)
  enabled: true
  # dns server port (default: 531)
  port: 531
  # optional ip fallback resolver for unknown queries (default: "9.9.9.9")
  fallback_ip: 9.9.9.9
  # optional DoH fallback resolver (default: "https://dns.quad9.net/dns-query")
  fallback_https: https://dns.quad9.net/dns-query
```

## Zones and Cloudflare

Sign in with `server.token` and select **New** in Zones to create a local zone. Add records there to serve them from plat's built-in DNS server or DNS-over-HTTPS endpoint. Local zones and their records are stored in `records.yml` and never sent to Cloudflare. You can delete a local zone after removing any DynDNS assignments to it.

Setting `cloudflare.token` enables Cloudflare zone import at startup and the existing sync controls. Cloudflare zones remain editable through plat; edits write through to Cloudflare when connected, and **Sync** pulls records from Cloudflare. If Cloudflare is unreachable at startup, plat continues using saved zones and records. With no token, plat can still serve and edit saved zones locally; Cloudflare sync controls are unavailable.

## License

GPL-3.0 (see `LICENSE`).
