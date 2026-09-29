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

Setting `cloudflare.token` enables Cloudflare zone import at startup and the existing sync controls. Cloudflare zones remain editable through plat; edits write through to Cloudflare when connected and **Sync** pulls records from Cloudflare. If Cloudflare is unreachable at startup, plat continues using saved zones and records. With no token, plat can still serve and edit saved zones locally; Cloudflare sync controls are unavailable.

## DNSSEC

Select a zone and open **DNSSEC** in the records toolbar. **Plat** is the default signing provider for both local zones and imported Cloudflare zones. Enter the nameservers that will serve the zone from plat and select **Enable DNSSEC**. Plat generates an Ed25519 combined signing key (algorithm 15, flags 257), publishes DNSKEY and RRSIG records and uses signed NSEC records for authenticated denial of existence. Responses support aliases, wildcards, empty non-terminals and signed or unsigned child delegations. Recursive resolvers use these records to validate the zone.

The modal exposes copyable **DS Record**, **Digest**, **Digest Type**, **Algorithm**, **Public Key**, **Key Tag**, **Flags**, **Protocol** and **DNSKEY Record** values. The DS uses SHA-256 (digest type 2). Signing status means signatures are being served; it does not assert that public delegation and the parent DS have been configured or validated.

For public DNSSEC, configure your registrar's nameserver delegation to point to servers running plat, provide registrar glue and matching A/AAAA records when the nameservers are inside the zone and make those servers reachable on **UDP and TCP port 53**. Plat's default DNS port is 531; change `dns.port` to 53 or arrange forwarding for both transports. Each authoritative server must serve the same signed zone and keys. Once delegation is ready, publish the displayed DS through the registrar or parent-zone operator. The DS belongs in the **parent zone**, not at the signed zone's own apex. Remove any DS for a previous signer as part of a coordinated migration; all delegated servers must match the published DS during the transition.

Plat supplies the configured apex NS records and generates an SOA when none is present. Generated DNSSEC records are served automatically rather than inserted into the editable records table. Imported records continue using Cloudflare's existing edit/sync behavior, while plat supplies its own signatures when selected as signer.

Keys and per-zone settings are saved separately in `dnssec.yml`, with owner-only file permissions where supported and excluded from Git. Back up this file together with `records.yml`; losing the private key requires a new key and a parent DS change. Signatures have a 14-day validity period and refresh on demand after 24 hours, including after a period without queries. Record edits, deletions, DynDNS updates and Cloudflare sync invalidate the signed snapshot immediately. The signing key remains stable across restarts and disable/re-enable cycles so the parent DS remains stable; key rollover requires coordination with the parent zone.

For a connected Cloudflare zone, choose **Cloudflare** to inspect existing Cloudflare DNSSEC, enable it and copy its registrar values. The Cloudflare API token needs **Zone DNS Settings: Read/Write** and access to the zone. Cloudflare manages its own signing keys; plat relays queries for a Cloudflare-signed zone to Cloudflare's authoritative nameservers. Keep the public delegation pointed to Cloudflare in this mode.

Before disabling DNSSEC, remove the parent DS and allow its cached copies to expire, then confirm this in the modal. Disable the current provider before switching providers or deleting a signed local zone. Plat retains its key when disabled.

Authenticated management endpoints are `GET /-/{zone}/dnssec` and `PUT /-/{zone}/dnssec`. GET accepts `?provider=plat` or `?provider=cloudflare` to inspect a provider. PUT accepts `enabled`, `provider`, `nameservers` and `parent_ds_removed`; private signing keys are never returned by the API.

## License

GPL-3.0 (see `LICENSE`).
