# Master/slave setup

`plat` remains the writable master. When `cluster.enabled` is true, replication shares its existing HTTP listener at `/-/replication`; no separate replication port is opened. `plat-slave` is a separate, DNS-only executable: UDP/TCP DNS and HTTPS `/dns-query`, with no UI, management API, DynDNS endpoint, Cloudflare client initialization or management log database. Release archives include both executables. Build locally with `go build -o plat .` and `go build -o plat-slave ./cmd/slave` (use `builder build go --cgo` for the master's SQLite-enabled build).

## First run: start, copy certificates, restart

No OpenSSL commands or shared CA private key are needed. Run each node in its own working directory; all paths below are relative to that directory.

1. Start `plat` on the master. It creates `config.yml` if needed, `certs/master.crt`, `certs/master.key` and the empty `certs/slaves/` trust directory, even before replication is enabled.
2. Start `plat-slave` on each slave. It creates `slave.yml`, `certs/slave.crt`, `certs/slave.key` and a separate DoH identity (`certs/doh.crt`, `certs/doh.key`). It then exits with setup instructions because the master address is not configured yet.
3. Copy the master's **`certs/master.crt`** to **`certs/master.crt` on every slave**.
4. Copy each slave's **`certs/slave.crt`** to the master's **`certs/slaves/`** directory, giving each a unique filename, such as `slave-1.crt` and `slave-2.crt`.
5. Set `cluster.enabled: true` on the master. On each slave, set `master.address` to the master's existing base URL, such as `https://master.example.net` through a reverse proxy or `http://master.example.net:8080` when connecting directly. Use the HTTP/HTTPS port already exposed for plat; no extra firewall rule is needed.
6. Restart both sides. The slave synchronizes before it starts serving DNS and DoH for the first time.

Copy only public `.crt` files over a trusted channel, **never `.key` files**. No fingerprint entry is required. An empty master trust directory authorizes no slaves, but the master can still start. Trust files are loaded at startup: adding, replacing or removing a slave certificate requires a master restart; replacing the trusted master certificate requires a slave restart. Remove a slave's certificate and restart the master to revoke its access.

## Certificates and trust

Generated identities are self-signed Ed25519 certificates valid for ten years. Existing certificate/key pairs are reused on restart. A partial, corrupt or mismatched pair causes startup to fail without overwriting it; restore the original pair from backup. Certificates are never silently renewed, because changing them would invalidate the copies trusted by peers. To rotate an identity, stop that node, move both old files aside, restart to generate a new pair and exchange the new public certificate before reconnecting. Expired certificates are rejected during TLS verification.

Replication always uses verified, mutually authenticated TLS 1.3 with ALPN `plat-replication/1`, carried inside a binary WebSocket connection. This inner TLS session remains end-to-end encrypted and authenticated even over plain HTTP or through an HTTPS-terminating reverse proxy. In automatic mode each side verifies the certificate normally **and** pins the exact copied peer certificate. There is no trust-on-first-use or disabled verification. The generated master certificate has the logical DNS identity `plat-master`; leave the slave's `server_name` at `plat-master` even when connecting to a different hostname or IP address. That name is authenticated by the copied certificate, independently of the network address.

New keys, certificates, checkpoints and master data files use mode 0600 on Unix and a protected service-account/SYSTEM DACL on Windows. Keep their directories restricted to the service account as well. Trusted slaves receive the authoritative DNSSEC private signing keys.

## Master `config.yml`

Add this to the existing master configuration to enable replication on its existing `server.port`:

```yaml
cluster:
  enabled: true
```

Optional `cluster.tls.certificate` and `cluster.tls.key` override the generated identity paths (set both). `cluster.trusted_clients` overrides `certs/slaves`. All `.crt` and `.pem` files in that directory must contain only public certificates; malformed certificate files prevent startup. Other file extensions and subdirectories are ignored.

### HTTP/HTTPS and reverse proxies

Slaves open an HTTP/1.1 WebSocket upgrade at `/-/replication`, using subprotocol `plat-replication-v1`. The endpoint uses certificate authentication inside the tunnel, independently of the management API bearer token. Ordinary HTTP routes continue to work on the same listener. Replication is disabled when `cluster.enabled` is omitted or false.

If a reverse proxy fronts plat, forward this route with WebSocket upgrades enabled (`Upgrade` and `Connection` headers and HTTP/1.1 to the backend). Many proxies handle WebSockets automatically; a proxy that strips upgrade headers or buffers the upgraded stream needs its route adjusted. Regular replication heartbeats keep the connection active. For `https://` addresses, the outer HTTPS certificate must also be valid for the URL hostname and trusted by the slave's operating system; the generated replication certificate authenticates the separate inner TLS session. The proxy does not need either node's replication private key or client-certificate configuration.

`master.address` is a base URL, not a bare `host:port` or the endpoint URL. The slave appends `/-/replication`; a base path such as `https://example.net/plat` is supported if the proxy strips `/plat` before forwarding to plat. The former dedicated-port configuration is replaced by `cluster.enabled` and this HTTP/HTTPS base URL.

## Slave `slave.yml`

`slave.yml` is generated on first run; the configuration path is fixed. Use `plat-slave --version` or `plat-slave -v` to print the version. The slave opens one outbound connection to the master; it needs no inbound replication port.

```yaml
master:
  address: https://master.example.net
  server_name: plat-master
  trusted_master: certs/master.crt
  tls:
    certificate: certs/slave.crt
    key: certs/slave.key
checkpoint: data/slave.json
dns:
  enabled: true
  port: 53
  fallback_ip: ""
  fallback_https: ""
https:
  address: ":443"
  certificate: certs/doh.crt
  key: certs/doh.key
```

Expose both UDP and TCP port 53 and HTTPS port 443 as appropriate. With empty fallback values, the slave serves its replicated authoritative data without enabling recursion. Configure delegation, glue and parent DS records as described in the main DNSSEC documentation. Slaves sign locally with the replicated keys, refresh derived signatures independently and retain master-controlled SOA serials. Cloudflare-signed zones retain their authoritative forwarding behavior.

### DoH certificate

The generated DoH certificate is separate from the replication identity. By default its SANs cover the machine hostname, `localhost`, `127.0.0.1` and `::1`. Set `https.names` to a list of DNS names/IP addresses before generating it to serve a different identity (for example, `names: [dns.example.net]`). Changing this list does not replace an existing certificate; move both DoH files aside to regenerate them deliberately.

For private DoH clients, install/trust `certs/doh.crt` in those clients and use a name listed in that certificate. Public browsers and resolvers do not automatically trust self-signed certificates. For publicly trusted DoH, point `https.certificate` and `https.key` at an existing public-CA certificate/full chain and key; plat reuses them. Restart the slave after replacing those files.

### Existing private-CA deployments

The manual CA workflow is still supported. Setting `tls.ca` selects it instead of copied-certificate trust; replication certificates/keys must already exist in that mode. Issue a master certificate with the master's DNS name in its SAN and `serverAuth` usage and a distinct `clientAuth` certificate for every slave. On the master, configure `cluster.tls.certificate`, `cluster.tls.key`, `cluster.tls.ca` and `cluster.clients` (a map from slave name to its 64-character hexadecimal SHA-256 leaf-certificate fingerprint). On each slave, configure `master.tls.certificate`, `master.tls.key`, `master.tls.ca` and `master.server_name` matching the master certificate. Omit `trusted_clients`/`trusted_master` when using CA mode.

The master verifies both the client chain and the fingerprint allowlist. Obtain a fingerprint using `openssl x509 -in slave-1.crt -outform DER | openssl dgst -sha256`; copy only the 64 hexadecimal characters. Certificate renewal changes that fingerprint, so update the allowlist and restart the master. Distribute only the CA certificate, never its private key.

## Consistency and recovery

A new slave starts serving only after the first complete, persisted synchronization (including an empty dataset). A valid checkpoint is served immediately after restart, while reconciliation happens in the background. The previous complete state stays available during disconnection, interrupted transfers, persistence errors and resynchronization. Invalid/corrupt checkpoints cause startup to fail rather than serve unverified data. Slave storage is read-only; there is no promotion or local edit path.

Each connection receives an immutable snapshot at a master epoch/revision, a paged zone/hash manifest and requested zones from that same snapshot. Deletions are staged. Concurrent commits are replayed in order before a completion marker atomically persists and publishes the entire staged state. Subsequent commits are persisted and published individually. Epoch changes after master restart, sequence gaps and resulting-hash mismatches force a fresh reconciliation. Hashes cover versioned, deterministically ordered authoritative records, metadata, DNSSEC configuration and keys; derived signature timestamps are excluded. Zone hashes are cached between changes.

Heartbeats default to one second; five seconds without inbound frames closes a connection. Reconnects use exponential backoff (250 ms to 15 seconds, plus up to 50% jitter). Connection health and acknowledged replication progress are tracked separately. Idle heartbeats do not touch the checkpoint or scan/hash zones. Application frames are limited to 64 KiB, transfers use acknowledged 32 KiB chunks to bound transport buffering and per-slave commit queues are bounded to 256 events/16 MiB. Queue overflow disconnects the slow slave for a fresh snapshot without blocking master writes or DNS queries. Initial reconciliation has a five-minute deadline. Limits are 64 MiB per canonical zone, 128 MiB total canonical staged state, 100,000 zones and 256 MiB per checkpoint.

Replication is **asynchronous**: a successful master write means it was persisted on the master, not necessarily on any slave. If the master fails before its latest commits reach a slave, those latest updates may be absent from the serving slave and lost if the master's durable data cannot be recovered. There is no quorum, distributed election or automatic failover to writable service.

Back up the master's `data/records.yml` (records and authoritative DNSSEC state committed together), any legacy `data/dnssec.yml` still present and the slave's complete `data/slave.json`. Existing records/DNSSEC YAML files are read compatibly; committed zones migrate their DNSSEC state into `records.yml`, with an explicit marker preventing stale legacy settings from being restored. Do not downgrade to an older master binary after that migration without restoring a matching pre-migration backup.
