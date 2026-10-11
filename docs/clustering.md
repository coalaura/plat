# Master/slave setup

`plat` remains the writable master. When `cluster.enabled` is true, replication shares its existing HTTP listener at `/-/replication`; no separate replication port is opened. `plat-slave` is a separate, DNS-only executable: UDP/TCP DNS and HTTP `/dns-query` behind a TLS-terminating reverse proxy, with no UI, management API, DynDNS endpoint, Cloudflare client initialization or management log database. Release archives include both executables. Build locally with `go build -o plat .` and `go build -o plat-slave ./cmd/slave` (use `builder build go --cgo` for the master's SQLite-enabled build).

## First run: start, copy certificates, restart

No OpenSSL commands or shared CA private key are needed. Run each node in its own working directory; all paths below are relative to that directory.

1. Start `plat` on the master. It creates `config.yml` if needed, `data/certs/master.crt`, `data/certs/master.key` and the empty `data/certs/slaves/` trust directory, even before replication is enabled.
2. Start `plat-slave` on each slave. It creates `slave.yml`, `data/certs/slave.crt` and `data/certs/slave.key`. It then exits with setup instructions because the master address is not configured yet.
3. Copy the master's **`data/certs/master.crt`** to **`data/certs/master.crt` on every slave**.
4. Copy each slave's **`data/certs/slave.crt`** to the master's **`data/certs/slaves/`** directory, giving each a unique filename, such as `slave-1.crt` and `slave-2.crt`.
5. Set `cluster.enabled: true` on the master. On each slave, set `master.address` to the master's existing base URL, such as `https://master.example.net` through a reverse proxy or `http://master.example.net:8080` when connecting directly. Use the HTTP/HTTPS port already exposed for plat; no extra firewall rule is needed.
6. Restart both sides. The slave synchronizes before it starts serving DNS and DoH for the first time.

Copy only public `.crt` files over a trusted channel, **never `.key` files**. No fingerprint entry is required. An empty master trust directory authorizes no slaves, but the master can still start. Trust files are loaded at startup: adding, replacing or removing a slave certificate requires a master restart; replacing the trusted master certificate requires a slave restart. Remove a slave's certificate and restart the master to revoke its access.

## Certificates and trust

Generated identities are self-signed Ed25519 certificates valid for ten years. Existing certificate/key pairs are reused on restart. A partial, corrupt or mismatched pair causes startup to fail without overwriting it; restore the original pair from backup. Certificates are never silently renewed, because changing them would invalidate the copies trusted by peers. To rotate an identity, stop that node, move both old files aside, restart to generate a new pair and exchange the new public certificate before reconnecting. Expired certificates are rejected during TLS verification.

Replication always uses verified, mutually authenticated TLS 1.3 with ALPN `plat-replication/1`, carried inside a binary WebSocket connection. This inner TLS session remains end-to-end encrypted and authenticated even over plain HTTP or through an HTTPS-terminating reverse proxy. Each side verifies the certificate normally **and** pins the exact copied peer certificate. There is no trust-on-first-use or disabled verification. The generated master certificate and the slave's verification always use the fixed logical DNS identity `plat-master`, independently of the hostname or IP address in `master.address`.

The copied certificates in `master.trusted_master` and `cluster.trusted_clients` are both trust anchors and exact certificate pins. Replication identities are generated automatically; no separate CA file or configurable server name is needed. nginx's outer HTTPS certificate is verified separately against the URL hostname using the slave's OS root CA trust store, so public certificates such as Let's Encrypt belong on the reverse proxy.

New keys, certificates, checkpoints and master data files use mode 0600 on Unix and a protected service-account/SYSTEM DACL on Windows. Keep their directories restricted to the service account as well. Trusted slaves receive the authoritative DNSSEC private signing keys.

## Master `config.yml`

Add this to the existing master configuration to enable replication on its existing `server.port`:

```yaml
cluster:
  enabled: true
```

Optional `cluster.tls.certificate` and `cluster.tls.key` override the generated identity paths (set both). `cluster.trusted_clients` overrides `data/certs/slaves`. All `.crt` and `.pem` files in that directory must contain only public certificates; malformed certificate files prevent startup. Other file extensions and subdirectories are ignored.

### HTTP/HTTPS and reverse proxies

Slaves open an HTTP/1.1 WebSocket upgrade at `/-/replication`, using subprotocol `plat-replication-v1`. The endpoint uses certificate authentication inside the tunnel, independently of the management API bearer token. Ordinary HTTP routes continue to work on the same listener. Replication is disabled when `cluster.enabled` is omitted or false.

If a reverse proxy fronts plat, forward this route with WebSocket upgrades enabled (`Upgrade` and `Connection` headers and HTTP/1.1 to the backend). Many proxies handle WebSockets automatically; a proxy that strips upgrade headers or buffers the upgraded stream needs its route adjusted. Regular replication heartbeats keep the connection active. For `https://` addresses, the outer HTTPS certificate must also be valid for the URL hostname and trusted by the slave's operating system; the generated replication certificate authenticates the separate inner TLS session. The proxy does not need either node's replication private key or client-certificate configuration.

`master.address` is a base URL, not a bare `host:port` or the endpoint URL. The slave appends `/-/replication`; a base path such as `https://example.net/plat` is supported if the proxy strips `/plat` before forwarding to plat.

## Slave `slave.yml`

`slave.yml` is generated on first run; the configuration path is fixed. The checkpoint is always stored at `data/checkpoint.json`. Use `plat-slave --version` or `plat-slave -v` to print the version. The slave opens one outbound connection to the master; it needs no inbound replication port.

```yaml
master:
  address: https://master.example.net
  trusted_master: data/certs/master.crt
  tls:
    certificate: data/certs/slave.crt
    key: data/certs/slave.key
dns:
  enabled: true
  port: 53
  fallback_ip: "9.9.9.9"
  fallback_https: "https://dns.quad9.net/dns-query"
http:
  address: ":8080"
```

The `master.tls` paths and `master.trusted_master` are optional and default to the values shown. If overriding identity paths, set both `certificate` and `key`; plat still generates the identity when both files are absent.

Expose both UDP and TCP port 53 and let nginx serve public HTTPS on port 443, proxying `/dns-query` to the slave's HTTP listener on port 8080. Unknown queries use the Quad9 fallbacks by default; empty fallback values disable recursion. Configure delegation, glue and parent DS records as described in the main DNSSEC documentation. Slaves sign locally with the replicated keys, refresh derived signatures independently and retain master-controlled SOA serials. Cloudflare-signed zones retain their authoritative forwarding behavior.

### DoH reverse proxy

The slave serves `/dns-query` over plain HTTP at `http.address` (default `:8080`). Configure nginx to terminate TLS with the public DoH certificate and forward requests to `http://<slave-address>:8080/dns-query`, preserving the query string and request body. DoH clients continue to use the public `https://dns.example.net/dns-query` URL.

## Troubleshooting synchronization

`Waiting for first complete synchronization` means no complete checkpoint is available yet. The slave logs failed connection attempts and their retry delay, successful connections and completed synchronization. The master logs rejected replication TLS handshakes and synchronization failures.

WebSocket upgrade requests carry `User-Agent: plat-slave` because some reverse proxies reject requests with an empty user agent.

- `open replication WebSocket`: check connectivity to `master.address`, the outer HTTPS certificate, `cluster.enabled` and forwarding of `/-/replication` with HTTP/1.1 WebSocket upgrade headers. A working management frontend alone does not verify WebSocket forwarding.
- `replication TLS handshake`: check that `master.trusted_master` contains the master's generated replication certificate. Check the master's log for client-certificate rejection and restart the master after adding the slave's public certificate to `cluster.trusted_clients`.
- `synchronize replica`: check both nodes' logs, including checkpoint filesystem errors and connection timeouts.

Initial synchronization is outbound from the slave to the master. The slave's public DoH hostname, nginx configuration and HTTPS certificate are not required for that connection.

## Consistency and recovery

A new slave starts serving only after the first complete, persisted synchronization (including an empty dataset). A valid checkpoint is served immediately after restart, while reconciliation happens in the background. The previous complete state stays available during disconnection, interrupted transfers, persistence errors and resynchronization. Invalid/corrupt checkpoints cause startup to fail rather than serve unverified data. Slave storage is read-only; there is no promotion or local edit path.

Each connection receives an immutable snapshot at a master epoch/revision, a paged zone/hash manifest and requested zones from that same snapshot. Deletions are staged. Concurrent commits are replayed in order before a completion marker atomically persists and publishes the entire staged state. Subsequent commits are persisted and published individually. Epoch changes after master restart, sequence gaps and resulting-hash mismatches force a fresh reconciliation. Hashes cover versioned, deterministically ordered authoritative records, metadata, DNSSEC configuration and keys; derived signature timestamps are excluded. Zone hashes are cached between changes.

Heartbeats default to one second; five seconds without inbound frames closes a connection. Reconnects use exponential backoff (250 ms to 15 seconds, plus up to 50% jitter). Connection health and acknowledged replication progress are tracked separately. Idle heartbeats do not touch the checkpoint or scan/hash zones. Application frames are limited to 64 KiB, transfers use acknowledged 32 KiB chunks to bound transport buffering and per-slave commit queues are bounded to 256 events/16 MiB. Queue overflow disconnects the slow slave for a fresh snapshot without blocking master writes or DNS queries. Initial reconciliation has a five-minute deadline. Limits are 64 MiB per canonical zone, 128 MiB total canonical staged state, 100,000 zones and 256 MiB per checkpoint.

Replication is **asynchronous**: a successful master write means it was persisted on the master, not necessarily on any slave. If the master fails before its latest commits reach a slave, those latest updates may be absent from the serving slave and lost if the master's durable data cannot be recovered. There is no quorum, distributed election or automatic failover to writable service.

Back up the master's `data/records.yml` (records and authoritative DNSSEC state committed together) and the slave's complete `data/checkpoint.json`.
