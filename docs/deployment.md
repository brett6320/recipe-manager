# Deployment

The application is designed to run behind Cloudflare. Two origin topologies
are supported; pick one.

## Option A: Cloudflare Tunnel (no inbound ports)

`cloudflared` runs next to the app and connects out to Cloudflare. The origin
is never reachable from the internet, so this is the simplest and most secure
option.

1. Create a tunnel in Zero Trust → Networks → Tunnels and point the public
   hostname `recipes.example.com` at `http://127.0.0.1:8080` (or
   `http://recipe-manager:8080` inside the same compose network). An example
   config is in [`deploy/cloudflared.example.yml`](../deploy/cloudflared.example.yml).
2. Run the app with:

   ```sh
   RM_PUBLIC_URL=https://recipes.example.com
   RM_TRUSTED_PROXIES=cloudflare,127.0.0.1     # tunnel connects from localhost
   RM_REQUIRE_PROXY=true
   ```

   The tunnel preserves `CF-Connecting-IP`, so rate limits and audit logs see
   real client addresses.

## Option B: Proxied DNS + origin TLS

The origin has a public IP and Cloudflare proxies to it.

1. Create a **Cloudflare Origin Certificate** (SSL/TLS → Origin Server) and
   set SSL mode to **Full (strict)**.
2. Enable **Authenticated Origin Pulls** (SSL/TLS → Origin Server) and download
   Cloudflare's origin-pull CA certificate.
3. Run the app with TLS and the client CA so only Cloudflare can connect:

   ```sh
   RM_PUBLIC_URL=https://recipes.example.com
   RM_LISTEN=0.0.0.0:8443
   RM_TLS_CERT=/etc/recipe-manager/origin.pem
   RM_TLS_KEY=/etc/recipe-manager/origin.key
   RM_TLS_CLIENT_CA=/etc/recipe-manager/cloudflare-origin-pull-ca.pem
   RM_TRUSTED_PROXIES=cloudflare
   RM_REQUIRE_PROXY=true
   ```

4. Firewall the origin so port 8443 only accepts Cloudflare's IP ranges
   (https://www.cloudflare.com/ips/). `RM_REQUIRE_PROXY` is a second layer,
   not a substitute.

## Recommended Cloudflare settings

| Area | Setting |
|---|---|
| SSL/TLS | Full (strict); Always Use HTTPS; Minimum TLS 1.2; HSTS can be enabled at the edge too (the app already sends HSTS) |
| Security | Bot Fight Mode on; Security Level Medium or higher; Browser Integrity Check on |
| WAF | Managed ruleset on. Add a rate-limiting rule for `/login/*`, `/api/webauthn/*`, `/register`, `/setup`: e.g. 20 requests / minute per IP |
| Access (optional) | Put Cloudflare Access in front of the whole hostname for an extra identity layer. Passkey/TOTP still apply inside |
| Caching | Default is fine: the app sends `Cache-Control: no-store` on dynamic pages and lets `/static/*` be cached for an hour |
| Network | WebSockets not needed; HTTP/2 and HTTP/3 on |

Keep the embedded Cloudflare IP list current: when Cloudflare announces range
changes, update `cloudflareRanges` in `internal/config/config.go` or set
`RM_TRUSTED_PROXIES` explicitly.

## Docker Compose

`docker-compose.yml` in the repository root is production-ready:

- distroless static image, runs as uid 65532
- read-only root filesystem, `tmpfs` for `/tmp`, `cap_drop: ALL`,
  `no-new-privileges`, pid and memory limits
- `/data` volume for the SQLite database and the instance key
- health check via the binary's `-healthcheck` subcommand (no shell or curl in
  the image)

```sh
export RM_PUBLIC_URL=https://recipes.example.com
export RM_TRUSTED_PROXIES=cloudflare,127.0.0.1
export RM_REQUIRE_PROXY=true
docker compose up -d --build
```

To add `cloudflared` to the same compose project, add a service using
`cloudflare/cloudflared:latest` with `tunnel --no-autoupdate run --token …`
and point the tunnel at `http://recipe-manager:8080`; then remove the `ports`
mapping from the app service entirely.

## systemd (native)

```sh
useradd --system --home /var/lib/recipe-manager --shell /usr/sbin/nologin recipe-manager
install -d -o recipe-manager -g recipe-manager -m 0700 /var/lib/recipe-manager
install -m 0755 recipe-manager /usr/local/bin/recipe-manager
install -m 0644 deploy/recipe-manager.service /etc/systemd/system/
install -d -m 0750 -g recipe-manager /etc/recipe-manager
# create /etc/recipe-manager/env with the RM_* variables (mode 0640, group recipe-manager)
systemctl enable --now recipe-manager
```

The unit applies `ProtectSystem=strict`, `PrivateTmp`, `NoNewPrivileges`,
`ProtectHome`, a syscall filter, memory-deny-write-execute and restricts
address families to IPv4/IPv6. Only `/var/lib/recipe-manager` is writable.

## Backups

Everything lives in `RM_DATA_DIR`:

- `recipes.db` (+ `-wal`/`-shm` while running): SQLite in WAL mode. Use
  `sqlite3 recipes.db ".backup backup.db"` for a consistent copy, or stop the
  service and copy the files.
- `secret.key`: 32 random bytes that encrypt TOTP seeds. Losing it means every
  user must re-enrol their authenticator app (passkeys are unaffected).

## First run

Browse to `https://recipes.example.com/setup`. The page only exists while there
are zero accounts. Create the admin, then add a passkey or authenticator app
on the Security page; the app refuses to show anything else until you do.
Invite everyone else from Admin → "Create invite link" (single use, 48 hours).

## Upgrading

Pull, rebuild, restart. Schema migrations run automatically at start-up.
Rebuild on every Go security release too; the binary embeds the runtime.
