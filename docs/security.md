# Security notes

This document describes what the application does to stay safe on the public
internet and what the operator is still responsible for.

## Threat model

Attackers are assumed to be able to reach the Cloudflare edge from anywhere,
to craft arbitrary HTTP requests, to lure logged-in users to hostile pages, and
to submit hostile recipe files and URLs for import. Cloudflare and the host OS
are trusted. Other authenticated users are *not* trusted with anything beyond
what has been explicitly shared with them.

## Authentication

- **Passkeys** (WebAuthn): discoverable credentials, user verification
  *required*, challenge stored server-side for three minutes and consumed
  once, RP ID/origin pinned to `RM_PUBLIC_URL`, signature counter and clone
  detection honoured, credentials stored as public keys only.
- **TOTP**: SHA-1/6 digits/30 s for authenticator compatibility; seeds are
  AES-256-GCM encrypted with `secret.key` (bound to the user handle as AAD);
  ±1 step skew; the highest accepted step is stored so a code can never be
  reused; 5 failures per 10 minutes lock the IP *and* the username for 15
  minutes; failed attempts take a fixed minimum time.
- **Enrolment rule**: an account with no passkey and no confirmed TOTP can only
  reach the Security page. Unenrolled accounts older than two hours are
  deleted automatically. The last remaining method cannot be removed.
- **Registration**: closed. The first account is created once at `/setup`;
  afterwards only single-use, 48-hour invite codes (stored hashed, shown to
  the admin exactly once via a short-lived cookie, never logged) admit users.

## Sessions and CSRF

- 32 random bytes, stored as SHA-256, cookie `__Host-session` with `Secure`,
  `HttpOnly`, `SameSite=Strict`, absolute TTL (30 d) and idle timeout (7 d).
  Login rotates the session; users can revoke all other sessions.
- State-changing requests must carry `Sec-Fetch-Site: same-origin` or an
  `Origin`/`Referer` matching `RM_PUBLIC_URL`. Combined with SameSite=Strict
  this blocks CSRF without per-form tokens. `Referrer-Policy: same-origin`
  keeps those headers populated without leaking URLs to third parties.

## Browser hardening

`Content-Security-Policy: default-src 'none'; script-src 'self'; style-src
'self'; img-src 'self' https: data:; connect-src 'self'; form-action 'self';
base-uri 'none'; frame-ancestors 'none'; object-src 'none'`, plus HSTS
(2 years, preload), `X-Content-Type-Options`, `X-Frame-Options: DENY`,
`Permissions-Policy` restricting everything except WebAuthn, COOP/CORP
`same-origin`. There are no inline scripts or styles anywhere. External recipe
images are loaded with `referrerpolicy="no-referrer"`; external links carry
`rel="noopener noreferrer nofollow"`.

## Authorisation

Every recipe, folder, group and share operation re-derives the caller's
permission in SQL. A recursive CTE combines ownership, direct recipe shares,
shares on any ancestor folder and group membership, yielding the best of
none/view/edit/owner. Objects a user cannot see return 404 so their existence
is not disclosed. Only owners can share, move, or delete. Group management is
limited to the group's creator and admins; members can always leave.

## Input handling

All user- or import-supplied text goes through `recipes.Clean` /
`CleanMultiline`: control characters, zero-width and bidirectional override
characters are removed, whitespace is collapsed, and each field has a hard
length cap. URLs must be absolute `http(s)` without credentials or shell/HTML
metacharacters; anything else (e.g. `javascript:`) is dropped. Output is
escaped by `html/template`. SQL uses bound parameters everywhere; `LIKE`
wildcards in search are escaped. Redirect targets taken from forms are matched
against a strict regular expression.

## Import pipeline

- **URL fetch**: a custom dialer resolves the hostname, rejects anything that is
  not globally routable (loopback, RFC 1918, 169.254.0.0/16 incl. cloud
  metadata, 100.64.0.0/10, multicast, broadcast, TEST-NETs, `::1`, `fe80::/10`,
  `fc00::/7`, `2001:db8::/32`, IPv4-mapped IPv6) and then dials the validated
  IP so a second lookup cannot rebind. Ports other than 80/443, URLs with
  credentials, `localhost`/`.local`/`.internal` names and non-http schemes are
  refused before any connection. Up to 5 redirects, each re-validated.
  Environment proxies are ignored. 20 s total budget, 8 MB body cap, no
  cookies.
- **Parsers**: JSON is walked with a depth limit; HTML is tokenised with
  `script`, `style`, `iframe` etc. skipped and tags inside JSON-LD fields
  stripped; PDF parsing runs under `recover()` with page (50) and text (512
  KB) caps. Multipart uploads use a route-specific body limit and temp files
  are removed.
- **Result**: the parsed recipe is rendered into the editor and nothing is
  written until the user presses Save. Repeated failed imports lock the user
  out of importing for 15 minutes.

## Rate limiting and logging

A global per-IP token bucket (50 r/s, burst 100) and a stricter one on
authentication routes (1 r/s, burst 15) sit behind Cloudflare. Client IPs are
taken from `CF-Connecting-IP` only when the TCP peer is a configured trusted
proxy; otherwise the peer address is used. With `RM_REQUIRE_PROXY=true`
non-proxy connections are refused outright. Logs are structured, contain no
secrets or request bodies, and record logins, enrolments, failed attempts and
administrative actions.

## Process and supply chain

- Pure-Go, `CGO_ENABLED=0`, `-trimpath`, stripped; ~10 direct dependencies.
- Distroless static image, `USER 65532`, read-only root FS, `cap_drop: ALL`,
  `no-new-privileges`, pid/memory limits (compose). Hardened systemd unit for
  native deployments.
- CI runs `go vet`, race tests, `govulncheck`, golangci-lint with gosec,
  CodeQL (security-extended) and hadolint on every change; Dependabot tracks
  Go modules, GitHub Actions and the base image weekly.

## Operator responsibilities

- Keep the origin unreachable except via Cloudflare (tunnel, or firewall +
  Authenticated Origin Pulls + `RM_REQUIRE_PROXY`).
- Back up `RM_DATA_DIR`; protect `secret.key`.
- Rebuild and redeploy when Go or a dependency publishes a security fix.
- Review the Admin page occasionally: remove stale users, check that everyone
  has a passkey.

## Reporting

See [SECURITY.md](../SECURITY.md).
