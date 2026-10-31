# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](../../security/advisories/new) for this
repository. Do not open public issues for security problems.

## Supported versions

Only the latest commit on `main` is supported. Rebuild and redeploy after
every merge; the CI pipeline runs `govulncheck`, CodeQL and gosec on each
change, and Dependabot keeps Go, Docker and Actions dependencies current.

## Hardening notes

See `docs/deployment.md` for the recommended Cloudflare, container and
systemd configuration. The application has no password authentication by
design: every account must hold a passkey or a TOTP enrolment.
