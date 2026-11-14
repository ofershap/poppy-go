# Security Policy

## Reporting a vulnerability

Please report security issues through GitHub's private vulnerability reporting
("Report a vulnerability" on the Security tab of this repository). Do not open
a public issue for a vulnerability.

## Scope notes

poppy-go verifies signed headers, delegation chains and client assertions; it
is security-critical code by nature. Key material is never logged. The
metadata fetcher is bounded (HTTPS only, size and timeout caps, untrusted-URL
policy) and performs no other network calls.
