# Contributing

Issues and pull requests are welcome.

## Setup

Go 1.26 or newer. Standard library only; no other dependencies for the
library or tests.

## Checks

Run everything CI runs before opening a PR:

```bash
go vet ./...
gofmt -l .
go test -race ./...
```

## Rules

- Behaviour follows the Poppy draft 1.0 spec and is verified against the
  official Node validator. If the spec or validator changes, update the
  golden vectors in the same change.
- Keep every package standard-library only. No new dependency without an
  issue first.
- Claims in the README must match what the tests demonstrate.
