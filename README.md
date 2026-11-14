# poppy-go

Accept Personal Agent Protocol (Poppy) traffic in a Go backend without pulling in a framework: discovery document, DPoP-bound session verification, and agent client-assertion checks as three small, dependency-free packages.

[Poppy](https://personalagentprotocol.org/) (draft 1.0) is an open protocol that lets personal agents discover companies, start sessions, and act for users through APIs, web pages, and company agents. The official implementation kit covers the company side through an agent skill and a Node validator. `poppy-go` is the Go library layer for the same company side: the pieces an API gateway or Go service needs before any business logic runs.

## What you get

| Package | What it does |
| --- | --- |
| `poppyjson` | Build, validate (spec MUST-level invariants), and serve `/.well-known/poppy.json` with correct content type and caching. |
| `session` | Verify the two credentials on every Poppy request: the DPoP proof (RFC 9449, ES256) and the Session Token it is bound to (`cnf.jkt`, RFC 7638 thumbprint), plus scope checks. Includes a bounded in-memory jti replay cache. |
| `clientassert` | Verify the Personal Agent's `private_key_jwt` client assertion (RFC 7523) at your token endpoint, resolving keys from the agent's published metadata (inline `jwks` or `jwks_uri`) with a bounded HTTPS fetcher and cache. |

Every package is standard-library only. No `jwt` dependency tree, no framework lock-in: everything works on plain `net/http`.

## Install

```bash
go get github.com/ofershap/poppy-go
```

## Usage

Serve the discovery document:

```go
doc := &poppyjson.Document{
    ProtocolVersion: "1.0",
    Organization:    poppyjson.Organization{Name: "Example Store", Domain: "example.com"},
    Auth:            &poppyjson.Auth{Issuer: "https://auth.example.com"},
    APIs:            []poppyjson.API{{Type: "openapi", Endpoint: "https://api.example.com"}},
}
h, err := poppyjson.Handler(doc, 3600) // fails fast on an invalid document
if err != nil { log.Fatal(err) }
mux.Handle(poppyjson.Path, h)
```

Verify a request's DPoP proof and Session Token:

```go
v := &session.Verifier{
    Issuer:     "https://auth.example.com",
    Audience:   "https://api.example.com",
    IssuerKeys: jwksKeyResolver,          // func(kid string) (crypto.PublicKey, error)
    Replay:     session.NewMemoryReplayCache(10 * time.Minute),
}

func ordersHandler(w http.ResponseWriter, r *http.Request) {
    raw, err := session.ExtractToken(r)  // Authorization: DPoP <token>; Bearer rejected
    if err != nil { http.Error(w, "unauthorized", 401); return }

    proof, err := v.VerifyProof(r, raw)  // htm/htu, iat window, jti replay, ath binding
    if err != nil { http.Error(w, "unauthorized", 401); return }

    tok, err := v.VerifyToken(raw, proof) // iss/aud/exp, cnf.jkt key binding
    if err != nil { http.Error(w, "unauthorized", 401); return }

    if !tok.RequireScopes("orders:read") { http.Error(w, "forbidden", 403); return }
    // tok.SessionID, tok.UserID (pairwise per company), tok.SignedIn
}
```

Verify a Personal Agent's client assertion at your token endpoint:

```go
cv := &clientassert.Verifier{
    TokenEndpoint: "https://auth.example.com/oauth/token",
    Fetcher:       clientassert.NewClient(), // cached, bounded, HTTPS-only
}
a, err := cv.Verify(ctx, clientAssertion) // RFC 7523 private_key_jwt, ES256
// a.ClientID is the verified agent identity
```

## What it doesn't do

- Sign-in flows (Direct, Device, Mediated), token issuance, or consent UI. This library verifies credentials; your OAuth server issues them.
- Conversations, web browser-session handoff, or extensions (operations, UCP). Discovery document fields exist; the protocols are out of scope.
- Automatic JWKS rotation for your issuer keys: `IssuerKeys` is a callback so you control caching and rotation.
- Conformance certification. `poppy-go` targets Poppy draft 1.0 and is checked by unit tests (positive and adversarial negative cases) but has not yet been run against the official Node validator and has not been independently security-audited. It is early-stage: evaluate it before trusting it with production traffic.

## Notes

- ES256 is the only supported signature algorithm, matching the one algorithm the spec requires every company to accept.
- DPoP `htu` comparison follows RFC 9449 (absolute URI without query).
- The replay cache is per-process; deploy multiple replicas behind a shared cache by implementing `session.ReplayCache`.
- The metadata fetcher treats agent client_ids as untrusted URLs: https-only, no non-https redirects, and only public IP destinations (checked per connection, including redirects and re-resolution). For agents inside a private network, supply your own `*http.Client` with an explicit destination policy.

<details>
<summary><strong>Q&amp;A</strong></summary>

**What is the Personal Agent Protocol (Poppy)?**
An open protocol (draft 1.0, initiated by Sierra) for companies and personal agents: a company publishes `/.well-known/poppy.json`, agents start sessions and sign users in through standard OAuth, and every API call carries a DPoP-bound session token.

**Does poppy-go work with Gin/Echo/Fiber?**
Yes. Verification takes an `*http.Request` and returns plain values, so any framework that exposes the request works.

**Why not use a generic JWT library?**
The Poppy company side needs a fixed, narrow shape: ES256-only DPoP proofs, `cnf.jkt` key binding, pairwise user IDs, and agent metadata resolution. Implementing exactly that on the standard library keeps the dependency tree empty and the audited surface small.

**Is there an official Go SDK?**
No. The official company kit is a coding-agent skill plus a Node validator. poppy-go is an independent implementation of the same draft spec.

</details>

---

[![gitshow](https://gitshow.dev/api/card/ofershap)](https://gitshow.dev/ofershap)

Built with [README Builder](https://github.com/ofershap/readme-builder) · MIT © [Ofer Shapira](https://github.com/ofershap)
