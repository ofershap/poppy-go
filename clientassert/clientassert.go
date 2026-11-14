// Package clientassert verifies a Personal Agent's client assertion at the
// Company's token endpoint (Poppy draft 1.0 spec 4.1). The assertion is a
// private_key_jwt (RFC 7523): a JWS whose iss and sub are the agent's
// client_id, an HTTPS URL hosting the agent's client metadata document,
// which publishes the agent's public keys as a JWKS.
//
// Poppy requires companies to accept assertions signed with ES256 and with
// PS384 (spec 4.1, 10.7), and to accept aud only when it is the Company's
// issuer as a single string, compared character for character - an array,
// or the token endpoint's URL, is rejected (spec 4.1, 10.4).
package clientassert

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/ofershap/poppy-go/internal/jose"
)

// Errors returned by assertion verification.
var (
	ErrMalformedAssertion = errors.New("clientassert: malformed assertion")
	ErrBadAlg             = errors.New("clientassert: assertion alg not allowed")
	ErrClientID           = errors.New("clientassert: client_id must be an https URL")
	ErrIssuerMismatch     = errors.New("clientassert: iss and sub must both equal client_id")
	ErrAudience           = errors.New("clientassert: aud must be the issuer, as a single string")
	ErrExpired            = errors.New("clientassert: assertion expired or not yet valid")
	ErrNoKey              = errors.New("clientassert: no matching key in agent metadata")
	ErrBadSignature       = errors.New("clientassert: assertion signature invalid")
	ErrMetadataFetch      = errors.New("clientassert: could not fetch agent metadata")
)

// Metadata is the agent's client metadata document, fetched from its
// client_id URL. Only the fields verification needs are modeled.
type Metadata struct {
	Issuer  string `json:"issuer"` // if present, must equal the client_id
	JWKSUri string `json:"jwks_uri"`
	JWKS    *JWKS  `json:"jwks"`
}

// JWKS is a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK is one public key: an EC P-256 key (ES256) or an RSA key (PS384),
// the two algorithms Poppy requires companies to accept (spec 4.1).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// IsEC reports whether the key is an EC P-256 key (ES256).
func (k JWK) IsEC() bool { return k.Kty == "EC" && k.Crv == "P-256" && k.X != "" && k.Y != "" }

// IsRSA reports whether the key is an RSA key (PS384).
func (k JWK) IsRSA() bool { return k.Kty == "RSA" && k.N != "" && k.E != "" }

// Fetcher retrieves the agent's metadata document and JWKS. *Client is a
// Fetcher; tests can substitute a fake.
type Fetcher interface {
	FetchMetadata(ctx context.Context, clientID string) (*Metadata, error)
	FetchJWKS(ctx context.Context, uri string) (*JWKS, error)
}

// Client fetches agent metadata over HTTPS with a bounded cache so the token
// endpoint does not fetch the client_id document on every assertion.
//
// Trust model: agent client_ids are arbitrary third-party URLs, so NewClient
// fetches only https URLs and dials only public IP destinations (checked per
// connection, initial request and every redirect hop). The client_id
// document itself is fetched without following redirects (spec 4.1: serve
// agent.json at exactly its URL); jwks_uri fetches follow https-only
// redirects. Deployments that intentionally talk to agents inside a private
// network must construct their own *http.Client with an explicit destination
// policy and set Client.HTTP - the default dialer refuses those
// destinations.
type Client struct {
	HTTP    *http.Client
	MaxBody int64 // default 64 KiB

	mu    sync.Mutex
	cache map[string]cacheEntry
	TTL   time.Duration // default 10 minutes
}

type cacheEntry struct {
	doc   any
	until time.Time
}

// MaxCacheEntries bounds the metadata/JWKS cache (default 1024) so a stream
// of distinct agent client_ids cannot grow memory without limit.
const MaxCacheEntries = 1024

// IsPublicAddr reports whether ip is a public unicast address. Loopback,
// private (RFC 1918 / ULA), link-local, unspecified, and multicast addresses
// are not public.
func IsPublicAddr(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	// 100.64.0.0/10 (CGNAT) is not globally routable either.
	if ip.Is4() && ip.As4()[0] == 100 && ip.As4()[1] >= 64 && ip.As4()[1] <= 127 {
		return false
	}
	return ip.IsGlobalUnicast()
}

// publicDialer returns a DialContext that rejects any connection whose
// resolved addresses include a non-public IP. Every connection (initial
// request and each redirect hop) is resolved and checked at dial time, so a
// hostname that later re-resolves to a private address (DNS rebinding) is
// rejected on the connection that would reach it.
func publicDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("clientassert: no addresses for %s", host)
		}
		for _, ip := range ips {
			na, ok := netip.AddrFromSlice(ip)
			if !ok || !IsPublicAddr(na) {
				return nil, fmt.Errorf("clientassert: refusing non-public destination %s", host)
			}
		}
		return d.DialContext(ctx, network, net.JoinHostPort(host, port))
	}
}

// NewClient returns a Client with production defaults. JWKS fetches reject
// redirects to non-https URLs: a downgrade redirect must not turn the fetch
// into SSRF. The client_id document is fetched without following redirects
// at all (spec 4.1).
func NewClient() *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = publicDialer()
	c := &Client{
		HTTP: &http.Client{
			Timeout:   10 * time.Second,
			Transport: tr,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if req.URL.Scheme != "https" {
					return fmt.Errorf("clientassert: refusing redirect to %s", req.URL.Scheme)
				}
				if len(via) >= 5 {
					return errors.New("clientassert: too many redirects")
				}
				return nil
			},
		},
		MaxBody: 64 << 10,
		cache:   make(map[string]cacheEntry),
		TTL:     10 * time.Minute,
	}
	return c
}

func (c *Client) maxBody() int64 {
	if c.MaxBody > 0 {
		return c.MaxBody
	}
	return 64 << 10
}

func (c *Client) ttl() time.Duration {
	if c.TTL > 0 {
		return c.TTL
	}
	return 10 * time.Minute
}

// httpClient returns the redirect-following client (JWKS fetches).
func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return NewClient().HTTP
}

// noRedirectClient wraps the configured client with redirects disabled, for
// the client_id document fetch (spec 4.1).
func (c *Client) noRedirectClient() *http.Client {
	base := c.httpClient()
	nr := *base
	nr.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &nr
}

func (c *Client) get(ctx context.Context, client *http.Client, rawurl string, out any) error {
	u, err := url.Parse(rawurl)
	if err != nil || u.Scheme != "https" {
		return ErrClientID
	}
	c.mu.Lock()
	if e, ok := c.cache[rawurl]; ok && time.Now().Before(e.until) {
		c.mu.Unlock()
		// Shallow-copy the cached document into out via JSON round-trip so
		// callers never share mutable state.
		b, _ := json.Marshal(e.doc)
		return json.Unmarshal(b, out)
	}
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMetadataFetch, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: HTTP %d", ErrMetadataFetch, res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, c.maxBody()))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMetadataFetch, err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%w: invalid JSON", ErrMetadataFetch)
	}
	c.mu.Lock()
	if len(c.cache) >= MaxCacheEntries {
		// Evict an arbitrary entry; the cache is an optimization, not state.
		for k := range c.cache {
			delete(c.cache, k)
			break
		}
	}
	c.cache[rawurl] = cacheEntry{doc: out, until: time.Now().Add(c.ttl())}
	c.mu.Unlock()
	return nil
}

// FetchMetadata fetches the client_id document without following redirects:
// the agent must serve its metadata at exactly the client_id URL (spec 4.1).
func (c *Client) FetchMetadata(ctx context.Context, clientID string) (*Metadata, error) {
	var m Metadata
	if err := c.get(ctx, c.noRedirectClient(), clientID, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// FetchJWKS implements Fetcher. Redirects are followed, https-only.
func (c *Client) FetchJWKS(ctx context.Context, uri string) (*JWKS, error) {
	var j JWKS
	if err := c.get(ctx, c.httpClient(), uri, &j); err != nil {
		return nil, err
	}
	return &j, nil
}

// Verifier checks client assertions for one issuer.
type Verifier struct {
	// Issuer is the Company's issuer identifier. The assertion's aud must
	// equal it exactly, as a single string: an array, or any other value
	// including the token endpoint's URL, is rejected (spec 4.1, 10.4).
	Issuer string
	// Fetcher retrieves agent metadata. Required.
	Fetcher Fetcher
	// MaxAssertionAge bounds assertion iat/exp window. Default 5 minutes.
	MaxAssertionAge time.Duration
	// SeenJTI, when set, records assertion jti values and rejects replays
	// (RFC 7523 §3 allows rejecting a reused jti). Return true on replay.
	SeenJTI func(clientID, jti string) bool
	// Now supplies the current time (test hook).
	Now func() time.Time
}

// Assertion is a verified client assertion.
type Assertion struct {
	ClientID string
	JTI      string
}

// Verify checks a client_assertion value (client_assertion_type is expected
// to be urn:ietf:params:oauth:client-assertion-type:jwt-bearer, RFC 7523;
// the caller checks that form field).
func (v *Verifier) Verify(ctx context.Context, assertion string) (*Assertion, error) {
	if v.Fetcher == nil {
		return nil, errors.New("clientassert: Verifier.Fetcher is required")
	}
	tok, err := jose.ParseCompact(assertion)
	if err != nil {
		return nil, ErrMalformedAssertion
	}
	header, err := jose.ParseHeader(tok.HeaderRaw)
	if err != nil {
		return nil, ErrMalformedAssertion
	}
	if header.Alg != "ES256" && header.Alg != "PS384" {
		return nil, ErrBadAlg
	}
	var claims struct {
		ISS string          `json:"iss"`
		Sub string          `json:"sub"`
		AUD json.RawMessage `json:"aud"`
		EXP int64           `json:"exp"`
		IAT int64           `json:"iat"`
		JTI string          `json:"jti"`
	}
	if err := json.Unmarshal(tok.PayloadRaw, &claims); err != nil {
		return nil, ErrMalformedAssertion
	}
	if u, err := url.Parse(claims.ISS); err != nil || u.Scheme != "https" {
		return nil, ErrClientID
	}
	if claims.Sub == "" || claims.Sub != claims.ISS {
		return nil, ErrIssuerMismatch
	}
	// aud must be a single string equal to the issuer (spec 10.4): arrays
	// and any other value are rejected character for character.
	var aud string
	if err := json.Unmarshal(claims.AUD, &aud); err != nil || aud != v.Issuer {
		return nil, ErrAudience
	}
	now := v.now()
	maxAge := v.MaxAssertionAge
	if maxAge <= 0 {
		maxAge = 5 * time.Minute
	}
	if claims.EXP == 0 || now.Unix() >= claims.EXP {
		return nil, ErrExpired
	}
	if claims.IAT > 0 && now.Sub(time.Unix(claims.IAT, 0)) > maxAge {
		return nil, ErrExpired
	}

	if claims.JTI != "" && v.SeenJTI != nil && v.SeenJTI(claims.ISS, claims.JTI) {
		return nil, fmt.Errorf("clientassert: assertion jti replayed")
	}

	keys, err := v.keysFor(ctx, claims.ISS)
	if err != nil {
		return nil, err
	}
	for _, jwk := range keys.Keys {
		if header.Kid != "" && jwk.Kid != "" && jwk.Kid != header.Kid {
			continue
		}
		switch {
		case header.Alg == "ES256" && jwk.IsEC():
			pub, err := jose.ECKeyFromJWK(jwk.X, jwk.Y)
			if err != nil {
				continue
			}
			if err := jose.VerifyES256(pub, tok.Input, tok.Signature); err == nil {
				return &Assertion{ClientID: claims.ISS, JTI: claims.JTI}, nil
			}
		case header.Alg == "PS384" && jwk.IsRSA():
			pub, err := jose.RSAKeyFromJWK(jwk.N, jwk.E)
			if err != nil {
				continue
			}
			if err := jose.VerifyPS384(pub, tok.Input, tok.Signature); err == nil {
				return &Assertion{ClientID: claims.ISS, JTI: claims.JTI}, nil
			}
		}
	}
	return nil, ErrNoKey
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// keysFor resolves the agent's published keys: inline jwks first, then
// jwks_uri (RFC 7517).
func (v *Verifier) keysFor(ctx context.Context, clientID string) (*JWKS, error) {
	md, err := v.Fetcher.FetchMetadata(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if md.Issuer != "" && md.Issuer != clientID {
		return nil, ErrIssuerMismatch
	}
	if md.JWKS != nil && len(md.JWKS.Keys) > 0 {
		return md.JWKS, nil
	}
	if md.JWKSUri != "" {
		return v.Fetcher.FetchJWKS(ctx, md.JWKSUri)
	}
	return nil, ErrNoKey
}
