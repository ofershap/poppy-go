// Package clientassert verifies a Personal Agent's client assertion at the
// Company's token endpoint (Poppy draft 1.0 spec 4.2: the token endpoint
// verifies each Personal Agent's client assertion against its published
// keys). The assertion is a private_key_jwt (RFC 7523): a JWS whose iss and
// sub are the agent's client_id, an HTTPS URL hosting the agent's client
// metadata document, which publishes the agent's public keys as a JWKS.
package clientassert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Errors returned by assertion verification.
var (
	ErrMalformedAssertion = errors.New("clientassert: malformed assertion")
	ErrBadTyp             = errors.New("clientassert: assertion typ must be jwt")
	ErrBadAlg             = errors.New("clientassert: assertion alg not allowed")
	ErrClientID           = errors.New("clientassert: client_id must be an https URL")
	ErrIssuerMismatch     = errors.New("clientassert: iss and sub must both equal client_id")
	ErrAudience           = errors.New("clientassert: aud must name the token endpoint")
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

// JWK is one public key. Only EC P-256 keys are supported (ES256 is the one
// algorithm Poppy requires, spec 3.2).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (k JWK) publicKey() (*ecdsa.PublicKey, error) {
	if k.Kty != "EC" || k.Crv != "P-256" {
		return nil, ErrNoKey
	}
	xb, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, ErrNoKey
	}
	yb, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, ErrNoKey
	}
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, ErrNoKey
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// Fetcher retrieves the agent's metadata document and JWKS. *Client is a
// Fetcher; tests can substitute a fake.
type Fetcher interface {
	FetchMetadata(ctx context.Context, clientID string) (*Metadata, error)
	FetchJWKS(ctx context.Context, uri string) (*JWKS, error)
}

// Client fetches agent metadata over HTTPS with a bounded cache so the token
// endpoint does not fetch the client_id document on every assertion.
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

// NewClient returns a Client with production defaults. The HTTP client
// rejects redirects to non-https URLs: the client_id is required to be an
// https URL, and a downgrade redirect must not turn the fetch into SSRF.
func NewClient() *Client {
	return &Client{
		HTTP: &http.Client{
			Timeout: 10 * time.Second,
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

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (c *Client) get(ctx context.Context, rawurl string, out any) error {
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
	res, err := c.httpClient().Do(req)
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

// FetchMetadata implements Fetcher.
func (c *Client) FetchMetadata(ctx context.Context, clientID string) (*Metadata, error) {
	var m Metadata
	if err := c.get(ctx, clientID, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// FetchJWKS implements Fetcher.
func (c *Client) FetchJWKS(ctx context.Context, uri string) (*JWKS, error) {
	var j JWKS
	if err := c.get(ctx, uri, &j); err != nil {
		return nil, err
	}
	return &j, nil
}

// Verifier checks client assertions for one token endpoint.
type Verifier struct {
	// TokenEndpoint is the exact URL the assertion's aud must name.
	TokenEndpoint string
	// Fetcher retrieves agent metadata. Required.
	Fetcher Fetcher
	// MaxAssertionAge bounds assertion iat/exp window. Default 5 minutes.
	MaxAssertionAge time.Duration
	// SeenJTI, when set, records assertion jti values and rejects replays
	// (RFC 7523 §3: assertions are one-time-use). Return true on replay.
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
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedAssertion
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrMalformedAssertion
	}
	var header struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, ErrMalformedAssertion
	}
	if header.Alg != "ES256" {
		return nil, ErrBadAlg
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformedAssertion
	}
	var claims struct {
		ISS string `json:"iss"`
		Sub string `json:"sub"`
		AUD string `json:"aud"`
		EXP int64  `json:"exp"`
		IAT int64  `json:"iat"`
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, ErrMalformedAssertion
	}
	if u, err := url.Parse(claims.ISS); err != nil || u.Scheme != "https" {
		return nil, ErrClientID
	}
	if claims.Sub != claims.ISS {
		return nil, ErrIssuerMismatch
	}
	if claims.AUD != v.TokenEndpoint {
		return nil, ErrAudience
	}
	now := v.now()
	maxAge := v.MaxAssertionAge
	if maxAge <= 0 {
		maxAge = 5 * time.Minute
	}
	if now.Unix() >= claims.EXP {
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
		pub, err := jwk.publicKey()
		if err != nil {
			continue
		}
		if verifyES256(pub, []byte(parts[0]+"."+parts[1]), parts[2]) {
			return &Assertion{ClientID: claims.ISS, JTI: claims.JTI}, nil
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

// verifyES256 checks an ES256 JWS signature.
func verifyES256(key *ecdsa.PublicKey, signingInput []byte, sigB64 string) bool {
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	digest := sha256.Sum256(signingInput)
	return ecdsa.Verify(key, digest[:], r, s)
}
