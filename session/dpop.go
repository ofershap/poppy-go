// Package session verifies the two credentials a Company receives on every
// Poppy request: the Session Token (a short-lived, key-bound access token)
// and the DPoP proof that the sender holds the key the token is bound to
// (Poppy draft 1.0 spec 4.2-4.3; DPoP itself is RFC 9449).
//
// Verification is local and self-contained: no network calls, no external
// dependencies beyond the standard library. Replay protection is provided
// through the ReplayCache interface.
package session

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DPoPHeader is the HTTP header carrying the DPoP proof (RFC 9449 §4.2).
const DPoPHeader = "DPoP"

// AuthorizationScheme is the scheme for a DPoP-bound Session Token.
const AuthorizationScheme = "DPoP"

// Errors returned by proof and token verification.
var (
	ErrNoProof        = errors.New("session: no DPoP proof header")
	ErrMalformedProof = errors.New("session: malformed DPoP proof")
	ErrBadTyp         = errors.New("session: DPoP proof typ must be dpop+jwt")
	ErrBadAlg         = errors.New("session: DPoP proof alg not allowed")
	ErrBadKey         = errors.New("session: unsupported or invalid DPoP public key")
	ErrBadSignature   = errors.New("session: DPoP proof signature invalid")
	ErrMethodMismatch = errors.New("session: DPoP htm does not match the request method")
	ErrURIMismatch    = errors.New("session: DPoP htu does not match the request URI")
	ErrProofExpired   = errors.New("session: DPoP proof too old or from the future")
	ErrReplay         = errors.New("session: DPoP proof jti already seen")
	ErrTokenBinding   = errors.New("session: DPoP ath does not match the access token")
	ErrMalformedToken = errors.New("session: malformed session token")
	ErrTokenExpired   = errors.New("session: session token expired")
	ErrBadIssuer      = errors.New("session: session token issuer mismatch")
	ErrBadAudience    = errors.New("session: session token audience mismatch")
	ErrBadBinding     = errors.New("session: token cnf.jkt does not match the DPoP key")
)

// ReplayCache records seen DPoP jti values. Implementations must be safe for
// concurrent use.
type ReplayCache interface {
	// Seen reports whether jti was already recorded, and records it if not.
	// Returns true when the jti is a replay.
	Seen(jti string) bool
}

// MemoryReplayCache is an in-memory ReplayCache with bounded size. Entries
// expire after the proof freshness window, so memory stays flat.
type MemoryReplayCache struct {
	mu    sync.Mutex
	items map[string]time.Time
	ttl   time.Duration
}

// NewMemoryReplayCache returns a cache that keeps jtis for ttl.
func NewMemoryReplayCache(ttl time.Duration) *MemoryReplayCache {
	return &MemoryReplayCache{items: make(map[string]time.Time), ttl: ttl}
}

func (c *MemoryReplayCache) Seen(jti string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, t := range c.items {
		if now.Sub(t) > c.ttl {
			delete(c.items, k)
		}
	}
	if _, ok := c.items[jti]; ok {
		return true
	}
	c.items[jti] = now
	return false
}

// Verifier checks DPoP proofs and Session Tokens for one Company deployment.
type Verifier struct {
	// Issuer is the Company's OAuth issuer identifier; session tokens must
	// carry it as iss.
	Issuer string
	// Audience is the value session tokens must carry as aud, typically the
	// Company's resource identifier from its protected-resource metadata.
	Audience string
	// IssuerKeys resolves the Company's token-signing key by kid. Production
	// deployments back it with a cached JWKS fetcher; tests can return a
	// static key.
	IssuerKeys func(kid string) (crypto.PublicKey, error)
	// Replay rejects reused DPoP jti values. Required.
	Replay ReplayCache
	// MaxProofAge bounds DPoP proof iat freshness. Default 5 minutes.
	MaxProofAge time.Duration
	// Now supplies the current time; defaults to time.Now (test hook).
	Now func() time.Time
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) maxProofAge() time.Duration {
	if v.MaxProofAge > 0 {
		return v.MaxProofAge
	}
	return 5 * time.Minute
}

// Proof is a verified DPoP proof.
type Proof struct {
	JTI           string
	KeyThumbprint string // RFC 7638 JWK SHA-256 thumbprint of the proof key
}

// Token is a verified Session Token.
type Token struct {
	SessionID string
	UserID    string // pairwise, company-specific (spec 4.2)
	SignedIn  bool
	Scopes    []string
	ExpiresAt time.Time
}

// VerifyProof checks the DPoP proof on r. When accessToken is non-empty it
// must be the Session Token sent alongside, and the proof's ath claim is
// checked against it (RFC 9449 §4.2, Poppy spec 4.3).
func (v *Verifier) VerifyProof(r *http.Request, accessToken string) (*Proof, error) {
	raw := r.Header.Get(DPoPHeader)
	if raw == "" {
		return nil, ErrNoProof
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedProof
	}
	headerBytes, err := b64().DecodeString(parts[0])
	if err != nil {
		return nil, ErrMalformedProof
	}
	var header struct {
		Typ string          `json:"typ"`
		Alg string          `json:"alg"`
		JWK json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, ErrMalformedProof
	}
	if header.Typ != "dpop+jwt" {
		return nil, ErrBadTyp
	}
	if header.Alg != "ES256" {
		// Poppy requires ES256 support; other algorithms can be allowed by
		// extending this check once implemented.
		return nil, ErrBadAlg
	}
	key, thumb, err := parseJWK(header.JWK)
	if err != nil {
		return nil, err
	}
	payloadBytes, err := b64().DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformedProof
	}
	var claims struct {
		JTI string `json:"jti"`
		HTM string `json:"htm"`
		HTU string `json:"htu"`
		IAT int64  `json:"iat"`
		ATH string `json:"ath"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, ErrMalformedProof
	}
	if !verifyES256(key, []byte(parts[0]+"."+parts[1]), parts[2]) {
		return nil, ErrBadSignature
	}
	if !strings.EqualFold(claims.HTM, r.Method) {
		return nil, ErrMethodMismatch
	}
	if claims.HTU != requestURIWithoutQuery(r) {
		return nil, ErrURIMismatch
	}
	iat := time.Unix(claims.IAT, 0)
	if d := v.now().Sub(iat); d > v.maxProofAge() || d < -v.maxProofAge() {
		return nil, ErrProofExpired
	}
	if v.Replay != nil && claims.JTI != "" && v.Replay.Seen(claims.JTI) {
		return nil, ErrReplay
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		if claims.ATH != b64().EncodeToString(sum[:]) {
			return nil, ErrTokenBinding
		}
	}
	return &Proof{JTI: claims.JTI, KeyThumbprint: thumb}, nil
}

// VerifyToken checks a Session Token (a JWS signed by the Company's token
// endpoint) and its binding to the DPoP proof key (spec 4.2-4.3: cnf.jkt).
func (v *Verifier) VerifyToken(raw string, proof *Proof) (*Token, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedToken
	}
	headerBytes, err := b64().DecodeString(parts[0])
	if err != nil {
		return nil, ErrMalformedToken
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, ErrMalformedToken
	}
	if v.IssuerKeys == nil {
		return nil, errors.New("session: Verifier.IssuerKeys is required")
	}
	key, err := v.IssuerKeys(header.Kid)
	if err != nil {
		return nil, fmt.Errorf("session: resolve issuer key: %w", err)
	}
	switch header.Alg {
	case "ES256":
		ec, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("session: issuer key is not ECDSA")
		}
		if !verifyES256(ec, []byte(parts[0]+"."+parts[1]), parts[2]) {
			return nil, ErrBadSignature
		}
	default:
		return nil, ErrBadAlg
	}
	payloadBytes, err := b64().DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformedToken
	}
	var claims struct {
		ISS string `json:"iss"`
		AUD string `json:"aud"`
		EXP int64  `json:"exp"`
		SID string `json:"session_id"`
		UID string `json:"user_id"`
		In  bool   `json:"signed_in"`
		Scp string `json:"scope"`
		CNF struct {
			JKT string `json:"jkt"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, ErrMalformedToken
	}
	if v.Issuer != "" && claims.ISS != v.Issuer {
		return nil, ErrBadIssuer
	}
	if v.Audience != "" && claims.AUD != v.Audience {
		return nil, ErrBadAudience
	}
	if v.now().Unix() >= claims.EXP {
		return nil, ErrTokenExpired
	}
	if proof != nil && claims.CNF.JKT != "" && claims.CNF.JKT != proof.KeyThumbprint {
		return nil, ErrBadBinding
	}
	var scopes []string
	if claims.Scp != "" {
		scopes = strings.Fields(claims.Scp)
	}
	return &Token{
		SessionID: claims.SID,
		UserID:    claims.UID,
		SignedIn:  claims.In,
		Scopes:    scopes,
		ExpiresAt: time.Unix(claims.EXP, 0),
	}, nil
}

// RequireScopes reports whether the token carries every wanted scope.
func (t *Token) RequireScopes(want ...string) bool {
	have := make(map[string]bool, len(t.Scopes))
	for _, s := range t.Scopes {
		have[s] = true
	}
	for _, w := range want {
		if !have[w] {
			return false
		}
	}
	return true
}

// BearerToken extracts the Session Token from the Authorization header.
// The scheme is DPoP (RFC 9449 §7.1); Bearer is rejected so a stolen token
// cannot be replayed without the proof.
func ExtractToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", errors.New("session: no Authorization header")
	}
	scheme, tok, ok := strings.Cut(h, " ")
	if !ok || tok == "" {
		return "", errors.New("session: malformed Authorization header")
	}
	if !strings.EqualFold(scheme, AuthorizationScheme) {
		return "", fmt.Errorf("session: authorization scheme must be %s", AuthorizationScheme)
	}
	return tok, nil
}

// parseJWK parses the public JWK embedded in a DPoP proof header (ES256
// only) and returns the key plus its RFC 7638 SHA-256 thumbprint.
func parseJWK(raw json.RawMessage) (*ecdsa.PublicKey, string, error) {
	var jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, "", ErrBadKey
	}
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		return nil, "", ErrBadKey
	}
	xb, err := b64().DecodeString(jwk.X)
	if err != nil {
		return nil, "", ErrBadKey
	}
	yb, err := b64().DecodeString(jwk.Y)
	if err != nil {
		return nil, "", ErrBadKey
	}
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, "", ErrBadKey
	}
	// RFC 7638 thumbprint: required members in lexicographic order.
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, jwk.X, jwk.Y)
	sum := sha256.Sum256([]byte(canonical))
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, b64().EncodeToString(sum[:]), nil
}

// verifyES256 checks an ES256 JWS signature over signingInput.
func verifyES256(key *ecdsa.PublicKey, signingInput []byte, sigB64 string) bool {
	sig, err := b64().DecodeString(sigB64)
	if err != nil || len(sig) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	digest := sha256.Sum256(signingInput)
	return ecdsa.Verify(key, digest[:], r, s)
}

// requestURIWithoutQuery returns the absolute request URI without query
// string, as RFC 9449 §4.2 requires for htu comparison.
func requestURIWithoutQuery(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host + r.URL.Path
}

func b64() *base64.Encoding { return base64.RawURLEncoding }

// GenerateTestKey returns a fresh P-256 key for tests and examples.
func GenerateTestKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// MarshalX509 is a helper for embedding issuer keys in tests.
func MarshalX509(key *ecdsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(key)
}
