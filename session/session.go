// Package session verifies the Poppy-Session header at a Company's resource
// endpoints (Poppy draft 1.0 spec 5.2, 5.3).
//
// A Personal Agent signs a fresh Session JWT for every request, typed
// poppy-session+jwt and signed with ES256 by a delegated key. The JWT's
// poppy_dlg header member carries a delegation: a short-lived JWT (at most
// 24 hours) signed with ES256 or PS384 by a key in the agent's jwks_uri,
// vouching for the delegated key in its cnf.jwk confirmation claim
// (RFC 7800). Sessions are named by sid, never by a key: the same Session
// must keep working when the agent rotates its delegated key.
//
// Verification (spec 5.2 Delegated keys, then 5.3):
//  1. find the key in the agent's jwks_uri the delegation's kid names and
//     verify the delegation's signature with it;
//  2. check the delegation's typ, iss (the Session JWT's iss), expiry and
//     24-hour maximum lifetime;
//  3. verify the Session JWT's signature with cnf.jwk, and that its kid is
//     that key's RFC 7638 thumbprint;
//  4. check typ and the claims: aud is the Company's identifier compared
//     character for character, htm and htu bind the request as in a DPoP
//     proof (RFC 9449 §4.2), iat is fresh, jti is not replayed, and ath is
//     present exactly when an access token is, matching its SHA-256 hash.
package session

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ofershap/poppy-go/clientassert"
	"github.com/ofershap/poppy-go/internal/jose"
)

// Error codes the protocol defines for Session failures (spec 5.3, 3.4).
// Both are HTTP 400 with a JSON body {"error": code}.
const (
	CodeInvalidSession     = "invalid_session"
	CodeVersionUnsupported = "version_unsupported"
)

// Error is a failed Session or version check. Code is the protocol error
// code to return in the JSON body; Reason is the internal cause (never send
// it to the client: it would tell an attacker which check failed).
type Error struct {
	Code   string
	Reason error
}

func (e *Error) Error() string { return fmt.Sprintf("session: %s: %v", e.Code, e.Reason) }
func (e *Error) Unwrap() error { return e.Reason }

func invalid(format string, args ...any) *Error {
	return &Error{Code: CodeInvalidSession, Reason: fmt.Errorf(format, args...)}
}

// Identity is a verified Session: who the Personal Agent is (client_id),
// which Session and User the request belongs to, and the access token the
// request carries (its validity is the resource's own concern).
type Identity struct {
	ClientID    string
	UserID      string
	SessionID   string
	AgentID     string // optional
	AccessToken string // raw bearer token, when the request carries one
}

// AgentFetcher resolves a Personal Agent's published keys from its
// client_id. It is clientassert.Fetcher: the same metadata document backs
// client assertions and Session delegations.
type AgentFetcher = clientassert.Fetcher

// Verifier checks Poppy-Session headers for one Company.
type Verifier struct {
	// Audience is the Company's identifier (spec 3.2): the issuer when the
	// Company has one, else https://{organization.domain}. Compared with the
	// Session JWT's aud character for character. Required.
	Audience string
	// Versions are the protocol versions the Company serves, such as
	// ["1.0"]. A request whose Poppy-Version header is missing or names
	// another version is rejected with version_unsupported (spec 3.4).
	// Required for VerifyRequest.
	Versions []string
	// Fetcher retrieves agent metadata and JWKS. Required.
	Fetcher AgentFetcher
	// MaxAge is the acceptance window for a Session JWT's iat. Default 2
	// minutes. The Company chooses its window; a long one lets a copied
	// Session JWT work longer.
	MaxAge time.Duration
	// MaxDelegationLifetime bounds a delegation's exp-iat. Default 24 hours,
	// the spec's maximum.
	MaxDelegationLifetime time.Duration
	// Now supplies the current time (test hook).
	Now func() time.Time

	mu       sync.Mutex
	sessions map[sessionKey]string // known Sessions: key -> AgentID
	seenJTI  map[string]time.Time  // "clientID|jti" -> seen at
}

type sessionKey struct{ clientID, sid, sub string }

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) maxAge() time.Duration {
	if v.MaxAge > 0 {
		return v.MaxAge
	}
	return 2 * time.Minute
}

func (v *Verifier) maxDelegationLifetime() time.Duration {
	if v.MaxDelegationLifetime > 0 {
		return v.MaxDelegationLifetime
	}
	return 24 * time.Hour
}

// CheckVersion applies the Poppy-Version rule (spec 3.4): an endpoint that
// verifies the Session header also checks Poppy-Version, and rejects a
// missing or unserved version with version_unsupported.
func (v *Verifier) CheckVersion(r *http.Request) *Error {
	got := r.Header.Get("Poppy-Version")
	for _, s := range v.Versions {
		if got == s {
			return nil
		}
	}
	return &Error{Code: CodeVersionUnsupported,
		Reason: fmt.Errorf("Poppy-Version %q is not served", got)}
}

// VerifyRequest checks the Poppy-Version and Poppy-Session headers of one
// request. On success it returns the Session identity; on failure an *Error
// whose Code is the protocol error to report.
func (v *Verifier) VerifyRequest(r *http.Request) (*Identity, *Error) {
	// Session first: a missing or bad Session header is invalid_session
	// even when Poppy-Version is missing too, so the agent learns how to
	// fix the Session (spec 5.3). Then the version gate (spec 3.4).
	id, serr := v.Verify(r)
	if serr != nil {
		return nil, serr
	}
	if verr := v.CheckVersion(r); verr != nil {
		return nil, verr
	}
	return id, nil
}

// Verify checks the Poppy-Session header of one request, without the
// Poppy-Version check (for callers that version-check separately).
func (v *Verifier) Verify(r *http.Request) (*Identity, *Error) {
	if v.Fetcher == nil {
		return nil, invalid("Verifier.Fetcher is required")
	}
	if v.Audience == "" {
		return nil, invalid("Verifier.Audience is required")
	}
	header := r.Header.Get("Poppy-Session")
	if header == "" {
		return nil, invalid("no Poppy-Session header")
	}
	tok, err := jose.ParseCompact(header)
	if err != nil {
		return nil, invalid("malformed Session JWT")
	}
	hdr, err := jose.ParseHeader(tok.HeaderRaw)
	if err != nil {
		return nil, invalid("malformed Session JWT header")
	}
	if hdr.Typ != "poppy-session+jwt" {
		return nil, invalid("typ must be poppy-session+jwt")
	}
	if hdr.Alg != "ES256" {
		return nil, invalid("Session JWTs are signed with ES256")
	}
	if hdr.DLG == "" {
		return nil, invalid("no delegation (poppy_dlg): Session JWTs are signed with delegated keys")
	}
	var claims struct {
		ISS     string          `json:"iss"`
		AUD     json.RawMessage `json:"aud"`
		SID     string          `json:"sid"`
		Sub     string          `json:"sub"`
		AgentID string          `json:"agent_id"`
		Htm     string          `json:"htm"`
		Htu     string          `json:"htu"`
		IAT     int64           `json:"iat"`
		JTI     string          `json:"jti"`
		Ath     string          `json:"ath"`
	}
	if err := json.Unmarshal(tok.PayloadRaw, &claims); err != nil {
		return nil, invalid("malformed Session JWT claims")
	}
	if claims.ISS == "" {
		return nil, invalid("no iss")
	}

	delegatedKey, derr := v.verifyDelegation(r, hdr.DLG, claims.ISS)
	if derr != nil {
		return nil, derr
	}

	// Step 3 (5.2): the Session JWT's signature verifies with cnf.jwk, and
	// its kid is that key's RFC 7638 thumbprint.
	if hdr.Kid == "" || hdr.Kid != jose.ThumbprintEC(delegatedKey.X, delegatedKey.Y) {
		return nil, invalid("kid is not the delegated key's JWK thumbprint")
	}
	pub, err := jose.ECKeyFromJWK(delegatedKey.X, delegatedKey.Y)
	if err != nil {
		return nil, invalid("bad delegated key")
	}
	if err := jose.VerifyES256(pub, tok.Input, tok.Signature); err != nil {
		return nil, invalid("Session JWT signature invalid")
	}

	// Claims (5.2, 5.3).
	var aud string
	if err := json.Unmarshal(claims.AUD, &aud); err != nil || aud != v.Audience {
		return nil, invalid("aud is not this Company's identifier")
	}
	if claims.SID == "" {
		return nil, invalid("no sid")
	}
	if claims.Sub == "" {
		return nil, invalid("no sub")
	}
	if !strings.EqualFold(claims.Htm, r.Method) {
		return nil, invalid("htm does not match the request method")
	}
	if claims.Htu != requestURL(r) {
		return nil, invalid("htu does not match the request URL")
	}
	now := v.now()
	iat := time.Unix(claims.IAT, 0)
	if claims.IAT == 0 || now.Sub(iat) > v.maxAge() || iat.Sub(now) > time.Minute {
		return nil, invalid("iat is outside the acceptance window")
	}
	if claims.JTI == "" {
		return nil, invalid("no jti")
	}
	if v.replayed(claims.ISS, claims.JTI, now) {
		return nil, invalid("jti already used")
	}

	// ath is present exactly when an access token is, and names its SHA-256
	// hash (5.2).
	token := bearerToken(r)
	if token == "" && claims.Ath != "" {
		return nil, invalid("ath without an access token")
	}
	if token != "" {
		sum := sha256.Sum256([]byte(token))
		if claims.Ath != jose.B64.EncodeToString(sum[:]) {
			return nil, invalid("ath does not match the access token")
		}
	}

	// Session lookup and continuity (5.3): the Session is named by
	// client_id, sid and User ID. A new combination starts a Session. A
	// known Session keeps its Agent ID (5.2), whatever delegated key signs.
	key := sessionKey{claims.ISS, claims.SID, claims.Sub}
	v.mu.Lock()
	if v.sessions == nil {
		v.sessions = make(map[sessionKey]string)
	}
	agentID, known := v.sessions[key]
	if known && agentID != claims.AgentID {
		v.mu.Unlock()
		return nil, invalid("agent_id changed within a Session")
	}
	v.sessions[key] = claims.AgentID
	v.mu.Unlock()

	return &Identity{
		ClientID:    claims.ISS,
		UserID:      claims.Sub,
		SessionID:   claims.SID,
		AgentID:     claims.AgentID,
		AccessToken: token,
	}, nil
}

// delegatedJWK is the delegated key a delegation vouches for.
type delegatedJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"` // must be empty: no private members (5.2)
}

// verifyDelegation runs steps 1 and 2 of Delegated keys (5.2) and returns
// the delegated public key.
func (v *Verifier) verifyDelegation(r *http.Request, dlg, wantISS string) (*delegatedJWK, *Error) {
	tok, err := jose.ParseCompact(dlg)
	if err != nil {
		return nil, invalid("malformed delegation")
	}
	hdr, err := jose.ParseHeader(tok.HeaderRaw)
	if err != nil {
		return nil, invalid("malformed delegation header")
	}
	if hdr.Typ != "poppy-delegation+jwt" {
		return nil, invalid("delegation typ must be poppy-delegation+jwt")
	}
	if hdr.Alg != "ES256" && hdr.Alg != "PS384" {
		return nil, invalid("delegation alg must be ES256 or PS384")
	}
	if hdr.Kid == "" {
		return nil, invalid("delegation has no kid")
	}
	var claims struct {
		ISS string `json:"iss"`
		CNF struct {
			JWK delegatedJWK `json:"jwk"`
		} `json:"cnf"`
		IAT int64  `json:"iat"`
		EXP int64  `json:"exp"`
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(tok.PayloadRaw, &claims); err != nil {
		return nil, invalid("malformed delegation claims")
	}
	if claims.ISS == "" || claims.ISS != wantISS {
		return nil, invalid("delegation iss is not the Session JWT's iss")
	}
	now := v.now()
	if claims.EXP == 0 || now.Unix() >= claims.EXP {
		return nil, invalid("delegation expired")
	}
	if time.Unix(claims.EXP, 0).Sub(time.Unix(claims.IAT, 0)) > v.maxDelegationLifetime() {
		return nil, invalid("delegation lasts more than 24 hours")
	}
	cnf := claims.CNF.JWK
	if cnf.Kty != "EC" || cnf.Crv != "P-256" || cnf.X == "" || cnf.Y == "" || cnf.D != "" {
		return nil, invalid("delegation cnf.jwk must be a public EC P-256 key")
	}

	// Step 1: the delegation verifies with the key its kid names in the
	// agent's jwks_uri.
	md, err := v.Fetcher.FetchMetadata(r.Context(), claims.ISS)
	if err != nil {
		return nil, invalid("could not fetch agent metadata")
	}
	var keys *clientassert.JWKS
	switch {
	case md.JWKS != nil && len(md.JWKS.Keys) > 0:
		keys = md.JWKS
	case md.JWKSUri != "":
		keys, err = v.Fetcher.FetchJWKS(r.Context(), md.JWKSUri)
		if err != nil {
			return nil, invalid("could not fetch agent JWKS")
		}
	default:
		return nil, invalid("agent metadata names no keys")
	}
	for _, jwk := range keys.Keys {
		if jwk.Kid != hdr.Kid {
			continue
		}
		switch {
		case hdr.Alg == "ES256" && jwk.IsEC():
			pub, err := jose.ECKeyFromJWK(jwk.X, jwk.Y)
			if err != nil {
				continue
			}
			if err := jose.VerifyES256(pub, tok.Input, tok.Signature); err == nil {
				return &cnf, nil
			}
		case hdr.Alg == "PS384" && jwk.IsRSA():
			pub, err := jose.RSAKeyFromJWK(jwk.N, jwk.E)
			if err != nil {
				continue
			}
			if err := jose.VerifyPS384(pub, tok.Input, tok.Signature); err == nil {
				return &cnf, nil
			}
		}
	}
	return nil, invalid("delegation signature does not verify with a key in jwks_uri")
}

// replayed records a Session JWT's jti and reports whether it was already
// used. Entries live for the iat window plus a margin; the window bounds how
// long a copied JWT could be replayed.
func (v *Verifier) replayed(clientID, jti string, now time.Time) bool {
	k := clientID + "|" + jti
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seenJTI == nil {
		v.seenJTI = make(map[string]time.Time)
	}
	// Prune occasionally: when the map is large, drop expired entries.
	if len(v.seenJTI) > 4096 {
		horizon := now.Add(-2 * v.maxAge())
		for key, at := range v.seenJTI {
			if at.Before(horizon) {
				delete(v.seenJTI, key)
			}
		}
	}
	if _, seen := v.seenJTI[k]; seen {
		return true
	}
	v.seenJTI[k] = now
	return false
}

// requestURL rebuilds the URL a Session JWT's htu names: scheme, host and
// path, without query or fragment (RFC 9449 §4.2, as 5.2 requires).
func requestURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host + r.URL.Path
}

// bearerToken returns the access token of an Authorization: Bearer header,
// or "". Tokens are taken from the header only, never the URL (5.6).
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return h[7:]
	}
	return ""
}

// Ensure the error type is assertable by callers.
var _ error = (*Error)(nil)
