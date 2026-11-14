package session

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

func thumbFor(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	enc := base64.RawURLEncoding
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`,
		enc.EncodeToString(pad32(key.X)), enc.EncodeToString(pad32(key.Y)))
	sum := sha256.Sum256([]byte(canonical))
	return enc.EncodeToString(sum[:])
}

func signToken(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	return signES256(t, key,
		map[string]any{"typ": "JWT", "alg": "ES256", "kid": "issuer-1"},
		claims)
}

func TestVerifyTokenAndBinding(t *testing.T) {
	issuerKey, _ := GenerateTestKey()
	agentKey, _ := GenerateTestKey()
	v := &Verifier{
		Issuer:   "https://auth.example.com",
		Audience: "https://api.example.com",
		IssuerKeys: func(kid string) (crypto.PublicKey, error) {
			if kid != "issuer-1" {
				return nil, fmt.Errorf("unknown kid %q", kid)
			}
			return &issuerKey.PublicKey, nil
		},
		Replay: NewMemoryReplayCache(10 * time.Minute),
	}

	// Live DPoP proof from the agent key.
	r := httptest.NewRequest("GET", "https://api.example.com/orders", nil)
	proof := signES256(t, agentKey,
		map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwkFor(agentKey)},
		map[string]any{
			"jti": "p1", "htm": "GET",
			"htu": "https://api.example.com/orders",
			"iat": time.Now().Unix(),
		})
	r.Header.Set(DPoPHeader, proof)
	p, err := v.VerifyProof(r, "")
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]any{
		"iss": "https://auth.example.com", "aud": "https://api.example.com",
		"exp":        time.Now().Add(5 * time.Minute).Unix(),
		"session_id": "sess-1", "user_id": "u-abc", "signed_in": true,
		"scope": "orders:read orders:write",
		"cnf":   map[string]any{"jkt": thumbFor(t, agentKey)},
	}
	raw := signToken(t, issuerKey, claims)

	tok, err := v.VerifyToken(raw, p)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if tok.SessionID != "sess-1" || tok.UserID != "u-abc" || !tok.SignedIn {
		t.Fatalf("token = %+v", tok)
	}
	if !tok.RequireScopes("orders:read", "orders:write") || tok.RequireScopes("admin") {
		t.Fatal("scope check wrong")
	}

	// A token bound to a different key must fail cnf.jkt binding.
	otherKey, _ := GenerateTestKey()
	claims["cnf"] = map[string]any{"jkt": thumbFor(t, otherKey)}
	rawOther := signToken(t, issuerKey, claims)
	if _, err := v.VerifyToken(rawOther, p); err != ErrBadBinding {
		t.Fatalf("wrong jkt: got %v, want ErrBadBinding", err)
	}

	// Expired token must fail.
	claims["cnf"] = map[string]any{"jkt": thumbFor(t, agentKey)}
	claims["exp"] = time.Now().Add(-time.Minute).Unix()
	rawExp := signToken(t, issuerKey, claims)
	if _, err := v.VerifyToken(rawExp, p); err != ErrTokenExpired {
		t.Fatalf("expired: got %v, want ErrTokenExpired", err)
	}

	// Wrong issuer must fail.
	claims["exp"] = time.Now().Add(5 * time.Minute).Unix()
	claims["iss"] = "https://evil.example.com"
	rawIss := signToken(t, issuerKey, claims)
	if _, err := v.VerifyToken(rawIss, p); err != ErrBadIssuer {
		t.Fatalf("issuer: got %v, want ErrBadIssuer", err)
	}
}

func TestExtractToken(t *testing.T) {
	r := httptest.NewRequest("GET", "https://api.example.com/x", nil)
	r.Header.Set("Authorization", "DPoP abc.def.ghi")
	tok, err := ExtractToken(r)
	if err != nil || tok != "abc.def.ghi" {
		t.Fatalf("tok=%q err=%v", tok, err)
	}
	r.Header.Set("Authorization", "Bearer abc")
	if _, err := ExtractToken(r); err == nil {
		t.Fatal("Bearer scheme must be rejected")
	}
}
