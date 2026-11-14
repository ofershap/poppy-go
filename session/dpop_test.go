package session

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"testing"
	"time"
)

func signES256(t *testing.T, key *ecdsa.PrivateKey, header, payload map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(h) + "." + enc.EncodeToString(p)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(pad32(r), pad32(s)...)
	return input + "." + enc.EncodeToString(sig)
}

func pad32(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func jwkFor(key *ecdsa.PrivateKey) map[string]any {
	enc := base64.RawURLEncoding
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   enc.EncodeToString(pad32(key.X)),
		"y":   enc.EncodeToString(pad32(key.Y)),
	}
}

func TestVerifyProofRoundtrip(t *testing.T) {
	key, err := GenerateTestKey()
	if err != nil {
		t.Fatal(err)
	}
	v := &Verifier{Replay: NewMemoryReplayCache(10 * time.Minute)}

	r := httptest.NewRequest("GET", "https://api.example.com/orders", nil)
	proof := signES256(t, key,
		map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwkFor(key)},
		map[string]any{
			"jti": "proof-1",
			"htm": "GET",
			"htu": "https://api.example.com/orders",
			"iat": time.Now().Unix(),
		})
	r.Header.Set(DPoPHeader, proof)

	p, err := v.VerifyProof(r, "")
	if err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}
	if p.JTI != "proof-1" {
		t.Fatalf("jti = %q", p.JTI)
	}

	// Replay of the same jti must fail.
	r2 := httptest.NewRequest("GET", "https://api.example.com/orders", nil)
	r2.Header.Set(DPoPHeader, proof)
	if _, err := v.VerifyProof(r2, ""); err != ErrReplay {
		t.Fatalf("replay: got %v, want ErrReplay", err)
	}

	// Wrong method must fail.
	r3 := httptest.NewRequest("POST", "https://api.example.com/orders", nil)
	proof3 := signES256(t, key,
		map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwkFor(key)},
		map[string]any{
			"jti": "proof-3", "htm": "GET",
			"htu": "https://api.example.com/orders",
			"iat": time.Now().Unix(),
		})
	r3.Header.Set(DPoPHeader, proof3)
	if _, err := v.VerifyProof(r3, ""); err != ErrMethodMismatch {
		t.Fatalf("htm mismatch: got %v, want ErrMethodMismatch", err)
	}

	// ath binding: proof naming another token must fail.
	other := signES256(t, key,
		map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwkFor(key)},
		map[string]any{
			"jti": "proof-4", "htm": "GET",
			"htu": "https://api.example.com/orders",
			"iat": time.Now().Unix(),
			"ath": base64.RawURLEncoding.EncodeToString([]byte("not-the-token-hash-32bytes!!!!")),
		})
	r4 := httptest.NewRequest("GET", "https://api.example.com/orders", nil)
	r4.Header.Set(DPoPHeader, other)
	if _, err := v.VerifyProof(r4, "real-token"); err != ErrTokenBinding {
		t.Fatalf("ath mismatch: got %v, want ErrTokenBinding", err)
	}
}

func TestAdversarialNegativeCases(t *testing.T) {
	key, _ := GenerateTestKey()
	v := &Verifier{Replay: NewMemoryReplayCache(10 * time.Minute)}
	hdr := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwkFor(key)}

	// Missing jti must fail closed (otherwise replay checks are skippable).
	r := httptest.NewRequest("GET", "https://api.example.com/o", nil)
	r.Header.Set(DPoPHeader, signES256(t, key, hdr, map[string]any{
		"htm": "GET", "htu": "https://api.example.com/o", "iat": time.Now().Unix(),
	}))
	if _, err := v.VerifyProof(r, ""); err != ErrMalformedProof {
		t.Fatalf("missing jti: got %v, want ErrMalformedProof", err)
	}

	// Stale iat must fail.
	r = httptest.NewRequest("GET", "https://api.example.com/o", nil)
	r.Header.Set(DPoPHeader, signES256(t, key, hdr, map[string]any{
		"jti": "old", "htm": "GET", "htu": "https://api.example.com/o",
		"iat": time.Now().Add(-time.Hour).Unix(),
	}))
	if _, err := v.VerifyProof(r, ""); err != ErrProofExpired {
		t.Fatalf("stale iat: got %v, want ErrProofExpired", err)
	}

	// Wrong htu must fail.
	r = httptest.NewRequest("GET", "https://api.example.com/other", nil)
	r.Header.Set(DPoPHeader, signES256(t, key, hdr, map[string]any{
		"jti": "u1", "htm": "GET", "htu": "https://api.example.com/o",
		"iat": time.Now().Unix(),
	}))
	if _, err := v.VerifyProof(r, ""); err != ErrURIMismatch {
		t.Fatalf("htu: got %v, want ErrURIMismatch", err)
	}
}

func TestTokenWithoutBindingFailsClosed(t *testing.T) {
	issuerKey, _ := GenerateTestKey()
	agentKey, _ := GenerateTestKey()
	v := &Verifier{
		Issuer: "https://auth.example.com", Audience: "https://api.example.com",
		IssuerKeys: func(kid string) (crypto.PublicKey, error) { return &issuerKey.PublicKey, nil },
		Replay:     NewMemoryReplayCache(10 * time.Minute),
	}
	r := httptest.NewRequest("GET", "https://api.example.com/o", nil)
	r.Header.Set(DPoPHeader, signES256(t, agentKey,
		map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwkFor(agentKey)},
		map[string]any{"jti": "b1", "htm": "GET", "htu": "https://api.example.com/o", "iat": time.Now().Unix()}))
	p, err := v.VerifyProof(r, "")
	if err != nil {
		t.Fatal(err)
	}
	// Token with no cnf at all must be rejected when a proof is presented.
	raw := signToken(t, issuerKey, map[string]any{
		"iss": "https://auth.example.com", "aud": "https://api.example.com",
		"exp": time.Now().Add(time.Minute).Unix(),
	})
	if _, err := v.VerifyToken(raw, p); err != ErrBadBinding {
		t.Fatalf("unbound token: got %v, want ErrBadBinding", err)
	}
}
