package clientassert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"testing"
	"time"
)

func pad32(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func sign(t *testing.T, key *ecdsa.PrivateKey, header, payload map[string]any) string {
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
	return input + "." + enc.EncodeToString(append(pad32(r), pad32(s)...))
}

type fakeFetcher struct {
	md   *Metadata
	jwks *JWKS
	err  error
}

func (f fakeFetcher) FetchMetadata(ctx context.Context, clientID string) (*Metadata, error) {
	return f.md, f.err
}
func (f fakeFetcher) FetchJWKS(ctx context.Context, uri string) (*JWKS, error) {
	return f.jwks, f.err
}

const (
	testClientID = "https://agent.example/.well-known/client.json"
	testTokenURL = "https://auth.example.com/oauth/token"
)

func setup(t *testing.T) (*ecdsa.PrivateKey, *Verifier) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	jwks := &JWKS{Keys: []JWK{{
		Kty: "EC", Crv: "P-256", Kid: "k1",
		X: enc.EncodeToString(pad32(key.X)),
		Y: enc.EncodeToString(pad32(key.Y)),
	}}}
	v := &Verifier{
		TokenEndpoint: testTokenURL,
		Fetcher: fakeFetcher{
			md: &Metadata{JWKS: jwks},
		},
	}
	return key, v
}

func validClaims() map[string]any {
	return map[string]any{
		"iss": testClientID, "sub": testClientID, "aud": testTokenURL,
		"exp": time.Now().Add(2 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
		"jti": "assert-1",
	}
}

func TestVerifyRoundtrip(t *testing.T) {
	key, v := setup(t)
	a := sign(t, key, map[string]any{"typ": "JWT", "alg": "ES256", "kid": "k1"}, validClaims())
	got, err := v.Verify(context.Background(), a)
	if err != nil {
		t.Fatalf("valid assertion rejected: %v", err)
	}
	if got.ClientID != testClientID || got.JTI != "assert-1" {
		t.Fatalf("assertion = %+v", got)
	}
}

func TestVerifyRejects(t *testing.T) {
	key, v := setup(t)
	hdr := map[string]any{"typ": "JWT", "alg": "ES256", "kid": "k1"}

	// Wrong audience.
	c := validClaims()
	c["aud"] = "https://other.example.com/token"
	if _, err := v.Verify(context.Background(), sign(t, key, hdr, c)); err != ErrAudience {
		t.Fatalf("aud: got %v", err)
	}
	// sub != iss.
	c = validClaims()
	c["sub"] = "https://other-agent.example"
	if _, err := v.Verify(context.Background(), sign(t, key, hdr, c)); err != ErrIssuerMismatch {
		t.Fatalf("sub: got %v", err)
	}
	// Non-https client_id.
	c = validClaims()
	c["iss"] = "http://agent.example"
	c["sub"] = "http://agent.example"
	if _, err := v.Verify(context.Background(), sign(t, key, hdr, c)); err != ErrClientID {
		t.Fatalf("scheme: got %v", err)
	}
	// Expired.
	c = validClaims()
	c["exp"] = time.Now().Add(-time.Minute).Unix()
	if _, err := v.Verify(context.Background(), sign(t, key, hdr, c)); err != ErrExpired {
		t.Fatalf("exp: got %v", err)
	}
	// Signed by a different key than published.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := v.Verify(context.Background(), sign(t, other, hdr, validClaims())); err != ErrNoKey {
		t.Fatalf("wrong key: got %v", err)
	}
	// Unsupported alg.
	if _, err := v.Verify(context.Background(), sign(t, key, map[string]any{"typ": "JWT", "alg": "HS256"}, validClaims())); err != ErrBadAlg {
		t.Fatalf("alg: got %v", err)
	}
	// Garbage input.
	if _, err := v.Verify(context.Background(), "not-a-jwt"); err != ErrMalformedAssertion {
		t.Fatalf("garbage: got %v", err)
	}
}

func TestJWKSUriFallback(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	enc := base64.RawURLEncoding
	jwks := &JWKS{Keys: []JWK{{
		Kty: "EC", Crv: "P-256", Kid: "k1",
		X: enc.EncodeToString(pad32(key.X)),
		Y: enc.EncodeToString(pad32(key.Y)),
	}}}
	v := &Verifier{
		TokenEndpoint: testTokenURL,
		Fetcher: fakeFetcher{
			md:   &Metadata{JWKSUri: "https://agent.example/jwks.json"},
			jwks: jwks,
		},
	}
	a := sign(t, key, map[string]any{"typ": "JWT", "alg": "ES256", "kid": "k1"}, validClaims())
	if _, err := v.Verify(context.Background(), a); err != nil {
		t.Fatalf("jwks_uri fallback rejected: %v", err)
	}
}

func TestAssertionReplayRejected(t *testing.T) {
	key, v := setup(t)
	seen := map[string]bool{}
	v.SeenJTI = func(clientID, jti string) bool {
		k := clientID + "|" + jti
		if seen[k] {
			return true
		}
		seen[k] = true
		return false
	}
	a := sign(t, key, map[string]any{"typ": "JWT", "alg": "ES256", "kid": "k1"}, validClaims())
	if _, err := v.Verify(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), a); err == nil {
		t.Fatal("replayed assertion accepted")
	}
}

func TestRedirectDowngradeRejected(t *testing.T) {
	c := NewClient()
	if c.HTTP.CheckRedirect == nil {
		t.Fatal("NewClient must install a redirect policy")
	}
	req, _ := http.NewRequest("GET", "http://169.254.169.254/latest/meta-data", nil)
	if err := c.HTTP.CheckRedirect(req, nil); err == nil {
		t.Fatal("http redirect target must be rejected")
	}
	req2, _ := http.NewRequest("GET", "https://agent.example/jwks.json", nil)
	if err := c.HTTP.CheckRedirect(req2, nil); err != nil {
		t.Fatalf("https redirect rejected: %v", err)
	}
}
