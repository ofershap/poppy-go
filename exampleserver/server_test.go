package exampleserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ofershap/poppy-go/clientassert"
)

type fakeFetcher struct{ jwks *clientassert.JWKS }

func (f fakeFetcher) FetchMetadata(ctx context.Context, clientID string) (*clientassert.Metadata, error) {
	return &clientassert.Metadata{JWKS: f.jwks}, nil
}
func (f fakeFetcher) FetchJWKS(ctx context.Context, uri string) (*clientassert.JWKS, error) {
	return f.jwks, nil
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

func jwkOf(key *ecdsa.PrivateKey) map[string]any {
	enc := base64.RawURLEncoding
	return map[string]any{"kty": "EC", "crv": "P-256",
		"x": enc.EncodeToString(pad32(key.X)), "y": enc.EncodeToString(pad32(key.Y))}
}

func signJWS(t *testing.T, key *ecdsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(h) + "." + enc.EncodeToString(p)
	sig, err := signES256(key, []byte(input))
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + enc.EncodeToString(sig)
}

const agentClientID = "https://agent.example/client.json"

func dpop(t *testing.T, key *ecdsa.PrivateKey, jti, method, htu, token string) string {
	t.Helper()
	claims := map[string]any{
		"jti": jti, "htm": method, "htu": htu, "iat": time.Now().Unix(),
	}
	if token != "" {
		sum := sha256.Sum256([]byte(token))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	return signJWS(t, key,
		map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwkOf(key)}, claims)
}

func newTestServer(t *testing.T) (*Server, *ecdsa.PrivateKey) {
	t.Helper()
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	s, err := New(Config{
		Issuer: "https://auth.example.com",
		Domain: "example.com",
		Name:   "Example Store",
		AgentFetcher: fakeFetcher{jwks: &clientassert.JWKS{Keys: []clientassert.JWK{{
			Kty: "EC", Crv: "P-256", Kid: "k1",
			X: enc.EncodeToString(pad32(agentKey.X)),
			Y: enc.EncodeToString(pad32(agentKey.Y)),
		}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, agentKey
}

func do(t *testing.T, s *Server, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestDiscovery(t *testing.T) {
	s, _ := newTestServer(t)
	w := do(t, s, httptest.NewRequest("GET", "https://example.com/.well-known/poppy.json", nil))
	if w.Code != 200 {
		t.Fatalf("poppy.json: %d", w.Code)
	}
	var doc map[string]any
	json.Unmarshal(w.Body.Bytes(), &doc)
	if doc["protocol_version"] != "1.0" {
		t.Fatalf("doc: %v", doc)
	}
}

func TestFullPoppyFlow(t *testing.T) {
	s, agentKey := newTestServer(t)

	// 1. Start a session: client assertion + DPoP proof.
	assertion := signJWS(t, agentKey,
		map[string]any{"typ": "JWT", "alg": "ES256", "kid": "k1"},
		map[string]any{
			"iss": agentClientID, "sub": agentClientID,
			"aud": "https://auth.example.com/oauth/token",
			"exp": time.Now().Add(2 * time.Minute).Unix(),
			"jti": "a1",
		})
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}
	tr := httptest.NewRequest("POST", "https://auth.example.com/oauth/token", strings.NewReader(form.Encode()))
	tr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tr.Header.Set("DPoP", dpop(t, agentKey, "p1", "POST", "https://auth.example.com/oauth/token", ""))
	tw := do(t, s, tr)
	if tw.Code != 200 {
		body, _ := io.ReadAll(tw.Result().Body)
		t.Fatalf("token: %d %s", tw.Code, body)
	}
	var grant struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		SessionID   string `json:"session_id"`
	}
	json.Unmarshal(tw.Body.Bytes(), &grant)
	if grant.AccessToken == "" || grant.TokenType != "DPoP" || grant.SessionID == "" {
		t.Fatalf("grant: %+v", grant)
	}

	// 2. Call the protected API with the bound proof.
	or := httptest.NewRequest("GET", "https://example.com/orders", nil)
	or.Header.Set("Authorization", "DPoP "+grant.AccessToken)
	or.Header.Set("DPoP", dpop(t, agentKey, "p2", "GET", "https://example.com/orders", grant.AccessToken))
	ow := do(t, s, or)
	if ow.Code != 200 {
		t.Fatalf("orders: %d", ow.Code)
	}
	var body map[string]any
	json.Unmarshal(ow.Body.Bytes(), &body)
	if body["session_id"] != grant.SessionID {
		t.Fatalf("orders body: %v", body)
	}

	// 3. No proof: rejected.
	bad1 := httptest.NewRequest("GET", "https://example.com/orders", nil)
	bad1.Header.Set("Authorization", "DPoP "+grant.AccessToken)
	if w := do(t, s, bad1); w.Code != 401 {
		t.Fatalf("no proof: %d", w.Code)
	}

	// 4. Proof from a different key than the token's binding: rejected.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bad2 := httptest.NewRequest("GET", "https://example.com/orders", nil)
	bad2.Header.Set("Authorization", "DPoP "+grant.AccessToken)
	bad2.Header.Set("DPoP", dpop(t, otherKey, "p3", "GET", "https://example.com/orders", grant.AccessToken))
	if w := do(t, s, bad2); w.Code != 401 {
		t.Fatalf("wrong key proof: %d", w.Code)
	}

	// 5. Bearer scheme: rejected.
	bad3 := httptest.NewRequest("GET", "https://example.com/orders", nil)
	bad3.Header.Set("Authorization", "Bearer "+grant.AccessToken)
	bad3.Header.Set("DPoP", dpop(t, agentKey, "p4", "GET", "https://example.com/orders", grant.AccessToken))
	if w := do(t, s, bad3); w.Code != 401 {
		t.Fatalf("bearer: %d", w.Code)
	}
}
