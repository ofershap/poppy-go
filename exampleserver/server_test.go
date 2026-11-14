package exampleserver

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ofershap/poppy-go/clientassert"
	"github.com/ofershap/poppy-go/internal/jose"
)

// testAgent is a Personal Agent the server is told about by hand, as local
// testing with the official validator works.
type testAgent struct {
	ec       *ecdsa.PrivateKey
	delegKey *ecdsa.PrivateKey
	clientID string
	jwks     *clientassert.JWKS
}

func newTestAgent(t *testing.T) *testAgent {
	t.Helper()
	ecKey, err := jose.GenerateEC()
	if err != nil {
		t.Fatal(err)
	}
	deleg, err := jose.GenerateEC()
	if err != nil {
		t.Fatal(err)
	}
	x, y := jose.ECJWK(ecKey)
	return &testAgent{
		ec:       ecKey,
		delegKey: deleg,
		clientID: "https://agent.example/agent.json",
		jwks:     &clientassert.JWKS{Keys: []clientassert.JWK{{Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: "ec-1"}}},
	}
}

func (a *testAgent) assertion(t *testing.T, issuer, jti string) string {
	t.Helper()
	now := time.Now().Unix()
	jwt, err := jose.SignES256(a.ec, map[string]any{"typ": "JWT", "alg": "ES256", "kid": "ec-1"}, map[string]any{
		"iss": a.clientID, "sub": a.clientID, "aud": issuer,
		"iat": now, "exp": now + 60, "jti": jti,
	})
	if err != nil {
		t.Fatal(err)
	}
	return jwt
}

func (a *testAgent) sessionJWT(t *testing.T, audience, method, url, ath, jti string) string {
	t.Helper()
	x, y := jose.ECJWK(a.delegKey)
	now := time.Now().Unix()
	dlg, err := jose.SignES256(a.ec, map[string]any{"alg": "ES256", "typ": "poppy-delegation+jwt", "kid": "ec-1"}, map[string]any{
		"iss": a.clientID,
		"cnf": map[string]any{"jwk": map[string]any{"kty": "EC", "crv": "P-256", "x": x, "y": y}},
		"iat": now, "exp": now + 7200, "jti": "dlg-" + jti,
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{
		"iss": a.clientID, "aud": audience, "sid": "sid-1", "sub": "usr_1",
		"htm": method, "htu": url, "iat": now, "jti": jti,
	}
	if ath != "" {
		claims["ath"] = ath
	}
	jwt, err := jose.SignES256(a.delegKey, map[string]any{
		"typ": "poppy-session+jwt", "alg": "ES256",
		"kid": jose.ThumbprintEC(x, y), "poppy_dlg": dlg,
	}, claims)
	if err != nil {
		t.Fatal(err)
	}
	return jwt
}

func newTestServer(t *testing.T) (*httptest.Server, *testAgent, string) {
	t.Helper()
	agent := newTestAgent(t)
	// The issuer and domain derive from the test server's URL, so build the
	// company server around a placeholder first and then swap the handler.
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	issuer := s.URL
	domain := strings.TrimPrefix(s.URL, "https://")
	inner, err := New(Config{
		Issuer:       issuer,
		Domain:       domain,
		Name:         "Example Store",
		AgentFetcher: NewStaticAgentFetcher(agent.clientID, agent.jwks),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.Config.Handler = inner
	return s, agent, issuer
}

func getJSON(t *testing.T, c *http.Client, url string) map[string]any {
	t.Helper()
	res, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(res.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDiscoveryAndMetadata(t *testing.T) {
	s, _, issuer := newTestServer(t)
	defer s.Close()
	domain := strings.TrimPrefix(s.URL, "https://")

	doc := getJSON(t, s.Client(), s.URL+"/.well-known/poppy.json")
	if doc["protocol_version"] != "1.0" {
		t.Fatalf("protocol_version %v", doc["protocol_version"])
	}
	org := doc["organization"].(map[string]any)
	if org["domain"] != domain {
		t.Fatalf("domain %v", org["domain"])
	}
	if auth := doc["auth"].(map[string]any); auth["issuer"] != issuer {
		t.Fatalf("issuer %v", auth["issuer"])
	}

	prm := getJSON(t, s.Client(), s.URL+"/.well-known/oauth-protected-resource")
	if prm["resource"] != "https://"+domain {
		t.Fatalf("resource %v", prm["resource"])
	}
	asm := getJSON(t, s.Client(), s.URL+"/.well-known/oauth-authorization-server")
	for _, f := range []string{"issuer", "token_endpoint", "revocation_endpoint"} {
		if asm[f] == nil {
			t.Fatalf("metadata missing %s", f)
		}
	}
	gts := asm["grant_types_supported"].([]any)
	found := false
	for _, g := range gts {
		if g == "refresh_token" {
			found = true
		}
	}
	if !found {
		t.Fatal("grant_types_supported lacks refresh_token")
	}
}

func tokenRequest(t *testing.T, s *httptest.Server, form url.Values) (int, map[string]any) {
	t.Helper()
	res, err := s.Client().Post(s.URL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	m := map[string]any{}
	json.Unmarshal(body, &m)
	return res.StatusCode, m
}

func tokenForm(assertion, grant string) url.Values {
	return url.Values{
		"grant_type":            {grant},
		"client_id":             {"https://agent.example/agent.json"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
		"refresh_token":         {"rt_unknown"},
	}
}

func TestTokenEndpoint(t *testing.T) {
	s, agent, issuer := newTestServer(t)
	defer s.Close()

	// No assertion: invalid_client.
	st, m := tokenRequest(t, s, tokenForm("", "client_credentials"))
	if st != 400 || m["error"] != "invalid_client" {
		t.Fatalf("%d %v", st, m)
	}
	// Valid assertion, unknown refresh token: invalid_grant (spec 4.4).
	st, m = tokenRequest(t, s, tokenForm(agent.assertion(t, issuer, "jti-a"), "refresh_token"))
	if st != 400 || m["error"] != "invalid_grant" {
		t.Fatalf("%d %v", st, m)
	}
	// Replayed assertion jti: invalid_client.
	st, m = tokenRequest(t, s, tokenForm(agent.assertion(t, issuer, "jti-a"), "refresh_token"))
	if st != 400 || m["error"] != "invalid_client" {
		t.Fatalf("replayed jti: %d %v", st, m)
	}
	// aud naming the token endpoint rather than the issuer: invalid_client.
	st, m = tokenRequest(t, s, tokenForm(agent.assertion(t, issuer+"/oauth/token", "jti-b"), "refresh_token"))
	if st != 400 || m["error"] != "invalid_client" {
		t.Fatalf("aud=endpoint: %d %v", st, m)
	}
	// client_credentials issues a Bearer token.
	st, m = tokenRequest(t, s, tokenForm(agent.assertion(t, issuer, "jti-c"), "client_credentials"))
	if st != 200 || m["access_token"] == nil || m["token_type"] != "Bearer" {
		t.Fatalf("%d %v", st, m)
	}
}

// ordersRequest sends a GET /orders with the given headers.
func ordersRequest(t *testing.T, s *httptest.Server, sessionJWT, version, auth string) (int, http.Header, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("GET", s.URL+"/orders", nil)
	if sessionJWT != "" {
		req.Header.Set("Poppy-Session", sessionJWT)
	}
	if version != "" {
		req.Header.Set("Poppy-Version", version)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	res, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	m := map[string]any{}
	json.Unmarshal(body, &m)
	return res.StatusCode, res.Header, m
}

func TestOrdersSessionFlow(t *testing.T) {
	s, agent, issuer := newTestServer(t)
	defer s.Close()
	ordersURL := s.URL + "/orders"

	// No headers at all: the Session check runs first.
	st, _, m := ordersRequest(t, s, "", "", "")
	if st != 400 || m["error"] != "invalid_session" {
		t.Fatalf("no headers: %d %v", st, m)
	}
	// Version, no Session header: invalid_session.
	st, _, m = ordersRequest(t, s, "", "1.0", "")
	if st != 400 || m["error"] != "invalid_session" {
		t.Fatalf("no session: %d %v", st, m)
	}
	// Unsupported version with a valid Session header.
	badVer := agent.sessionJWT(t, issuer, "GET", ordersURL, "", "jti-v")
	st, _, m = ordersRequest(t, s, badVer, "0.0", "")
	if st != 400 || m["error"] != "version_unsupported" {
		t.Fatalf("version 0.0: %d %v", st, m)
	}
	// Valid signed-out Session: 200.
	jwt := agent.sessionJWT(t, issuer, "GET", ordersURL, "", "jti-1")
	st, _, m = ordersRequest(t, s, jwt, "1.0", "")
	if st != 200 || m["session_id"] != "sid-1" || m["user_id"] != "usr_1" {
		t.Fatalf("valid session: %d %v", st, m)
	}

	// An access token the server never issued: 401 invalid_token, in
	// WWW-Authenticate (section 7).
	invented := "validator-invented"
	sum := sha256.Sum256([]byte(invented))
	jwt2 := agent.sessionJWT(t, issuer, "GET", ordersURL, jose.B64.EncodeToString(sum[:]), "jti-2")
	st, hdr, m := ordersRequest(t, s, jwt2, "1.0", "Bearer "+invented)
	if st != 401 || !strings.Contains(hdr.Get("WWW-Authenticate"), "invalid_token") {
		t.Fatalf("invented token: %d %v %v", st, hdr.Get("WWW-Authenticate"), m)
	}

	// ath present without a token: invalid_session.
	jwt3 := agent.sessionJWT(t, issuer, "GET", ordersURL, jose.B64.EncodeToString(sum[:]), "jti-3")
	st, _, m = ordersRequest(t, s, jwt3, "1.0", "")
	if st != 400 || m["error"] != "invalid_session" {
		t.Fatalf("ath without token: %d %v", st, m)
	}
}

func TestIssuedTokenEndToEnd(t *testing.T) {
	s, agent, issuer := newTestServer(t)
	defer s.Close()

	// Issue a token.
	st, m := tokenRequest(t, s, tokenForm(agent.assertion(t, issuer, "jti-1"), "client_credentials"))
	if st != 200 {
		t.Fatalf("%d %v", st, m)
	}
	tok := m["access_token"].(string)
	sum := sha256.Sum256([]byte(tok))
	jwt := agent.sessionJWT(t, issuer, "GET", s.URL+"/orders", jose.B64.EncodeToString(sum[:]), "jti-2")
	st, _, m = ordersRequest(t, s, jwt, "1.0", "Bearer "+tok)
	if st != 200 {
		t.Fatalf("signed-in request: %d %v", st, m)
	}

	// Another agent presenting that token: invalid_session (5.3).
	other := newTestAgent(t)
	sum2 := sha256.Sum256([]byte(tok))
	jwt2 := other.sessionJWT(t, issuer, "GET", s.URL+"/orders", jose.B64.EncodeToString(sum2[:]), "jti-1")
	st, _, m = ordersRequest(t, s, jwt2, "1.0", "Bearer "+tok)
	if st != 400 || m["error"] != "invalid_session" {
		t.Fatalf("other client's token: %d %v", st, m)
	}
	fmt.Println()
}
