package session

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ofershap/poppy-go/clientassert"
	"github.com/ofershap/poppy-go/internal/jose"
)

const (
	testClientID = "https://agent.example/agent.json"
	testAudience = "https://auth.shop.example"
	testURL      = "https://shop.example/orders"
)

type fakeFetcher struct{ jwks *clientassert.JWKS }

func (f *fakeFetcher) FetchMetadata(context.Context, string) (*clientassert.Metadata, error) {
	return &clientassert.Metadata{JWKS: f.jwks}, nil
}
func (f *fakeFetcher) FetchJWKS(context.Context, string) (*clientassert.JWKS, error) {
	return nil, nil
}

type agent struct {
	ec       *ecdsa.PrivateKey
	rsa      *rsa.PrivateKey
	delegKey *ecdsa.PrivateKey
	fetcher  *fakeFetcher
}

func newAgent(t *testing.T) *agent {
	t.Helper()
	ecKey, err := jose.GenerateEC()
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := jose.GenerateRSA()
	if err != nil {
		t.Fatal(err)
	}
	deleg, err := jose.GenerateEC()
	if err != nil {
		t.Fatal(err)
	}
	x, y := jose.ECJWK(ecKey)
	n, e := jose.RSAJWK(rsaKey)
	return &agent{
		ec:       ecKey,
		rsa:      rsaKey,
		delegKey: deleg,
		fetcher: &fakeFetcher{jwks: &clientassert.JWKS{Keys: []clientassert.JWK{
			{Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: "ec-1"},
			{Kty: "RSA", N: n, E: e, Kid: "rsa-1"},
		}}},
	}
}

type dlgOpts struct {
	rsa      bool
	typ      string
	kid      string
	iss      string
	iat      int64
	lifetime int64
	stranger *ecdsa.PrivateKey
	cnfD     bool
}

func (a *agent) delegation(t *testing.T, deleg *ecdsa.PrivateKey, o dlgOpts) string {
	t.Helper()
	if deleg == nil {
		deleg = a.delegKey
	}
	x, y := jose.ECJWK(deleg)
	iat := time.Now().Unix()
	if o.iat != 0 {
		iat = o.iat
	}
	lifetime := int64(7200)
	if o.lifetime != 0 {
		lifetime = o.lifetime
	}
	iss := testClientID
	if o.iss != "" {
		iss = o.iss
	}
	typ := "poppy-delegation+jwt"
	if o.typ != "" {
		typ = o.typ
	}
	claims := map[string]any{
		"iss": iss,
		"cnf": map[string]any{"jwk": map[string]any{"kty": "EC", "crv": "P-256", "x": x, "y": y}},
		"iat": iat, "exp": iat + lifetime, "jti": "dlg-1",
	}
	if o.cnfD {
		claims["cnf"].(map[string]any)["jwk"].(map[string]any)["d"] = "private-material"
	}
	if o.rsa {
		kid := "rsa-1"
		if o.kid != "" {
			kid = o.kid
		}
		dlg, err := jose.SignPS384(a.rsa, map[string]any{"alg": "PS384", "typ": typ, "kid": kid}, claims)
		if err != nil {
			t.Fatal(err)
		}
		return dlg
	}
	key := a.ec
	if o.stranger != nil {
		key = o.stranger
	}
	kid := "ec-1"
	if o.kid != "" {
		kid = o.kid
	}
	dlg, err := jose.SignES256(key, map[string]any{"alg": "ES256", "typ": typ, "kid": kid}, claims)
	if err != nil {
		t.Fatal(err)
	}
	return dlg
}

type jwtOpts struct {
	key     *ecdsa.PrivateKey
	dlg     string
	noDlg   bool
	typ     string
	kid     string
	sid     string
	dropSub bool
	drop    []string
	ps384   bool
	aud     string
	htm     string
	htu     string
	iat     int64
	jti     string
	ath     *string
	agentID string
}

func (a *agent) sessionJWT(t *testing.T, o jwtOpts) string {
	t.Helper()
	key := a.delegKey
	if o.key != nil {
		key = o.key
	}
	x, y := jose.ECJWK(key)
	kid := jose.ThumbprintEC(x, y)
	if o.kid != "" {
		kid = o.kid
	}
	typ := "poppy-session+jwt"
	if o.typ != "" {
		typ = o.typ
	}
	dlg := o.dlg
	if dlg == "" && !o.noDlg {
		dlg = a.delegation(t, key, dlgOpts{})
	}
	hdr := map[string]any{"typ": typ, "alg": "ES256", "kid": kid, "poppy_dlg": dlg}
	if o.noDlg {
		delete(hdr, "poppy_dlg")
	}
	sid := "sid-1"
	if o.sid != "" {
		sid = o.sid
	}
	aud := testAudience
	if o.aud != "" {
		aud = o.aud
	}
	htm := "GET"
	if o.htm != "" {
		htm = o.htm
	}
	htu := testURL
	if o.htu != "" {
		htu = o.htu
	}
	iat := time.Now().Unix()
	if o.iat != 0 {
		iat = o.iat
	}
	jti := "jti-1"
	if o.jti != "" {
		jti = o.jti
	}
	claims := map[string]any{
		"iss": testClientID, "aud": aud, "sid": sid, "sub": "usr_1",
		"htm": htm, "htu": htu, "iat": iat, "jti": jti,
	}
	if o.dropSub {
		delete(claims, "sub")
	}
	if o.agentID != "" {
		claims["agent_id"] = o.agentID
	}
	if o.ath != nil {
		claims["ath"] = *o.ath
	}
	for _, k := range o.drop {
		delete(claims, k)
	}
	if o.ps384 {
		hdr["alg"] = "PS384"
		jwt, err := jose.SignPS384(a.rsa, hdr, claims)
		if err != nil {
			t.Fatal(err)
		}
		return jwt
	}
	jwt, err := jose.SignES256(key, hdr, claims)
	if err != nil {
		t.Fatal(err)
	}
	return jwt
}

func newVerifier(a *agent) *Verifier {
	return &Verifier{Audience: testAudience, Versions: []string{"1.0"}, Fetcher: a.fetcher}
}

func verify(t *testing.T, v *Verifier, jwt, version, auth string) (*Identity, *Error) {
	t.Helper()
	r := httptest.NewRequest("GET", testURL, nil)
	r.Header.Set("Poppy-Session", jwt)
	if version != "" {
		r.Header.Set("Poppy-Version", version)
	}
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	return v.VerifyRequest(r)
}

func mustAccept(t *testing.T, v *Verifier, jwt string) *Identity {
	t.Helper()
	id, serr := verify(t, v, jwt, "1.0", "")
	if serr != nil {
		t.Fatal(serr)
	}
	return id
}

func mustReject(t *testing.T, v *Verifier, jwt string) {
	t.Helper()
	id, serr := verify(t, v, jwt, "1.0", "")
	if serr == nil {
		t.Fatalf("expected rejection, got %+v", id)
	}
	if serr.Code != CodeInvalidSession {
		t.Fatalf("code %q, want %q (%v)", serr.Code, CodeInvalidSession, serr)
	}
}

func TestValidSessionES256Delegation(t *testing.T) {
	a := newAgent(t)
	id := mustAccept(t, newVerifier(a), a.sessionJWT(t, jwtOpts{}))
	if id.ClientID != testClientID || id.UserID != "usr_1" || id.SessionID != "sid-1" {
		t.Fatalf("identity %+v", id)
	}
}

func TestValidSessionPS384Delegation(t *testing.T) {
	a := newAgent(t)
	dlg := a.delegation(t, nil, dlgOpts{rsa: true})
	mustAccept(t, newVerifier(a), a.sessionJWT(t, jwtOpts{dlg: dlg}))
}

func TestNewDelegatedKeySameSession(t *testing.T) {
	a := newAgent(t)
	v := newVerifier(a)
	mustAccept(t, v, a.sessionJWT(t, jwtOpts{}))
	fresh, _ := jose.GenerateEC()
	mustAccept(t, v, a.sessionJWT(t, jwtOpts{key: fresh, jti: "jti-2"}))
}

func TestNewSIDStartsAnotherSession(t *testing.T) {
	a := newAgent(t)
	v := newVerifier(a)
	mustAccept(t, v, a.sessionJWT(t, jwtOpts{}))
	mustAccept(t, v, a.sessionJWT(t, jwtOpts{sid: "sid-2", jti: "jti-2"}))
}

func TestRejections(t *testing.T) {
	stranger, err := jose.GenerateEC()
	if err != nil {
		t.Fatal(err)
	}
	ath := "not-a-hash"
	cases := []struct {
		name string
		jwt  func(a *agent) string
	}{
		{"typ not poppy-session+jwt", func(a *agent) string {
			return a.sessionJWT(t, jwtOpts{typ: "JWT"})
		}},
		{"no delegation", func(a *agent) string {
			return a.sessionJWT(t, jwtOpts{noDlg: true})
		}},
		{"signed by key delegation doesn't name", func(a *agent) string {
			// Delegation vouches for delegKey, JWT signed by stranger, but
			// kid claims the delegated key's thumbprint.
			x, y := jose.ECJWK(a.delegKey)
			return a.sessionJWT(t, jwtOpts{key: stranger, kid: jose.ThumbprintEC(x, y)})
		}},
		{"kid is not the key's thumbprint", func(a *agent) string {
			x, y := jose.ECJWK(stranger)
			return a.sessionJWT(t, jwtOpts{kid: jose.ThumbprintEC(x, y)})
		}},
		{"delegation signed by stranger under real kid", func(a *agent) string {
			dlg := a.delegation(t, nil, dlgOpts{stranger: stranger})
			return a.sessionJWT(t, jwtOpts{dlg: dlg})
		}},
		{"delegation expired", func(a *agent) string {
			dlg := a.delegation(t, nil, dlgOpts{iat: time.Now().Unix() - 7200, lifetime: 3600})
			return a.sessionJWT(t, jwtOpts{dlg: dlg})
		}},
		{"delegation lasts 25 hours", func(a *agent) string {
			dlg := a.delegation(t, nil, dlgOpts{lifetime: 25 * 3600})
			return a.sessionJWT(t, jwtOpts{dlg: dlg})
		}},
		{"delegation typ", func(a *agent) string {
			dlg := a.delegation(t, nil, dlgOpts{typ: "JWT"})
			return a.sessionJWT(t, jwtOpts{dlg: dlg})
		}},
		{"delegation iss another client", func(a *agent) string {
			dlg := a.delegation(t, nil, dlgOpts{iss: "https://other.example/agent.json"})
			return a.sessionJWT(t, jwtOpts{dlg: dlg})
		}},
		{"delegation kid unknown", func(a *agent) string {
			dlg := a.delegation(t, nil, dlgOpts{kid: "nope"})
			return a.sessionJWT(t, jwtOpts{dlg: dlg})
		}},
		{"no sub", func(a *agent) string {
			return a.sessionJWT(t, jwtOpts{dropSub: true})
		}},
		{"aud another company", func(a *agent) string {
			return a.sessionJWT(t, jwtOpts{aud: testAudience + "/other"})
		}},
		{"htm mismatch", func(a *agent) string {
			return a.sessionJWT(t, jwtOpts{htm: "POST"})
		}},
		{"htu mismatch", func(a *agent) string {
			return a.sessionJWT(t, jwtOpts{htu: "https://shop.example/other"})
		}},
		{"iat an hour old", func(a *agent) string {
			return a.sessionJWT(t, jwtOpts{iat: time.Now().Unix() - 3600})
		}},
		{"ath without token", func(a *agent) string {
			return a.sessionJWT(t, jwtOpts{ath: &ath})
		}},
		{"session JWT signed PS384", func(a *agent) string {
			return a.sessionJWT(t, jwtOpts{ps384: true})
		}},
		{"delegation PS384 header names EC key", func(a *agent) string {
			dlg := a.delegation(t, nil, dlgOpts{rsa: true, kid: "ec-1"})
			return a.sessionJWT(t, jwtOpts{dlg: dlg})
		}},
		{"delegation ES256 header names RSA key", func(a *agent) string {
			dlg := a.delegation(t, nil, dlgOpts{kid: "rsa-1"})
			return a.sessionJWT(t, jwtOpts{dlg: dlg})
		}},
		{"delegation cnf.jwk leaks private key", func(a *agent) string {
			dlg := a.delegation(t, nil, dlgOpts{cnfD: true})
			return a.sessionJWT(t, jwtOpts{dlg: dlg})
		}},
		{"no iss", func(a *agent) string {
			return a.sessionJWT(t, jwtOpts{drop: []string{"iss"}})
		}},
		{"no aud", func(a *agent) string {
			return a.sessionJWT(t, jwtOpts{drop: []string{"aud"}})
		}},
		{"no sid", func(a *agent) string {
			return a.sessionJWT(t, jwtOpts{drop: []string{"sid"}})
		}},
		{"no jti", func(a *agent) string {
			return a.sessionJWT(t, jwtOpts{drop: []string{"jti"}})
		}},
		{"no htm", func(a *agent) string {
			return a.sessionJWT(t, jwtOpts{drop: []string{"htm"}})
		}},
		{"no htu", func(a *agent) string {
			return a.sessionJWT(t, jwtOpts{drop: []string{"htu"}})
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := newAgent(t)
			mustReject(t, newVerifier(a), c.jwt(a))
		})
	}
}

func TestJTIReplay(t *testing.T) {
	a := newAgent(t)
	v := newVerifier(a)
	jwt := a.sessionJWT(t, jwtOpts{})
	mustAccept(t, v, jwt)
	mustReject(t, v, jwt) // same JWT again: same jti
}

func TestAgentIDStaysConstantWithinSession(t *testing.T) {
	a := newAgent(t)
	v := newVerifier(a)
	mustAccept(t, v, a.sessionJWT(t, jwtOpts{agentID: "agent-a"}))
	// Same Session, a different agent_id (5.2: they don't change).
	mustReject(t, v, a.sessionJWT(t, jwtOpts{agentID: "agent-b", jti: "jti-2"}))
}

func TestAccessTokenATH(t *testing.T) {
	a := newAgent(t)
	v := newVerifier(a)
	token := "tok-123"
	sum := sha256.Sum256([]byte(token))
	good := jose.B64.EncodeToString(sum[:])
	jwt := a.sessionJWT(t, jwtOpts{ath: &good})
	id, serr := verify(t, v, jwt, "1.0", "Bearer "+token)
	if serr != nil {
		t.Fatal(serr)
	}
	if id.AccessToken != token {
		t.Fatalf("token %q", id.AccessToken)
	}
	// ath names a different token.
	jwt2 := a.sessionJWT(t, jwtOpts{ath: &good, jti: "jti-2"})
	if _, serr := verify(t, v, jwt2, "1.0", "Bearer other"); serr == nil {
		t.Fatal("mismatched ath accepted")
	}
}

func TestVersionCheck(t *testing.T) {
	a := newAgent(t)
	v := newVerifier(a)
	// Each case needs a fresh jti: session verification runs first and
	// consumes it.
	for i, version := range []string{"", "0.0"} {
		jwt := a.sessionJWT(t, jwtOpts{jti: fmt.Sprintf("jti-v%d", i)})
		_, serr := verify(t, v, jwt, version, "")
		if serr == nil || serr.Code != CodeVersionUnsupported {
			t.Fatalf("version %q: %v", version, serr)
		}
	}
}
