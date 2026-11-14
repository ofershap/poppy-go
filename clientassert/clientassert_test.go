package clientassert

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/ofershap/poppy-go/internal/jose"
)

const (
	testClientID = "https://agent.example/agent.json"
	testIssuer   = "https://auth.shop.example"
)

type fakeFetcher struct {
	md   *Metadata
	jwks *JWKS
}

func (f *fakeFetcher) FetchMetadata(context.Context, string) (*Metadata, error) { return f.md, nil }
func (f *fakeFetcher) FetchJWKS(context.Context, string) (*JWKS, error)         { return f.jwks, nil }

type agentFixture struct {
	ec  *ecdsa.PrivateKey
	rsa *rsa.PrivateKey
	md  *Metadata
}

func newAgentFixture(t *testing.T) *agentFixture {
	t.Helper()
	ecKey, err := jose.GenerateEC()
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := jose.GenerateRSA()
	if err != nil {
		t.Fatal(err)
	}
	x, y := jose.ECJWK(ecKey)
	n, e := jose.RSAJWK(rsaKey)
	return &agentFixture{
		ec:  ecKey,
		rsa: rsaKey,
		md: &Metadata{JWKS: &JWKS{Keys: []JWK{
			{Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: "ec-1", Alg: "ES256", Use: "sig"},
			{Kty: "RSA", N: n, E: e, Kid: "rsa-1", Alg: "PS384", Use: "sig"},
		}}},
	}
}

type assertionOpts struct {
	aud      any
	jti      string
	iat      int64
	exp      int64
	sub      *string
	rsa      bool
	stranger *ecdsa.PrivateKey
	kid      string
}

func (a *agentFixture) assertion(t *testing.T, o assertionOpts) string {
	t.Helper()
	now := time.Now().Unix()
	iat := now
	if o.iat != 0 {
		iat = o.iat
	}
	exp := now + 60
	if o.exp != 0 {
		exp = o.exp
	}
	aud := any(testIssuer)
	if o.aud != nil {
		aud = o.aud
	}
	sub := testClientID
	if o.sub != nil {
		sub = *o.sub
	}
	jti := "jti-1"
	if o.jti != "" {
		jti = o.jti
	}
	claims := map[string]any{
		"iss": testClientID, "sub": sub, "aud": aud,
		"iat": iat, "exp": exp, "jti": jti,
	}
	if o.rsa {
		kid := "rsa-1"
		if o.kid != "" {
			kid = o.kid
		}
		jwt, err := jose.SignPS384(a.rsa, map[string]any{"typ": "JWT", "alg": "PS384", "kid": kid}, claims)
		if err != nil {
			t.Fatal(err)
		}
		return jwt
	}
	key := a.ec
	if o.stranger != nil {
		key = o.stranger
	}
	kid := "ec-1"
	if o.kid != "" {
		kid = o.kid
	}
	jwt, err := jose.SignES256(key, map[string]any{"typ": "JWT", "alg": "ES256", "kid": kid}, claims)
	if err != nil {
		t.Fatal(err)
	}
	return jwt
}

func verifierFor(md *Metadata, seen func(string, string) bool) *Verifier {
	return &Verifier{Issuer: testIssuer, Fetcher: &fakeFetcher{md: md}, SeenJTI: seen}
}

func TestVerifyES256(t *testing.T) {
	a := newAgentFixture(t)
	v := verifierFor(a.md, nil)
	got, err := v.Verify(context.Background(), a.assertion(t, assertionOpts{}))
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientID != testClientID {
		t.Fatalf("client_id %q", got.ClientID)
	}
}

func TestVerifyPS384(t *testing.T) {
	a := newAgentFixture(t)
	v := verifierFor(a.md, nil)
	if _, err := v.Verify(context.Background(), a.assertion(t, assertionOpts{rsa: true})); err != nil {
		t.Fatal(err)
	}
}

func TestRejects(t *testing.T) {
	a := newAgentFixture(t)
	stranger, _ := jose.GenerateEC()
	empty := ""
	cases := []struct {
		name string
		opts assertionOpts
		want error
	}{
		{"aud is another issuer", assertionOpts{aud: "https://other.example"}, ErrAudience},
		{"aud is the token endpoint URL", assertionOpts{aud: testIssuer + "/oauth/token"}, ErrAudience},
		{"aud is an array", assertionOpts{aud: []string{testIssuer, "https://other.example"}}, ErrAudience},
		{"expired", assertionOpts{iat: time.Now().Unix() - 600, exp: time.Now().Unix() - 300}, ErrExpired},
		{"no sub", assertionOpts{sub: &empty}, ErrIssuerMismatch},
		{"stranger signature", assertionOpts{stranger: stranger}, ErrNoKey},
		{"unknown kid", assertionOpts{kid: "nope"}, ErrNoKey},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := verifierFor(a.md, nil)
			_, err := v.Verify(context.Background(), a.assertion(t, assertionOpts{
				aud: c.opts.aud, iat: c.opts.iat, exp: c.opts.exp,
				sub: c.opts.sub, stranger: c.opts.stranger, kid: c.opts.kid,
			}))
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestRejectsMissingExp(t *testing.T) {
	a := newAgentFixture(t)
	stranger := a.ec
	claims := map[string]any{"iss": testClientID, "sub": testClientID, "aud": testIssuer, "iat": time.Now().Unix(), "jti": "x"}
	jwt, err := jose.SignES256(stranger, map[string]any{"typ": "JWT", "alg": "ES256", "kid": "ec-1"}, claims)
	if err != nil {
		t.Fatal(err)
	}
	v := verifierFor(a.md, nil)
	if _, err := v.Verify(context.Background(), jwt); !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v, want %v", err, ErrExpired)
	}
}

func TestRejectsNonHTTPSClientID(t *testing.T) {
	a := newAgentFixture(t)
	claims := map[string]any{
		"iss": "http://agent.example/agent.json", "sub": "http://agent.example/agent.json",
		"aud": testIssuer, "iat": time.Now().Unix(), "exp": time.Now().Unix() + 60, "jti": "x",
	}
	jwt, _ := jose.SignES256(a.ec, map[string]any{"typ": "JWT", "alg": "ES256", "kid": "ec-1"}, claims)
	v := verifierFor(a.md, nil)
	if _, err := v.Verify(context.Background(), jwt); !errors.Is(err, ErrClientID) {
		t.Fatalf("got %v, want %v", err, ErrClientID)
	}
}

func TestJTIReplay(t *testing.T) {
	a := newAgentFixture(t)
	seen := map[string]bool{}
	v := verifierFor(a.md, func(c, j string) bool {
		k := c + "|" + j
		if seen[k] {
			return true
		}
		seen[k] = true
		return false
	})
	jwt := a.assertion(t, assertionOpts{jti: "once"})
	if _, err := v.Verify(context.Background(), jwt); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), jwt); err == nil {
		t.Fatal("replayed jti accepted")
	}
}

func TestMetadataIssuerMismatch(t *testing.T) {
	a := newAgentFixture(t)
	md := &Metadata{Issuer: "https://someone-else.example/agent.json", JWKS: a.md.JWKS}
	v := verifierFor(md, nil)
	if _, err := v.Verify(context.Background(), a.assertion(t, assertionOpts{})); !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("got %v, want %v", err, ErrIssuerMismatch)
	}
}
