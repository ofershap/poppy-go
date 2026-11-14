// Package exampleserver is a minimal but complete Poppy company deployment
// built on poppy-go: the discovery document, OAuth issuer and protected
// resource metadata, a token endpoint that verifies client assertions, and
// a protected API that verifies the Poppy-Session header. It exists so the
// official validator (and humans) have something real to test against.
//
// It is an example, not a hardened identity provider: tokens live in
// memory, there are no real users or sign-in flows, and the refresh_token
// grant always answers invalid_grant.
package exampleserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ofershap/poppy-go/clientassert"
	"github.com/ofershap/poppy-go/poppyjson"
	"github.com/ofershap/poppy-go/session"
)

// ProtocolVersion is the draft this example speaks.
const ProtocolVersion = "1.0"

// Config configures the server.
type Config struct {
	// Issuer is the Company's OAuth issuer identifier, such as
	// https://shop.example.com. Client assertions must name it in aud and
	// Session JWTs in aud (spec 4.1, 5.2).
	Issuer string
	// Domain is the host (with port when not 443) that serves poppy.json,
	// such as shop.example.com or localhost:8443.
	Domain string
	// Name is the company's display name.
	Name string
	// AgentFetcher resolves agent metadata and JWKS; use
	// clientassert.NewClient() in production, or NewStaticAgentFetcher for
	// local testing with a hand-registered test agent.
	AgentFetcher clientassert.Fetcher
}

// Server is a Poppy company deployment.
type Server struct {
	cfg    Config
	mux    *http.ServeMux
	sess   *session.Verifier
	assert *clientassert.Verifier

	mu      sync.Mutex
	tokens  map[string]tokenRecord
	seenJTI map[string]bool
}

type tokenRecord struct {
	clientID string
	expires  time.Time
}

// New builds the server. Issuer and Domain are required.
func New(cfg Config) (*Server, error) {
	if cfg.Issuer == "" || cfg.Domain == "" {
		return nil, fmt.Errorf("exampleserver: Issuer and Domain are required")
	}
	if cfg.AgentFetcher == nil {
		return nil, fmt.Errorf("exampleserver: AgentFetcher is required")
	}
	s := &Server{
		cfg:     cfg,
		mux:     http.NewServeMux(),
		tokens:  make(map[string]tokenRecord),
		seenJTI: make(map[string]bool),
	}
	s.sess = &session.Verifier{
		Audience: cfg.Issuer,
		Versions: []string{ProtocolVersion},
		Fetcher:  cfg.AgentFetcher,
	}
	s.assert = &clientassert.Verifier{
		Issuer:  cfg.Issuer,
		Fetcher: cfg.AgentFetcher,
		SeenJTI: func(clientID, jti string) bool {
			s.mu.Lock()
			defer s.mu.Unlock()
			k := clientID + "|" + jti
			if s.seenJTI[k] {
				return true
			}
			s.seenJTI[k] = true
			return false
		},
	}

	doc := &poppyjson.Document{
		ProtocolVersion: ProtocolVersion,
		Organization:    poppyjson.Organization{Name: cfg.Name, Domain: cfg.Domain},
		Auth: &poppyjson.Auth{
			Issuer: cfg.Issuer,
			Scopes: map[string]string{"orders:read": "See your orders"},
		},
		APIs: []poppyjson.API{{
			Type: "rest", URL: cfg.Issuer + "/orders",
			Description: "List the signed-in user's orders",
		}},
	}
	docHandler, err := poppyjson.Handler(doc, 300)
	if err != nil {
		return nil, err
	}
	s.mux.Handle(poppyjson.Path, docHandler)
	s.mux.HandleFunc("/.well-known/oauth-protected-resource", s.protectedResource)
	s.mux.HandleFunc("/.well-known/oauth-authorization-server", s.authServerMeta)
	s.mux.HandleFunc("/oauth/token", s.token)
	s.mux.HandleFunc("/oauth/revoke", s.revoke)
	s.mux.HandleFunc("/orders", s.orders)
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeError reports a protocol or OAuth error as a JSON body (spec 7).
func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func (s *Server) protectedResource(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 "https://" + s.cfg.Domain,
		"authorization_servers":    []string{s.cfg.Issuer},
		"scopes_supported":         []string{"orders:read"},
		"bearer_methods_supported": []string{"header"},
	})
}

func (s *Server) authServerMeta(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                s.cfg.Issuer,
		"token_endpoint":        s.cfg.Issuer + "/oauth/token",
		"revocation_endpoint":   s.cfg.Issuer + "/oauth/revoke",
		"grant_types_supported": []string{"client_credentials", "refresh_token"},
		"protected_resources":   []string{"https://" + s.cfg.Domain},
		"scopes_supported":      []string{"orders:read"},
		"token_endpoint_auth_signing_alg_values_supported": []string{"ES256", "PS384"},
	})
}

// token is the token endpoint (spec 4.1, 4.4): it verifies the Personal
// Agent's client assertion, issues access tokens for the client_credentials
// grant this demo uses, and answers invalid_grant for refresh tokens it
// never issued.
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "invalid_request")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if r.PostForm.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		writeError(w, http.StatusBadRequest, "invalid_client")
		return
	}
	a, err := s.assert.Verify(r.Context(), r.PostForm.Get("client_assertion"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_client")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "client_credentials":
		tok := randomID(24)
		s.mu.Lock()
		s.tokens[tok] = tokenRecord{clientID: a.ClientID, expires: time.Now().Add(time.Hour)}
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": tok,
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "orders:read",
		})
	case "refresh_token":
		// The example issues no refresh tokens, so every presented one is
		// unknown.
		writeError(w, http.StatusBadRequest, "invalid_grant")
	default:
		writeError(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

// revoke is the revocation endpoint (spec 4.6). The example's tokens are
// in-memory; an unknown token still gets 200, as RFC 7009 requires.
func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		if tok := r.PostForm.Get("token"); tok != "" {
			s.mu.Lock()
			delete(s.tokens, tok)
			s.mu.Unlock()
		}
	}
	w.WriteHeader(http.StatusOK)
}

// orders is the protected API: every request carries the Session header
// (spec 5.2), signed in or out; a presented access token must be one this
// issuer issued to the same Personal Agent (spec 5.3, section 7).
func (s *Server) orders(w http.ResponseWriter, r *http.Request) {
	id, serr := s.sess.VerifyRequest(r)
	if serr != nil {
		writeError(w, http.StatusBadRequest, serr.Code)
		return
	}
	if id.AccessToken != "" {
		s.mu.Lock()
		rec, ok := s.tokens[id.AccessToken]
		s.mu.Unlock()
		switch {
		case !ok || time.Now().After(rec.expires):
			// Access token errors are OAuth errors in WWW-Authenticate
			// (section 7), never invalid_session.
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "invalid_token")
			return
		case rec.clientID != id.ClientID:
			// A token issued to another Personal Agent (5.3).
			writeError(w, http.StatusBadRequest, "invalid_session")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"orders": []map[string]any{
			{"id": "ord-1", "item": "Rain jacket", "status": "delivered"},
			{"id": "ord-2", "item": "Trail shoes", "status": "shipped"},
		},
		"session_id": id.SessionID,
		"user_id":    id.UserID,
	})
}

func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(b), "=")
}

// NewStaticAgentFetcher returns an AgentFetcher that knows exactly one
// Personal Agent: its client_id and public keys, registered by hand. Local
// testing uses it to register the official validator's test agent (its
// client_id is a loopback URL, which the production fetcher rightly refuses
// to fetch); production deployments fetch metadata over HTTPS with
// clientassert.NewClient instead.
func NewStaticAgentFetcher(clientID string, jwks *clientassert.JWKS) clientassert.Fetcher {
	return &staticFetcher{clientID: clientID, jwks: jwks}
}

type staticFetcher struct {
	clientID string
	jwks     *clientassert.JWKS
}

func (f *staticFetcher) FetchMetadata(_ context.Context, clientID string) (*clientassert.Metadata, error) {
	if clientID != f.clientID {
		return nil, fmt.Errorf("exampleserver: unknown client_id %s", clientID)
	}
	return &clientassert.Metadata{JWKS: f.jwks}, nil
}

func (f *staticFetcher) FetchJWKS(_ context.Context, uri string) (*clientassert.JWKS, error) {
	return nil, fmt.Errorf("exampleserver: static fetcher serves no jwks_uri %s", uri)
}
