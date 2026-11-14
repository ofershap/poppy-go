// Package exampleserver is a minimal but complete Poppy company deployment
// built on poppy-go: discovery document, token endpoint issuing DPoP-bound
// session tokens, and a protected API. It exists so the official validator
// (and humans) have something real to test against. It is an example, not a
// hardened identity provider: sessions live in memory and the issuer key is
// generated at startup.
package exampleserver

import (
	"crypto"
	"crypto/ecdsa"
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

// Config configures the server.
type Config struct {
	// Issuer is the OAuth issuer identifier, e.g. https://auth.example.com.
	Issuer string
	// Domain is the company's domain, e.g. example.com.
	Domain string
	// Name is the company's display name.
	Name string
	// AgentFetcher resolves agent metadata; use clientassert.NewClient() in
	// production.
	AgentFetcher clientassert.Fetcher
}

// Server is a Poppy company deployment.
type Server struct {
	cfg    Config
	mux    *http.ServeMux
	key    *ecdsa.PrivateKey
	sess   *session.Verifier
	assert *clientassert.Verifier

	mu       sync.Mutex
	sessions map[string]*sessionState
}

type sessionState struct {
	userID string
	thumb  string
}

// New builds the server. issuer and domain are required.
func New(cfg Config) (*Server, error) {
	if cfg.Issuer == "" || cfg.Domain == "" {
		return nil, fmt.Errorf("exampleserver: Issuer and Domain are required")
	}
	key, err := session.GenerateTestKey()
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:      cfg,
		mux:      http.NewServeMux(),
		key:      key,
		sessions: make(map[string]*sessionState),
	}
	s.sess = &session.Verifier{
		Issuer:   cfg.Issuer,
		Audience: "https://" + cfg.Domain,
		IssuerKeys: func(kid string) (crypto.PublicKey, error) {
			if kid != "issuer-1" {
				return nil, fmt.Errorf("unknown kid")
			}
			return &key.PublicKey, nil
		},
		Replay: session.NewMemoryReplayCache(10 * time.Minute),
	}
	s.assert = &clientassert.Verifier{
		TokenEndpoint: cfg.Issuer + "/oauth/token",
		Fetcher:       cfg.AgentFetcher,
	}

	doc := &poppyjson.Document{
		ProtocolVersion: "1.0",
		Organization:    poppyjson.Organization{Name: cfg.Name, Domain: cfg.Domain},
		Auth: &poppyjson.Auth{
			Issuer: cfg.Issuer,
			Direct: &poppyjson.SignIn{Scopes: map[string]string{
				"orders:read": "See your orders",
			}},
		},
		APIs: []poppyjson.API{{
			Type: "openapi", Endpoint: "https://" + cfg.Domain,
			Description: "Orders API",
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
	s.mux.HandleFunc("/orders", s.orders)
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func (s *Server) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (s *Server) protectedResource(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, map[string]any{
		"resource":              "https://" + s.cfg.Domain,
		"authorization_servers": []string{s.cfg.Issuer},
	})
}

func (s *Server) authServerMeta(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, map[string]any{
		"issuer":                            s.cfg.Issuer,
		"token_endpoint":                    s.cfg.Issuer + "/oauth/token",
		"grant_types_supported":             []string{"client_credentials"},
		"dpop_signing_alg_values_supported": []string{"ES256"},
		"protected_resources":               []string{"https://" + s.cfg.Domain},
	})
}

// token implements the Session-start grant: a verified client assertion in,
// a DPoP-bound session token out (spec 4.2).
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	assertion := r.PostForm.Get("client_assertion")
	a, err := s.assert.Verify(r.Context(), assertion)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid_client","detail":%q}`, err.Error()), http.StatusUnauthorized)
		return
	}
	// The agent's DPoP proof on this request establishes the key the session
	// token is bound to (spec 4.3).
	proof, err := s.sess.VerifyProof(r, "")
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid_dpop_proof","detail":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	sessID := randomID()
	userID := "u-" + randomID() // pairwise: different at each company
	s.mu.Lock()
	s.sessions[sessID] = &sessionState{userID: userID, thumb: proof.KeyThumbprint}
	s.mu.Unlock()

	tok, err := s.signSessionToken(sessID, userID, false, "orders:read", proof.KeyThumbprint)
	if err != nil {
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}
	s.writeJSON(w, map[string]any{
		"access_token": tok,
		"token_type":   "DPoP",
		"expires_in":   300,
		"session_id":   sessID,
		"user_id":      userID,
	})
	_ = a
}

// orders is the protected resource: DPoP proof + bound session token.
func (s *Server) orders(w http.ResponseWriter, r *http.Request) {
	raw, err := session.ExtractToken(r)
	if err != nil {
		http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
		return
	}
	proof, err := s.sess.VerifyProof(r, raw)
	if err != nil {
		http.Error(w, `{"error":"invalid_dpop_proof"}`, http.StatusUnauthorized)
		return
	}
	tok, err := s.sess.VerifyToken(raw, proof)
	if err != nil {
		http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
		return
	}
	if !tok.RequireScopes("orders:read") {
		http.Error(w, `{"error":"insufficient_scope"}`, http.StatusForbidden)
		return
	}
	s.writeJSON(w, map[string]any{
		"orders": []map[string]any{
			{"id": "ord-1", "item": "Rain jacket", "status": "delivered"},
			{"id": "ord-2", "item": "Trail shoes", "status": "shipped"},
		},
		"session_id": tok.SessionID,
		"user_id":    tok.UserID,
	})
}

// signSessionToken issues an ES256 session token with cnf.jkt binding.
func (s *Server) signSessionToken(sessID, userID string, signedIn bool, scope, jkt string) (string, error) {
	header := map[string]any{"typ": "JWT", "alg": "ES256", "kid": "issuer-1"}
	claims := map[string]any{
		"iss": s.cfg.Issuer, "aud": "https://" + s.cfg.Domain,
		"exp":        time.Now().Add(5 * time.Minute).Unix(),
		"session_id": sessID, "user_id": userID, "signed_in": signedIn,
		"scope": scope,
		"cnf":   map[string]any{"jkt": jkt},
	}
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(h) + "." + enc.EncodeToString(p)
	sig, err := signES256(s.key, []byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + enc.EncodeToString(sig), nil
}

func randomID() string {
	b := make([]byte, 9)
	readRand(b)
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(b), "=")
}
