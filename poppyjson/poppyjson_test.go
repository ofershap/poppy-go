package poppyjson

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func validDoc() *Document {
	return &Document{
		ProtocolVersion: "1.0",
		Organization:    Organization{Name: "Example Store", Domain: "example.com"},
		Auth: &Auth{
			Issuer: "https://auth.example.com",
			Direct: &SignIn{Scopes: map[string]string{"orders:read": "See your orders"}},
		},
		APIs: []API{{Type: "openapi", Endpoint: "https://api.example.com", Schema: "https://api.example.com/openapi.json"}},
	}
}

func TestValidate(t *testing.T) {
	if err := validDoc().Validate(); err != nil {
		t.Fatalf("valid doc rejected: %v", err)
	}
	d := validDoc()
	d.Auth = nil
	if err := d.Validate(); err == nil {
		t.Fatal("auth must be required when apis are present")
	}
	// No interfaces at all: auth may be absent (browsable website only).
	d = &Document{ProtocolVersion: "1.0", Organization: Organization{Name: "X", Domain: "x.com"}}
	if err := d.Validate(); err != nil {
		t.Fatalf("website-only doc must not require auth: %v", err)
	}
	d2 := validDoc()
	d2.Organization.Domain = ""
	if err := d2.Validate(); err == nil {
		t.Fatal("organization.domain required")
	}
}

func TestHandler(t *testing.T) {
	h, err := Handler(validDoc(), 3600)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", Path, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=3600" {
		t.Fatalf("cache-control %q", cc)
	}
	var got Document
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body not valid JSON: %v", err)
	}
	if got.Organization.Domain != "example.com" || got.Auth.Issuer != "https://auth.example.com" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}

	if _, err := Handler(&Document{}, 0); err == nil {
		t.Fatal("invalid document must fail at Handler construction, not at request time")
	}
}
