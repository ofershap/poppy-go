package poppyjson

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func validDoc() *Document {
	return &Document{
		ProtocolVersion: "1.0",
		Organization:    Organization{Name: "Shop", Domain: "shop.example"},
		Auth: &Auth{
			Issuer: "https://auth.shop.example",
			Scopes: map[string]string{"orders:read": "See your orders"},
		},
		APIs: []API{{Type: "rest", URL: "https://shop.example/orders", Description: "Orders"}},
	}
}

func TestValidateOK(t *testing.T) {
	if err := validDoc().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Document)
	}{
		{"no version", func(d *Document) { d.ProtocolVersion = "" }},
		{"bad version form", func(d *Document) { d.ProtocolVersion = "1" }},
		{"no org name", func(d *Document) { d.Organization.Name = "" }},
		{"bad domain", func(d *Document) { d.Organization.Domain = "not a host" }},
		{"no interface", func(d *Document) { d.APIs = nil }},
		{"issuer not https", func(d *Document) { d.Auth.Issuer = "http://auth.shop.example" }},
		{"api missing description", func(d *Document) { d.APIs[0].Description = "" }},
		{"api url not https", func(d *Document) { d.APIs[0].URL = "http://shop.example/api" }},
		{"bad scope hint", func(d *Document) {
			d.Auth.ScopeHints = map[string]ScopeHint{"x": {Changes: "major"}}
		}},
		{"sign-in disabled but mediated listed", func(d *Document) {
			d.Auth.Disabled = true
			d.Extensions = map[string]any{"mediated-sign-in": map[string]any{}}
		}},
		{"web disabled but endpoint listed", func(d *Document) {
			d.Web = &Web{Disabled: true, BrowserSessionEndpoint: "https://shop.example/join"}
		}},
		{"web disabled without other interface", func(d *Document) {
			d.APIs = nil
			d.Web = &Web{Disabled: true}
		}},
		{"unscoped web without endpoint", func(d *Document) {
			d.Web = &Web{Unscoped: true}
		}},
		{"extension name without domain", func(d *Document) {
			d.Extensions = map[string]any{"gift-wrap": map[string]any{}}
		}},
		{"supported version not https", func(d *Document) {
			d.SupportedVersions = map[string]string{"0.4": "http://shop.example/.well-known/poppy.json"}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := validDoc()
			c.mut(d)
			if err := d.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestDomainExtensionNameOK(t *testing.T) {
	d := validDoc()
	d.Extensions = map[string]any{"shop.example/gift-wrap": map[string]any{}}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestHandlerServesJSON(t *testing.T) {
	h, err := Handler(validDoc(), 300)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", Path, nil))
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=300" {
		t.Fatalf("cache-control %q", cc)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["protocol_version"] != "1.0" {
		t.Fatalf("body %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "TODO") {
		t.Fatal("placeholder in document")
	}
}

func TestHandlerRejectsInvalidDoc(t *testing.T) {
	if _, err := Handler(&Document{}, 0); err == nil {
		t.Fatal("expected validation error")
	}
}
