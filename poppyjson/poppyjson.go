// Package poppyjson builds and serves the discovery document a Company
// publishes at /.well-known/poppy.json under the Personal Agent Protocol
// (Poppy) draft 1.0, spec section 3.
//
// The document tells Personal Agents which interfaces the Company offers
// (APIs, website, company agent), how Sessions and sign-in work, and which
// extensions are supported.
package poppyjson

import (
	"encoding/json"
	"net/http"
)

// Path is the well-known location where the document must be served.
const Path = "/.well-known/poppy.json"

// Document is the poppy.json discovery document (spec 3.1).
type Document struct {
	ProtocolVersion string         `json:"protocol_version"`
	Organization    Organization   `json:"organization"`
	Auth            *Auth          `json:"auth,omitempty"`
	APIs            []API          `json:"apis,omitempty"`
	Agent           *Agent         `json:"agent,omitempty"`
	Web             *Web           `json:"web,omitempty"`
	Extensions      map[string]any `json:"extensions,omitempty"`
}

// Organization identifies the Company (spec 3.1).
type Organization struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
}

// Auth describes how Personal Agents start Sessions and how Users sign in
// (spec 3.2). Required if Agent, APIs, or Web.BrowserSessionEndpoint is set.
type Auth struct {
	// Issuer is the Company's OAuth issuer identifier (HTTPS URL).
	Issuer   string    `json:"issuer"`
	Direct   *SignIn   `json:"direct,omitempty"`
	Device   *SignIn   `json:"device,omitempty"`
	Mediated *Mediated `json:"mediated,omitempty"`
}

// SignIn lists the scopes a sign-in type can grant (spec 4.5, 4.6).
type SignIn struct {
	Scopes map[string]string `json:"scopes"`
}

// Mediated describes Mediated Sign-In, where the Personal Agent sends the
// User's credentials to the Company (spec 4.7).
type Mediated struct {
	Endpoint string            `json:"endpoint"`
	Fields   []Field           `json:"fields"`
	Scopes   map[string]string `json:"scopes"`
}

// Field is one credential field the Company asks for in Mediated Sign-In.
type Field struct {
	Name string `json:"name"`
	Type string `json:"type"` // e.g. "email", "password"
}

// API is one API the Company offers to Personal Agents (spec 3.3).
type API struct {
	Type        string `json:"type"` // e.g. "openapi", "mcp"
	Endpoint    string `json:"endpoint"`
	Description string `json:"description,omitempty"`
	Schema      string `json:"schema,omitempty"` // OpenAPI document URL, for type "openapi"
}

// Agent is the Company Agent a Personal Agent can talk with (spec 3.4).
type Agent struct {
	Protocols []AgentProtocol `json:"protocols"`
}

// AgentProtocol is one conversation protocol the Company Agent speaks.
type AgentProtocol struct {
	Type        string `json:"type"` // "poppy" or an extension type
	Endpoint    string `json:"endpoint"`
	Description string `json:"description,omitempty"`
}

// Web describes how Personal Agents may browse the Company's website
// (spec 3.5, section 5).
type Web struct {
	// BrowserSessionEndpoint is where the Personal Agent's browser joins a
	// Session. Without it, agents browse as ordinary signed-out visitors.
	BrowserSessionEndpoint string `json:"browser_session_endpoint,omitempty"`
	// Scope is the scope required for signed-in browsing, if any.
	Scope string `json:"scope,omitempty"`
}

// Validate checks the spec's MUST-level invariants that are checkable
// statically (spec 3.1-3.5). It returns the first violation found, or nil.
func (d *Document) Validate() error {
	if d.ProtocolVersion == "" {
		return errField("protocol_version", "required")
	}
	if d.Organization.Name == "" {
		return errField("organization.name", "required")
	}
	if d.Organization.Domain == "" {
		return errField("organization.domain", "required")
	}
	needsAuth := d.Agent != nil || len(d.APIs) > 0 ||
		(d.Web != nil && d.Web.BrowserSessionEndpoint != "")
	if needsAuth && d.Auth == nil {
		return errField("auth", "required when agent, apis, or web.browser_session_endpoint is present")
	}
	if d.Auth != nil && d.Auth.Issuer == "" {
		return errField("auth.issuer", "required")
	}
	if d.Auth != nil && d.Auth.Mediated != nil && d.Auth.Mediated.Endpoint == "" {
		return errField("auth.mediated.endpoint", "required")
	}
	return nil
}

type fieldError struct{ field, msg string }

func (e *fieldError) Error() string { return "poppyjson: " + e.field + ": " + e.msg }
func errField(f, m string) error    { return &fieldError{f, m} }

// Handler returns an http.Handler that serves the document as JSON at Path.
// The document is validated once, up front; an invalid document fails fast
// instead of serving a broken discovery file. Responses are cacheable for
// maxAge seconds; pass 0 for no explicit caching.
func Handler(doc *Document, maxAge int) (http.Handler, error) {
	if err := doc.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if maxAge > 0 {
			w.Header().Set("Cache-Control", cacheControl(maxAge))
		}
		w.Write(body)
	}), nil
}

func cacheControl(maxAge int) string {
	return "public, max-age=" + itoa(maxAge)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
