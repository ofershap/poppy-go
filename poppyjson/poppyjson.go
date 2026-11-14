// Package poppyjson builds and serves the discovery document a Company
// publishes at /.well-known/poppy.json under the Personal Agent Protocol
// (Poppy) draft 1.0, spec section 3.
//
// The document tells Personal Agents which interfaces the Company offers
// (APIs, website, company agent), which issuer identifies the Company, and
// which protocol versions and extensions it speaks.
package poppyjson

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

// Path is the well-known location where the document must be served.
const Path = "/.well-known/poppy.json"

// Document is the poppy.json discovery document (spec 3, 3.1).
type Document struct {
	// ProtocolVersion is the protocol version the document describes, such
	// as "1.0".
	ProtocolVersion string `json:"protocol_version"`
	// SupportedVersions maps other versions the Company serves to the HTTPS
	// URL of each version's document, on the same host (spec 3.4).
	SupportedVersions map[string]string `json:"supported_versions,omitempty"`
	Organization      Organization      `json:"organization"`
	Auth              *Auth             `json:"auth,omitempty"`
	Agent             *Agent            `json:"agent,omitempty"`
	APIs              []API             `json:"apis,omitempty"`
	Web               *Web              `json:"web,omitempty"`
	Extensions        map[string]any    `json:"extensions,omitempty"`
}

// Organization identifies the Company (spec 3.1). Domain is the host that
// serves the document, with its port when that isn't 443.
type Organization struct {
	Name    string `json:"name"`
	Domain  string `json:"domain"`
	LogoURI string `json:"logo_uri,omitempty"`
}

// Auth describes the Company's OAuth issuer and the scopes sign-in can
// grant (spec 3.1, 3.2).
type Auth struct {
	// Issuer is the Company's OAuth issuer identifier (HTTPS URL). Required
	// when the Company offers sign-in; when several authorization servers
	// are listed it names the one Personal Agents use.
	Issuer string `json:"issuer,omitempty"`
	// Disabled is true when the Company offers Personal Agents no sign-in.
	Disabled bool `json:"disabled,omitempty"`
	// Scopes describes each scope sign-in can grant, keyed by scope name.
	Scopes map[string]string `json:"scopes,omitempty"`
	// ScopeHints describes the most consequential operation each scope
	// enables (spec 4.7).
	ScopeHints map[string]ScopeHint `json:"scope_hints,omitempty"`
}

// ScopeHint is the hint for one scope (spec 4.7).
type ScopeHint struct {
	// Changes is "none", "reversible", or "irreversible".
	Changes string `json:"changes"`
	// PersonalData is true when the scope exposes personal data.
	PersonalData bool `json:"personal_data"`
}

// API is one API the Company offers to Personal Agents (spec 3.1, 7).
type API struct {
	Type        string `json:"type"` // e.g. "openapi", "mcp"
	URL         string `json:"url"`
	Description string `json:"description"`
}

// Agent is the Company Agent a Personal Agent can talk with (spec 8).
type Agent struct {
	Protocols []AgentProtocol `json:"protocols"`
}

// AgentProtocol is one conversation protocol the Company Agent speaks.
type AgentProtocol struct {
	Type        string `json:"type"` // "poppy" or an extension type
	Endpoint    string `json:"endpoint"`
	Description string `json:"description"`
}

// Web describes how Personal Agents may browse the Company's website
// (spec 6).
type Web struct {
	// BrowserSessionEndpoint is where a browser joins a Session.
	BrowserSessionEndpoint string `json:"browser_session_endpoint,omitempty"`
	// Disabled asks Personal Agents not to browse the website.
	Disabled bool `json:"disabled,omitempty"`
	// Unscoped means the website doesn't apply the Company's other scopes.
	Unscoped bool `json:"unscoped,omitempty"`
}

var (
	versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)
	domainPattern  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*(:[1-9][0-9]{0,4})?$`)
	httpsPattern   = regexp.MustCompile(`^https://[^\s/?#]+`)
	// Extensions the protocol defines; anyone else starts an extension's
	// name with a domain they control (spec 3.3).
	knownExtensions = map[string]bool{
		"mediated-sign-in": true,
		"disclosures":      true,
		"links":            true,
		"ucp":              true,
		"browser-control":  true,
		"operations":       true,
	}
)

// Validate checks the spec's MUST-level invariants that are checkable
// statically (spec 3.1-3.4). It returns the first violation found, or nil.
func (d *Document) Validate() error {
	if !versionPattern.MatchString(d.ProtocolVersion) {
		return errField("protocol_version", "required, in the form 1.0")
	}
	for v, u := range d.SupportedVersions {
		if !versionPattern.MatchString(v) {
			return errField("supported_versions", "version keys must be in the form 1.0")
		}
		if !httpsPattern.MatchString(u) {
			return errField("supported_versions["+v+"]", "must be an HTTPS URL")
		}
	}
	if d.Organization.Name == "" {
		return errField("organization.name", "required")
	}
	if !domainPattern.MatchString(d.Organization.Domain) {
		return errField("organization.domain", "required, a host with optional port")
	}
	if d.Organization.LogoURI != "" && !httpsPattern.MatchString(d.Organization.LogoURI) {
		return errField("organization.logo_uri", "must be an HTTPS URL")
	}
	if d.Agent == nil && len(d.APIs) == 0 && d.Web == nil {
		return errField("", "at least one of agent, apis, or web is required")
	}
	if d.Auth != nil {
		if d.Auth.Issuer != "" && !httpsPattern.MatchString(d.Auth.Issuer) {
			return errField("auth.issuer", "must be an HTTPS URL")
		}
		if d.Auth.Disabled {
			if _, ok := d.Extensions["mediated-sign-in"]; ok {
				return errField("auth.disabled", "a Company that turns off sign-in lists no way to sign in")
			}
		}
		for scope, hint := range d.Auth.ScopeHints {
			switch hint.Changes {
			case "none", "reversible", "irreversible":
			default:
				return errField("auth.scope_hints["+scope+"].changes", "must be none, reversible, or irreversible")
			}
		}
	}
	for i, a := range d.APIs {
		if a.Type == "" || a.URL == "" || a.Description == "" {
			return errField("apis", "each API needs type, url, and description")
		}
		if !httpsPattern.MatchString(a.URL) {
			return errField("apis", "each API url must be an HTTPS URL")
		}
		_ = i
	}
	if d.Agent != nil {
		if len(d.Agent.Protocols) == 0 {
			return errField("agent.protocols", "at least one protocol is required")
		}
		for _, p := range d.Agent.Protocols {
			if p.Type == "" || p.Endpoint == "" || p.Description == "" {
				return errField("agent.protocols", "each protocol needs type, endpoint, and description")
			}
			if !httpsPattern.MatchString(p.Endpoint) {
				return errField("agent.protocols", "each endpoint must be an HTTPS URL")
			}
		}
	}
	if d.Web != nil {
		if d.Web.BrowserSessionEndpoint != "" && !httpsPattern.MatchString(d.Web.BrowserSessionEndpoint) {
			return errField("web.browser_session_endpoint", "must be an HTTPS URL")
		}
		if d.Web.Disabled {
			if d.Web.BrowserSessionEndpoint != "" {
				return errField("web.disabled", "a Company that asks agents not to browse lists no browser-session endpoint")
			}
			if d.Agent == nil && len(d.APIs) == 0 {
				return errField("web.disabled", "a Company that asks agents not to browse must list agent or apis")
			}
		}
		if d.Web.Unscoped && d.Web.BrowserSessionEndpoint == "" {
			return errField("web.unscoped", "a Company whose website is unscoped lists a browser-session endpoint")
		}
	}
	for name := range d.Extensions {
		if !knownExtensions[name] && !extensionNameOK(name) {
			return errField("extensions", "extension names are ones the protocol defines, or start with a domain, such as example.com/gift-wrap")
		}
	}
	return nil
}

// extensionNameOK reports whether name starts with a domain: host/name.
func extensionNameOK(name string) bool {
	i := strings.Index(name, "/")
	return i > 1 && domainPattern.MatchString(name[:i]) && len(name) > i+1
}

type fieldError struct{ field, msg string }

func (e *fieldError) Error() string {
	if e.field == "" {
		return "poppyjson: " + e.msg
	}
	return "poppyjson: " + e.field + ": " + e.msg
}
func errField(f, m string) error { return &fieldError{f, m} }

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
