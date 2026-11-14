// Command example-server runs a minimal Poppy company deployment for local
// testing and validator interop. Not a production identity provider.
//
// Environment:
//
//	ISSUER          issuer identifier (default https://localhost:8443)
//	DOMAIN          host[:port] serving poppy.json (default localhost:8443)
//	ADDR            listen address (default :8443)
//	TLS_CERT/TLS_KEY  serve HTTPS with this certificate (required for the
//	                  official validator, which only speaks HTTPS)
//	AGENT_CLIENT_ID and AGENT_JWKS_FILE register a test Personal Agent by
//	                  hand (local testing); without them, agent metadata is
//	                  fetched over HTTPS (production behavior)
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/ofershap/poppy-go/clientassert"
	"github.com/ofershap/poppy-go/exampleserver"
)

func main() {
	fetcher := clientassert.Fetcher(clientassert.NewClient())
	if id, file := os.Getenv("AGENT_CLIENT_ID"), os.Getenv("AGENT_JWKS_FILE"); id != "" && file != "" {
		raw, err := os.ReadFile(file)
		if err != nil {
			log.Fatal(err)
		}
		var jwks clientassert.JWKS
		if err := json.Unmarshal(raw, &jwks); err != nil {
			log.Fatal(err)
		}
		fetcher = exampleserver.NewStaticAgentFetcher(id, &jwks)
		log.Printf("registered test Personal Agent %s from %s", id, file)
	}
	s, err := exampleserver.New(exampleserver.Config{
		Issuer:       env("ISSUER", "https://localhost:8443"),
		Domain:       env("DOMAIN", "localhost:8443"),
		Name:         "Example Store",
		AgentFetcher: fetcher,
	})
	if err != nil {
		log.Fatal(err)
	}
	addr := env("ADDR", ":8443")
	cert, key := os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY")
	if cert != "" && key != "" {
		log.Printf("example Poppy company on https://%s", addr)
		log.Fatal(http.ListenAndServeTLS(addr, cert, key, s))
	}
	log.Printf("example Poppy company on http://%s (set TLS_CERT/TLS_KEY for HTTPS)", addr)
	log.Fatal(http.ListenAndServe(addr, s))
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
