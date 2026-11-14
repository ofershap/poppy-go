// Command example-server runs a minimal Poppy company deployment for local
// testing and validator interop. Not a production identity provider.
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/ofershap/poppy-go/clientassert"
	"github.com/ofershap/poppy-go/exampleserver"
)

func main() {
	issuer := env("ISSUER", "http://localhost:8080")
	domain := env("DOMAIN", "localhost:8080")
	s, err := exampleserver.New(exampleserver.Config{
		Issuer:       issuer,
		Domain:       domain,
		Name:         "Example Store",
		AgentFetcher: clientassert.NewClient(),
	})
	if err != nil {
		log.Fatal(err)
	}
	addr := env("ADDR", ":8080")
	log.Printf("example Poppy company on %s (issuer %s)", addr, issuer)
	log.Fatal(http.ListenAndServe(addr, s))
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
