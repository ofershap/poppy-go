package exampleserver

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
)

func signES256(key *ecdsa.PrivateKey, input []byte) ([]byte, error) {
	digest := sha256.Sum256(input)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	rb, sb := r.Bytes(), s.Bytes()
	copy(out[32-len(rb):32], rb)
	copy(out[64-len(sb):], sb)
	return out, nil
}

func readRand(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
}
