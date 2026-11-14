// Package jose holds the small JOSE helpers poppy-go's packages share:
// compact-JWT parsing, ES256 and PS384 verification, ES256 and PS384
// signing (used by tests and examples), and RFC 7638 JWK thumbprints.
//
// It is internal: the public API of poppy-go is the poppyjson,
// clientassert and session packages.
package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// B64 is the base64url-without-padding encoding JOSE uses.
var B64 = base64.RawURLEncoding

// Compact is a parsed compact-serialized JWT.
type Compact struct {
	HeaderRaw  []byte
	PayloadRaw []byte
	Input      string // header.payload, the bytes a signature covers
	Signature  []byte
}

// Header is the part of a JOSE header poppy-go reads. Unknown members are
// ignored.
type Header struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	DLG string `json:"poppy_dlg"`
}

// ParseCompact splits and decodes a compact JWT without trusting it.
func ParseCompact(token string) (*Compact, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return nil, errors.New("jose: not a compact JWT")
	}
	header, err := B64.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jose: header encoding: %w", err)
	}
	payload, err := B64.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jose: payload encoding: %w", err)
	}
	sig, err := B64.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("jose: signature encoding: %w", err)
	}
	return &Compact{
		HeaderRaw:  header,
		PayloadRaw: payload,
		Input:      parts[0] + "." + parts[1],
		Signature:  sig,
	}, nil
}

// ParseHeader decodes a JWT header's common fields.
func ParseHeader(raw []byte) (*Header, error) {
	var h Header
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("jose: header JSON: %w", err)
	}
	return &h, nil
}

// ECKeyFromJWK builds an ECDSA public key from a P-256 JWK's x and y.
func ECKeyFromJWK(x, y string) (*ecdsa.PublicKey, error) {
	xb, err := B64.DecodeString(x)
	if err != nil {
		return nil, fmt.Errorf("jose: jwk x: %w", err)
	}
	yb, err := B64.DecodeString(y)
	if err != nil {
		return nil, fmt.Errorf("jose: jwk y: %w", err)
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("jose: EC point not on P-256")
	}
	return pub, nil
}

// RSAKeyFromJWK builds an RSA public key from a JWK's n and e.
func RSAKeyFromJWK(n, e string) (*rsa.PublicKey, error) {
	nb, err := B64.DecodeString(n)
	if err != nil {
		return nil, fmt.Errorf("jose: jwk n: %w", err)
	}
	eb, err := B64.DecodeString(e)
	if err != nil {
		return nil, fmt.Errorf("jose: jwk e: %w", err)
	}
	eInt := new(big.Int).SetBytes(eb)
	if !eInt.IsInt64() || eInt.Int64() < 3 {
		return nil, errors.New("jose: bad RSA exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(eInt.Int64())}, nil
}

// VerifyES256 checks an ES256 signature (RFC 7518): raw R||S over SHA-256.
func VerifyES256(pub *ecdsa.PublicKey, input string, sig []byte) error {
	if len(sig) != 64 {
		return errors.New("jose: ES256 signature must be 64 bytes")
	}
	digest := sha256.Sum256([]byte(input))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return errors.New("jose: ES256 signature invalid")
	}
	return nil
}

// VerifyPS384 checks a PS384 signature (RFC 7518): RSA-PSS over SHA-384
// with the salt length equal to the hash size.
func VerifyPS384(pub *rsa.PublicKey, input string, sig []byte) error {
	digest := sha512.Sum384([]byte(input))
	err := rsa.VerifyPSS(pub, crypto.SHA384, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return errors.New("jose: PS384 signature invalid")
	}
	return nil
}

// ThumbprintEC returns the RFC 7638 SHA-256 thumbprint of a P-256 JWK.
func ThumbprintEC(x, y string) string {
	canonical := `{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return B64.EncodeToString(sum[:])
}

// ThumbprintRSA returns the RFC 7638 SHA-256 thumbprint of an RSA JWK.
func ThumbprintRSA(n, e string) string {
	canonical := `{"e":"` + e + `","kty":"RSA","n":"` + n + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return B64.EncodeToString(sum[:])
}

// SignES256 signs header and payload with an ECDSA P-256 key, compact form.
// Tests and examples use it; verifying companies only verify.
func SignES256(priv *ecdsa.PrivateKey, header, payload any) (string, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	input := B64.EncodeToString(hb) + "." + B64.EncodeToString(pb)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + B64.EncodeToString(sig), nil
}

// SignPS384 signs header and payload with an RSA key using PS384, compact
// form. Tests and examples use it; verifying companies only verify.
func SignPS384(priv *rsa.PrivateKey, header, payload any) (string, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	input := B64.EncodeToString(hb) + "." + B64.EncodeToString(pb)
	digest := sha512.Sum384([]byte(input))
	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA384, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return "", err
	}
	return input + "." + B64.EncodeToString(sig), nil
}

// GenerateEC makes a fresh P-256 key pair (tests and examples).
func GenerateEC() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// GenerateRSA makes a fresh 2048-bit RSA key pair (tests and examples).
func GenerateRSA() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// ECJWK returns the public JWK members for an ECDSA P-256 key.
func ECJWK(priv *ecdsa.PrivateKey) (x, y string) {
	// JWK requires fixed-width 32-byte coordinates.
	xb := priv.PublicKey.X.Bytes()
	yb := priv.PublicKey.Y.Bytes()
	fx := make([]byte, 32)
	fy := make([]byte, 32)
	copy(fx[32-len(xb):], xb)
	copy(fy[32-len(yb):], yb)
	return B64.EncodeToString(fx), B64.EncodeToString(fy)
}

// RSAJWK returns the public JWK members for an RSA key.
func RSAJWK(priv *rsa.PrivateKey) (n, e string) {
	return B64.EncodeToString(priv.PublicKey.N.Bytes()),
		B64.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes())
}
