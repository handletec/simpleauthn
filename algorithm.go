package simpleauthn

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/svicknesh/key/v2"
	"github.com/svicknesh/key/v2/shared"
)

type Algorithm uint8

const (
	Unknown Algorithm = iota
	ED25519           // uses public private key
	ES256             // uses public private key
	ES384             // uses public private key
	ES512             // uses public private key
	HS256             // uses symetric key
	HS384             // uses symetric key
	HS512             // uses symetric key
)

// Alg - return algorithm type
func (ta Algorithm) Alg() (alg jwa.KeyAlgorithm, err error) {

	switch ta {
	case ED25519:
		alg = jwa.EdDSA()
	case ES256:
		alg = jwa.ES256()
	case ES384:
		alg = jwa.ES384()
	case ES512:
		alg = jwa.ES512()
	case HS256:
		alg = jwa.HS256()
	case HS384:
		alg = jwa.HS384()
	case HS512:
		alg = jwa.HS512()
	default:
		err = fmt.Errorf("alg: unknown signer algorithm")
	}

	return alg, err
}

func (ta Algorithm) String() (str string) {
	taStr := []string{"unknown", "ED25519", "ES256", "ES384", "ES512", "HS256", "HS384", "HS512"}
	taInt := int(ta)
	if taInt > len(taStr) {
		taInt = int(Unknown)
	}

	return taStr[taInt]
}

// AlgForKey - returns recommended algorithm for given key, useful when we don't know what key we are getting
func AlgForKey(inputKey string) (alg Algorithm) {

	// lets try to parse it as a public/private key
	j, err := key.NewKeyFromBytes([]byte(inputKey))
	if nil != err {
		// if its not a public/private key, or an error is encountered, treat it as a symetric key
		return HS256 // default use HMAC with SHA-256, still good enough
	}

	switch j.KeyType() {
	case shared.ED25519:
		return ED25519
	case shared.ECDSA256:
		return ES256
	case shared.ECDSA384:
		return ES384
	case shared.ECDSA521:
		return ES512
	}

	// if its not a public/private key, or an error is encountered, treat it as a symetric key
	return HS256 // default use HMAC with SHA-256, still good enough
}
