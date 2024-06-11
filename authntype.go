package simpleauthn

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
)

type Algorithm uint8

const (
	AlgUnknown Algorithm = iota
	AlgES256             // uses public private key
	AlgES384             // uses public private key
	AlgES512             // uses public private key
	AlgHS256             // uses symetric key
	AlgHS384             // uses symetric key
	AlgHS512             // uses symetric key
)

// Alg - return algorithm type
func (ta Algorithm) Alg() (alg jwa.KeyAlgorithm, err error) {

	switch ta {
	case AlgES256:
		alg = jwa.ES256
	case AlgES384:
		alg = jwa.ES384
	case AlgES512:
		alg = jwa.ES512
	case AlgHS256:
		alg = jwa.HS256
	case AlgHS384:
		alg = jwa.HS384
	case AlgHS512:
		alg = jwa.HS512
	default:
		err = fmt.Errorf("alg: unknown signer algorithm")
	}

	return alg, err
}

func (ta Algorithm) String() (str string) {
	taStr := []string{"unknown", "ES256", "ES384", "ES512", "HS256", "HS384", "HS512"}
	taInt := int(ta)
	if taInt > len(taStr) {
		taInt = int(AlgUnknown)
	}

	return taStr[taInt]
}
