package simpleauthn

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/svicknesh/key/v2"
	"golang.org/x/crypto/blake2b"
)

// Key - creates new instance of key with the preferred algorithm
type Key struct {
	alg                 jwa.KeyAlgorithm
	k                   jwk.Key
	isPrivate, isPublic bool
}

// NewKey - creates instance of key, which can be a string or ECDSA public/private keys in JWK format
func NewKey(alg Algorithm, inputKey string) (k *Key, err error) {

	if len(inputKey) == 0 {
		return nil, fmt.Errorf("newkey: input key cannot be empty")
	}

	k = new(Key)

	var input any
	inputBytes := []byte(inputKey)

	switch alg {
	case ED25519, ES256, ES384, ES512:
		// public/private key usage
		j, err := key.NewKeyFromBytes(inputBytes)
		if nil != err {
			return nil, fmt.Errorf("newkey: %w", err)
		}

		if j.IsPrivateKey() {
			input = j.PrivateKeyInstance()
			k.isPrivate = true
		} else if j.IsPublicKey() {
			input = j.PublicKeyInstance()
			k.isPublic = true
		} else {
			return nil, fmt.Errorf("newkey: no ED25519 or ECDSA public or private key instance found")
		}

	case HS256, HS384, HS512:
		// shared symetric key
		h := blake2b.Sum256(inputBytes) // we convert the input key to a hash value, allows us to use phrases as well
		input = h[:]
		k.isPrivate = true // for symetric keys, it is the same key for signing and verifying
		k.isPublic = true  // for symetric keys, it is the same key for signing and verifying
	default:
		return nil, fmt.Errorf("newkey: unsupported algorithm given")
	}

	k.k, err = jwk.Import(input)
	if nil != err {
		return nil, fmt.Errorf("newkey: %w", err)
	}

	k.alg, _ = alg.Alg() // keep a copy of the algorithm for signing and verification

	return
}
