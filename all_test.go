package simpleauthn_test

import (
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/handletec/simpleauthn"
	"github.com/svicknesh/key/v2"
)

func TestAuth(t *testing.T) {

	keyInput, err := simpleauthn.NewKey(simpleauthn.HS256, "super-secret-key") // create a key using symetric keys (shared secret)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	host, err := simpleauthn.NewHost(keyInput, 30)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	//requestStr, err := simpleauthn.NewRequest(keyInput, &simpleauthn.Optional{NotBefore: time.Now().UTC().Unix() + 100})
	requestStr, err := simpleauthn.NewRequest(keyInput, &simpleauthn.Optional{
		NotBefore: time.Now().UTC().Unix(),
		Expiry:    time.Now().UTC().Unix() + 100,
		Issuer:    "301:11.8888/USER/ABCD",
		Payload:   "anything i want",
	})
	//requestStr, err := simpleauthn.NewRequest(keyInput, nil)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}
	fmt.Println(requestStr)

	request, err := host.Verify(requestStr)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	fmt.Println(request)

}

func TestAlgForKey(t *testing.T) {

	k, err := key.GenerateKey(key.ED25519)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	alg, err := simpleauthn.AlgForKey(k.String())
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}
	fmt.Println(alg)

}

func TestKeys(t *testing.T) {

	// generate an Ed25519 key for testing
	k, err := key.GenerateKey(key.ED25519)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	// create instance of ED25519 from private key for `simpleauthn`
	keyPrivate, err := simpleauthn.NewKey(simpleauthn.ED25519, k.String())
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	// get the public key for ED25519 from the private key
	pubKey, err := k.PublicKey()
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	// create instance of ED25519 from public key for `simpleauthn`
	keyPublic, err := simpleauthn.NewKey(simpleauthn.ED25519, pubKey.String())
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	// create a new verifier using the public key for Ed25519
	host, err := simpleauthn.NewHost(keyPublic, 30)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	// create a new signer using the private key for Ed25519
	//requestStr, err := simpleauthn.NewRequest(key, &simpleauthn.Optional{NotBefore: time.Now().UTC().Unix() + 100})
	requestStr, err := simpleauthn.NewRequest(keyPrivate, nil)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}
	fmt.Println(requestStr)

	request, err := host.Verify(requestStr)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	fmt.Println(request)

}
