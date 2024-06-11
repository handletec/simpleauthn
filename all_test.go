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

	keyInput, err := simpleauthn.NewKey(simpleauthn.AlgHS256, "super-secret-key") // create a key using symetric keys (shared secret)
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

func TestKeys(t *testing.T) {

	k, err := key.GenerateKey(key.ECDSA256)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	keyPrivate, err := simpleauthn.NewKey(simpleauthn.AlgES256, k.String())
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	pubKey, err := k.PublicKey()
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	keyPublic, err := simpleauthn.NewKey(simpleauthn.AlgES256, pubKey.String())
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	host, err := simpleauthn.NewHost(keyPublic, 30)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

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
