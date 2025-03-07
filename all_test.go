package simpleauthn_test

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/handletec/simpleauthn"
	"github.com/svicknesh/key/v2"
)

type Claim struct {
	*simpleauthn.Claim        // import default claims
	Role               string `json:"role"`
}

func (r *Claim) String() (str string) {
	bytes, _ := json.Marshal(r)
	return string(bytes)
}

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

	r := new(Claim)
	r.Claim = simpleauthn.NewClaim(time.Duration(time.Second * 120)) // fill claims with default values
	r.Role = "superduperman-hs256"
	//fmt.Println(r)

	requestStr, err := simpleauthn.NewRequest(keyInput, r)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}
	fmt.Println(requestStr)

	r2 := new(Claim)
	err = host.Verify(requestStr, r2)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	fmt.Println(r2)

}

func TestAlgForKey(t *testing.T) {

	k, err := key.GenerateKey(key.ED25519)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	alg := simpleauthn.AlgForKey(k.String())
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

	r := new(Claim)
	r.Claim = simpleauthn.NewClaim(time.Duration(time.Second * 120)) // fill claims with default values
	r.Role = "superduperman-ed25519"
	//fmt.Println(r)

	// create a new signer using the private key for Ed25519
	requestStr, err := simpleauthn.NewRequest(keyPrivate, r)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}
	fmt.Println(requestStr)

	r2 := new(Claim)
	err = host.Verify(requestStr, r2)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	fmt.Println(r2)
	fmt.Println(r2.Role)

}
