package simpleauthn

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jws"
)

// AuthnRequest - authorization request token
type AuthnRequest struct {
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf,omitempty"`
	Expiry    int64  `json:"exp,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	Payload   any    `json:"payload,omitempty"`
}

// Optional - optional parameters for the authorization JWS
type Optional struct {
	NotBefore int64
	Expiry    int64
	Issuer    string
	Payload   any
}

/*
// NewOptional - create instance of Optional
func NewOptional() (optional *Optional) {
	optional = new(Optional)
	return
}
*/

// NewRequest - create new instance of authentication request token
func NewRequest(k *Key, optional *Optional) (authRequestStr string, err error) {

	if nil == k {
		return "", fmt.Errorf("newrequest: key cannot be nil")
	}

	// we need the private key to create the signature
	if !k.isPrivate {
		return "", fmt.Errorf("newrequest: expected private key for creating signature, none found")
	}

	authnRequest := new(AuthnRequest)
	authnRequest.IssuedAt = time.Now().UTC().Unix()

	// these are optional
	if nil != optional {
		authnRequest.NotBefore = optional.NotBefore
		authnRequest.Expiry = optional.Expiry
		authnRequest.Issuer = optional.Issuer
		authnRequest.Payload = optional.Payload
	}

	bytes, _ := json.Marshal(authnRequest)

	buf, err := jws.Sign(bytes, jws.WithKey(k.alg, k.k))
	if nil != err {
		return "", fmt.Errorf("newrequest: sign -> %w", err)
	}

	return string(buf), nil
}

func (authnRequest AuthnRequest) String() (str string) {
	bytes, _ := json.Marshal(authnRequest)
	return string(bytes)
}
