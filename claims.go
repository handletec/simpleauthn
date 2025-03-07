package simpleauthn

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jws"
)

// Claim - claim structure
type Claim struct {
	IssuedAt  int64 `json:"iat"`           // some apps can use the iat to determine when to expire the token, the app has a lifetime limit
	NotBefore int64 `json:"nbf,omitempty"` // indicate when this token is usable
	Expiry    int64 `json:"exp,omitempty"` // some apps will use expiry to determine when to expire, useful when we want long lived token
}

// NewClaim - create new instance of claim with default values set
func NewClaim(expiryDuration time.Duration) (claim *Claim) {

	t := time.Now().UTC()

	claim = new(Claim)
	claim.IssuedAt = t.Unix()
	claim.NotBefore = claim.IssuedAt            // by default the claim cannot be used before the issued time
	claim.Expiry = t.Add(expiryDuration).Unix() // add the given expiry duration to set the token expiry

	return
}

// NewRequest - create new instance of authorization JWT
func NewRequest(k *Key, payload any) (token string, err error) {

	if nil == k {
		return "", fmt.Errorf("newrequest: key cannot be nil")
	}

	// we need the private key to create the signature
	if !k.isPrivate {
		return "", fmt.Errorf("newrequest: expected private key for creating signature, none found")
	}

	bytes, _ := json.Marshal(payload)
	signBytes, err := jws.Sign(bytes, jws.WithKey(k.alg, k.k))
	if nil != err {
		return "", fmt.Errorf("newrequest: sign -> %w", err)
	}

	return string(signBytes), nil
}

func (claim *Claim) String() (str string) {
	bytes, _ := json.Marshal(claim)
	return string(bytes)
}
