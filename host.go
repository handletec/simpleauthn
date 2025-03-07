package simpleauthn

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jws"
)

// Host - host level authenticating requests
type Host struct {
	key      *Key
	validity int64
	//alg      jwa.KeyAlgorithm
}

// NewHost - create new instance for host to perform authentication requests
func NewHost(k *Key, validity int64) (host *Host, err error) {

	if nil == k {
		return nil, fmt.Errorf("newhost: key cannot be nil")
	}

	// we need the public key to verify the signature
	if !k.isPublic {
		return nil, fmt.Errorf("newhost: expected public key for verifying signature, none found")
	}

	host = new(Host)
	host.key = k
	host.validity = validity

	return
}

// Verify - verifies the given request string
func (host *Host) Verify(requestStr string) (authRequest *AuthnRequest, err error) {

	buf, err := jws.Verify([]byte(requestStr), jws.WithKey(host.key.alg, host.key.k))
	if nil != err {
		return nil, fmt.Errorf("verify: request -> %w", err)
	}

	authRequest = new(AuthnRequest)
	err = json.Unmarshal(buf, authRequest)
	if nil != err {
		return nil, fmt.Errorf("verify: unmarshal -> %w", err)
	}

	if authRequest.IssuedAt == 0 {
		return nil, fmt.Errorf("verify: missing issued at")
	}

	now := time.Now().UTC()
	nowUnix := now.Unix()

	diff := authRequest.IssuedAt - nowUnix + host.validity
	if !(diff >= 0 && diff <= host.validity) {
		return nil, fmt.Errorf("verify: authorization exceeds validity period")
	}

	// check optional fields

	// if the not before value is set, the value must not exceed current time
	if authRequest.NotBefore != 0 && authRequest.NotBefore > nowUnix {
		return nil, fmt.Errorf("verify: authorization request (nbf) is in the future")
	}

	// other optional fields such as issuer and payload will be dealt with the caller as they see fit

	return
}
