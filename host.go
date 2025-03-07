package simpleauthn

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
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
func (host *Host) Verify(requestStr string, output any) (err error) {

	bytes, err := jws.Verify([]byte(requestStr), jws.WithKey(host.key.alg, host.key.k))
	if nil != err {
		return fmt.Errorf("verify: request -> %w", err)
	}

	claim := new(Claim)
	err = json.Unmarshal(bytes, claim)
	if nil != err {
		return fmt.Errorf("verify: unmarshal -> %w", err)
	}

	if claim.IssuedAt == 0 {
		return fmt.Errorf("verify: missing issued at")
	}

	now := time.Now().UTC()
	nowUnix := now.Unix()

	diff := claim.IssuedAt - nowUnix + host.validity
	if !(diff >= 0 && diff <= host.validity) {
		return fmt.Errorf("verify: authorization exceeds validity period")
	}

	// check optional fields
	// if the not before value is set, the value must not exceed current time
	if claim.NotBefore != 0 && claim.NotBefore > nowUnix {
		return fmt.Errorf("verify: authorization request (nbf) is in the future")
	}

	// other optional fields such as issuer and payload will be dealt with the caller as they see fit

	// we split the JWS into its constituent parts and return the base64 decoded middle part, split[1]
	split := strings.Split(requestStr, ".")
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(split[1])
	return json.Unmarshal(payloadBytes, output)
}
