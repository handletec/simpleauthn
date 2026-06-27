package simpleauthn_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/handletec/simpleauthn"
	"github.com/svicknesh/key/v2"
	"github.com/svicknesh/key/v2/shared"
)

// testPayload embeds the standard Claim and adds an application field.
type testPayload struct {
	*simpleauthn.Claim
	Role string `json:"role"`
}

func (p *testPayload) String() string {
	b, _ := json.Marshal(p)
	return string(b)
}

// ── Algorithm.String ─────────────────────────────────────────────────────────

func TestAlgorithmStringKnown(t *testing.T) {
	cases := []struct {
		alg  simpleauthn.Algorithm
		want string
	}{
		{simpleauthn.Unknown, "unknown"},
		{simpleauthn.ED25519, "ED25519"},
		{simpleauthn.ES256, "ES256"},
		{simpleauthn.ES384, "ES384"},
		{simpleauthn.ES512, "ES512"},
		{simpleauthn.HS256, "HS256"},
		{simpleauthn.HS384, "HS384"},
		{simpleauthn.HS512, "HS512"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.alg.String(); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAlgorithmStringOutOfRange(t *testing.T) {
	// Values past HS512 (index 7) must return "unknown" and must not panic.
	for _, v := range []simpleauthn.Algorithm{8, 9, 100, 255} {
		v := v
		t.Run(fmt.Sprintf("alg-%d", v), func(t *testing.T) {
			got := v.String()
			if got != "unknown" {
				t.Errorf("Algorithm(%d).String() = %q, want %q", v, got, "unknown")
			}
		})
	}
}

// ── Algorithm.Alg ────────────────────────────────────────────────────────────

func TestAlgDefinedAlgorithmsReturnNoError(t *testing.T) {
	defined := []simpleauthn.Algorithm{
		simpleauthn.ED25519,
		simpleauthn.ES256, simpleauthn.ES384, simpleauthn.ES512,
		simpleauthn.HS256, simpleauthn.HS384, simpleauthn.HS512,
	}
	for _, alg := range defined {
		t.Run(alg.String(), func(t *testing.T) {
			if _, err := alg.Alg(); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestAlgUnknownReturnsError(t *testing.T) {
	if _, err := simpleauthn.Unknown.Alg(); err == nil {
		t.Error("Unknown.Alg() should return an error")
	}
}

// ── AlgForKey ────────────────────────────────────────────────────────────────

func TestAlgForKeyED25519(t *testing.T) {
	k, err := key.GenerateKey(key.ED25519)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("private", func(t *testing.T) {
		if got := simpleauthn.AlgForKey(k.String()); got != simpleauthn.ED25519 {
			t.Errorf("got %s, want ED25519", got)
		}
	})
	pub, err := k.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("public", func(t *testing.T) {
		if got := simpleauthn.AlgForKey(pub.String()); got != simpleauthn.ED25519 {
			t.Errorf("got %s, want ED25519", got)
		}
	})
}

func TestAlgForKeyECDSA(t *testing.T) {
	cases := []struct {
		keyType shared.KeyType
		want    simpleauthn.Algorithm
	}{
		{key.ECDSA256, simpleauthn.ES256},
		{key.ECDSA384, simpleauthn.ES384},
		{key.ECDSA521, simpleauthn.ES512},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.want.String(), func(t *testing.T) {
			k, err := key.GenerateKey(tc.keyType)
			if err != nil {
				t.Fatal(err)
			}
			if got := simpleauthn.AlgForKey(k.String()); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestAlgForKeyFallsBackToHS256(t *testing.T) {
	for _, input := range []string{"passphrase", "not-a-jwk", "random string"} {
		if got := simpleauthn.AlgForKey(input); got != simpleauthn.HS256 {
			t.Errorf("AlgForKey(%q) = %s, want HS256", input, got)
		}
	}
}

// ── NewKey ───────────────────────────────────────────────────────────────────

func TestNewKeyRejectsEmptyInput(t *testing.T) {
	if _, err := simpleauthn.NewKey(simpleauthn.HS256, ""); err == nil {
		t.Error("expected error for empty input")
	}
}

func TestNewKeyRejectsUnknownAlgorithm(t *testing.T) {
	if _, err := simpleauthn.NewKey(simpleauthn.Unknown, "some-key"); err == nil {
		t.Error("expected error for Unknown algorithm")
	}
}

// ── Key.IsPrivate / Key.IsPublic ──────────────────────────────────────────────

func TestSymmetricKeyIsPrivateAndPublic(t *testing.T) {
	k, err := simpleauthn.NewKey(simpleauthn.HS256, "symmetric-secret")
	if err != nil {
		t.Fatal(err)
	}
	if !k.IsPrivate() {
		t.Error("symmetric key: IsPrivate() should be true")
	}
	if !k.IsPublic() {
		t.Error("symmetric key: IsPublic() should be true")
	}
}

func TestAsymmetricPrivateKeyIsPrivateOnly(t *testing.T) {
	k, err := key.GenerateKey(key.ED25519)
	if err != nil {
		t.Fatal(err)
	}
	sa, err := simpleauthn.NewKey(simpleauthn.ED25519, k.String())
	if err != nil {
		t.Fatal(err)
	}
	if !sa.IsPrivate() {
		t.Error("private key: IsPrivate() should be true")
	}
	if sa.IsPublic() {
		t.Error("private key: IsPublic() should be false")
	}
}

func TestAsymmetricPublicKeyIsPublicOnly(t *testing.T) {
	k, err := key.GenerateKey(key.ED25519)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := k.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	sa, err := simpleauthn.NewKey(simpleauthn.ED25519, pub.String())
	if err != nil {
		t.Fatal(err)
	}
	if sa.IsPrivate() {
		t.Error("public key: IsPrivate() should be false")
	}
	if !sa.IsPublic() {
		t.Error("public key: IsPublic() should be true")
	}
}

// ── NewHost ───────────────────────────────────────────────────────────────────

func TestNewHostRejectsNilKey(t *testing.T) {
	if _, err := simpleauthn.NewHost(nil, 30); err == nil {
		t.Error("expected error for nil key")
	}
}

func TestNewHostRejectsPrivateOnlyKey(t *testing.T) {
	k, err := key.GenerateKey(key.ED25519)
	if err != nil {
		t.Fatal(err)
	}
	privKey, err := simpleauthn.NewKey(simpleauthn.ED25519, k.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = simpleauthn.NewHost(privKey, 30); err == nil {
		t.Error("expected error: private-only key cannot be used for verification")
	}
}

func TestNewHostRejectsZeroValidity(t *testing.T) {
	k, err := simpleauthn.NewKey(simpleauthn.HS256, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = simpleauthn.NewHost(k, 0); err == nil {
		t.Error("expected error for validity=0")
	}
}

func TestNewHostRejectsNegativeValidity(t *testing.T) {
	k, err := simpleauthn.NewKey(simpleauthn.HS256, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = simpleauthn.NewHost(k, -1); err == nil {
		t.Error("expected error for validity=-1")
	}
}

// ── NewRequest ────────────────────────────────────────────────────────────────

func TestNewRequestRejectsNilKey(t *testing.T) {
	if _, err := simpleauthn.NewRequest(nil, struct{}{}); err == nil {
		t.Error("expected error for nil key")
	}
}

func TestNewRequestRejectsPublicOnlyKey(t *testing.T) {
	k, err := key.GenerateKey(key.ED25519)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := k.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err := simpleauthn.NewKey(simpleauthn.ED25519, pub.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = simpleauthn.NewRequest(pubKey, struct{}{}); err == nil {
		t.Error("expected error: public-only key cannot sign")
	}
}

// ── Round-trip helpers ────────────────────────────────────────────────────────

func roundTripSymmetric(t *testing.T, alg simpleauthn.Algorithm) {
	t.Helper()
	k, err := simpleauthn.NewKey(alg, "test-symmetric-secret")
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	host, err := simpleauthn.NewHost(k, 30)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	payload := &testPayload{
		Claim: simpleauthn.NewClaim(time.Second * 60),
		Role:  alg.String() + "-role",
	}
	token, err := simpleauthn.NewRequest(k, payload)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if token == "" {
		t.Fatal("NewRequest returned empty token")
	}
	result := new(testPayload)
	if err = host.Verify(token, result); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Role != payload.Role {
		t.Errorf("Role: got %q, want %q", result.Role, payload.Role)
	}
}

func roundTripAsymmetric(t *testing.T, alg simpleauthn.Algorithm, keyType shared.KeyType) {
	t.Helper()
	k, err := key.GenerateKey(keyType)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	privKey, err := simpleauthn.NewKey(alg, k.String())
	if err != nil {
		t.Fatalf("NewKey (private): %v", err)
	}
	pub, err := k.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	pubKey, err := simpleauthn.NewKey(alg, pub.String())
	if err != nil {
		t.Fatalf("NewKey (public): %v", err)
	}
	host, err := simpleauthn.NewHost(pubKey, 30)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	payload := &testPayload{
		Claim: simpleauthn.NewClaim(time.Second * 60),
		Role:  alg.String() + "-role",
	}
	token, err := simpleauthn.NewRequest(privKey, payload)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	result := new(testPayload)
	if err = host.Verify(token, result); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Role != payload.Role {
		t.Errorf("Role: got %q, want %q", result.Role, payload.Role)
	}
}

// ── Round-trip tests ──────────────────────────────────────────────────────────

func TestRoundTripHS256(t *testing.T)   { roundTripSymmetric(t, simpleauthn.HS256) }
func TestRoundTripHS384(t *testing.T)   { roundTripSymmetric(t, simpleauthn.HS384) }
func TestRoundTripHS512(t *testing.T)   { roundTripSymmetric(t, simpleauthn.HS512) }
func TestRoundTripED25519(t *testing.T) { roundTripAsymmetric(t, simpleauthn.ED25519, key.ED25519) }
func TestRoundTripES256(t *testing.T)   { roundTripAsymmetric(t, simpleauthn.ES256, key.ECDSA256) }
func TestRoundTripES384(t *testing.T)   { roundTripAsymmetric(t, simpleauthn.ES384, key.ECDSA384) }
func TestRoundTripES512(t *testing.T)   { roundTripAsymmetric(t, simpleauthn.ES512, key.ECDSA521) }

// ── Verify error cases ────────────────────────────────────────────────────────

func TestVerifyRejectsTamperedToken(t *testing.T) {
	k, err := simpleauthn.NewKey(simpleauthn.HS256, "tamper-test-secret")
	if err != nil {
		t.Fatal(err)
	}
	host, err := simpleauthn.NewHost(k, 30)
	if err != nil {
		t.Fatal(err)
	}
	token, err := simpleauthn.NewRequest(k, &testPayload{
		Claim: simpleauthn.NewClaim(time.Second * 60),
		Role:  "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	tampered := token[:len(token)-4] + "XXXX"
	if err = host.Verify(tampered, new(testPayload)); err == nil {
		t.Error("expected error for tampered token")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	k1, err := simpleauthn.NewKey(simpleauthn.HS256, "key-one")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := simpleauthn.NewKey(simpleauthn.HS256, "key-two")
	if err != nil {
		t.Fatal(err)
	}
	host, err := simpleauthn.NewHost(k2, 30)
	if err != nil {
		t.Fatal(err)
	}
	token, err := simpleauthn.NewRequest(k1, &testPayload{
		Claim: simpleauthn.NewClaim(time.Second * 60),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = host.Verify(token, new(testPayload)); err == nil {
		t.Error("expected error: token signed with wrong key must be rejected")
	}
}

func TestVerifyRejectsTokenOutsideValidityWindow(t *testing.T) {
	// Construct a token whose iat is 100 seconds in the past; validity is 30s.
	// diff = (now-100) - now + 30 = -70 → fails diff >= 0.
	// No sleep required.
	k, err := simpleauthn.NewKey(simpleauthn.HS256, "validity-window-secret")
	if err != nil {
		t.Fatal(err)
	}
	host, err := simpleauthn.NewHost(k, 30)
	if err != nil {
		t.Fatal(err)
	}
	stale := &testPayload{
		Claim: &simpleauthn.Claim{IssuedAt: time.Now().UTC().Unix() - 100},
	}
	token, err := simpleauthn.NewRequest(k, stale)
	if err != nil {
		t.Fatal(err)
	}
	if err = host.Verify(token, new(testPayload)); err == nil {
		t.Error("expected error: token outside validity window must be rejected")
	}
}

func TestVerifyRejectsMissingIssuedAt(t *testing.T) {
	k, err := simpleauthn.NewKey(simpleauthn.HS256, "iat-missing-secret")
	if err != nil {
		t.Fatal(err)
	}
	host, err := simpleauthn.NewHost(k, 30)
	if err != nil {
		t.Fatal(err)
	}
	// IssuedAt zero value → serialised as "iat":0 → rejected by Verify
	token, err := simpleauthn.NewRequest(k, &testPayload{
		Claim: &simpleauthn.Claim{IssuedAt: 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = host.Verify(token, new(testPayload)); err == nil {
		t.Error("expected error: zero iat must be rejected")
	}
}

func TestVerifyRejectsNotBeforeInFuture(t *testing.T) {
	k, err := simpleauthn.NewKey(simpleauthn.HS256, "nbf-future-secret")
	if err != nil {
		t.Fatal(err)
	}
	host, err := simpleauthn.NewHost(k, 30)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Unix()
	token, err := simpleauthn.NewRequest(k, &testPayload{
		Claim: &simpleauthn.Claim{
			IssuedAt:  now,
			NotBefore: now + 3600, // 1 hour in the future
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = host.Verify(token, new(testPayload)); err == nil {
		t.Error("expected error: nbf in the future must be rejected")
	}
}

func TestVerifyPayloadRoundTrip(t *testing.T) {
	k, err := simpleauthn.NewKey(simpleauthn.HS256, "payload-roundtrip-secret")
	if err != nil {
		t.Fatal(err)
	}
	host, err := simpleauthn.NewHost(k, 30)
	if err != nil {
		t.Fatal(err)
	}
	payload := &testPayload{
		Claim: simpleauthn.NewClaim(time.Second * 60),
		Role:  "roundtrip-role",
	}
	token, err := simpleauthn.NewRequest(k, payload)
	if err != nil {
		t.Fatal(err)
	}
	result := new(testPayload)
	if err = host.Verify(token, result); err != nil {
		t.Fatal(err)
	}
	if result.Role != payload.Role {
		t.Errorf("Role: got %q, want %q", result.Role, payload.Role)
	}
}

// ── Malformed-input rejection ─────────────────────────────────────────────────

func TestVerifyRejectsMalformedToken(t *testing.T) {
	k, err := simpleauthn.NewKey(simpleauthn.HS256, "malformed-token-secret")
	if err != nil {
		t.Fatal(err)
	}
	host, err := simpleauthn.NewHost(k, 30)
	if err != nil {
		t.Fatal(err)
	}
	malformed := []string{
		"",
		"not.a.token",
		"garbage",
		"eyJhbGciOiJIUzI1NiJ9",         // only a header segment
		"eyJhbGciOiJub25lIn0.payload.", // alg:none — must be rejected
	}
	for _, m := range malformed {
		m := m
		t.Run(fmt.Sprintf("%q", m), func(t *testing.T) {
			if err = host.Verify(m, new(testPayload)); err == nil {
				t.Errorf("Verify(%q): expected error for malformed token", m)
			}
		})
	}
}

func TestVerifyRejectsPlainJSONAsToken(t *testing.T) {
	// A plain JSON blob is not a JWS compact serialisation (unsigned).
	k, err := simpleauthn.NewKey(simpleauthn.HS256, "plain-json-secret")
	if err != nil {
		t.Fatal(err)
	}
	host, err := simpleauthn.NewHost(k, 30)
	if err != nil {
		t.Fatal(err)
	}
	plain := `{"iat":1700000000,"role":"admin"}`
	if err = host.Verify(plain, new(testPayload)); err == nil {
		t.Error("expected error: plain JSON must not be accepted as a signed token")
	}
}

func TestNewKeyRejectsMalformedJWK(t *testing.T) {
	// Non-empty but structurally invalid JWK JSON — must not panic or succeed.
	// Uses ED25519 because the input is parsed as an asymmetric key; symmetric
	// algorithms hash any non-empty string and always succeed.
	bad := []string{
		`{"kty":"EC"}`,      // missing required curve / key material
		`{"kty":"unknown"}`, // unrecognised key type
		`not json at all`,   // not JSON
		`{}`,                // empty object
	}
	for _, b := range bad {
		b := b
		preview := b
		if len(preview) > 20 {
			preview = preview[:20]
		}
		t.Run(fmt.Sprintf("%q", preview), func(t *testing.T) {
			if _, err := simpleauthn.NewKey(simpleauthn.ED25519, b); err == nil {
				t.Errorf("NewKey(ED25519, %q): expected error for malformed JWK", b)
			}
		})
	}
}
