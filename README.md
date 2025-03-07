# Golang simple authentication library

Golang library to create a simple JWS authentication scheme. Allows creation of JWS signatures and verifying them using either ECDSA public/private keys or symetric keys.

# Supported Algorithms
This library supports the following algorithms

| Algorithm | Type | Description |
| :--: | :--: | :-- |
| `ED25519` | public/private key | uses twisted Edwards curves for signature generation. |
| `ES256` | public/private key | ECDSA with SHA-256 |
| `ES384` | public/private key | ECDSA with SHA-384 |
| `ES512` | public/private key | ECDSA with SHA-512 |
| `HS256` | symetric key | HMAC with SHA-256 |
| `HS384` | symetric key | HMAC with SHA-384 |
| `HS512` | symetric key | HMAC with SHA-512 |

# Creating JWS signature

This is done by the client side to create a request with required parameters for making sure the request is valid. The **absolute** minimum field needed is the issued at (`iat`) field that is used by the receiving end to ensure the request is valid. Other optional fields can be set which can be used by the caller to perform additional tasks based on the values. 

```golang
keyInput, err := simpleauthn.NewKey(simpleauthn.AlgHS256, "super-secret-key") // create a key using symetric keys (shared secret)
if nil != err {
    log.Println(err)
    os.Exit(1)
}

//requestStr, err := simpleauthn.NewRequest(key, &simpleauthn.Optional{NotBefore: time.Now().UTC().Unix() + 100})
requestStr, err := simpleauthn.NewRequest(keyInput, nil)
if nil != err {
    log.Println(err)
    os.Exit(1)
}
fmt.Println(requestStr)
```

The JSON structure for the fields in the request are
```json
{
    "iat": unix timestamp when the request was created,
    "nbf": unix timestamp when the request is considered valid (optional),
    "exp": unix timestamp when the request will be invalid (optional),
    "iss": "issuer of this token, can be a valid string",
    "payload": "can be anything that is needed by the application"
}
```

## Optional parameters

To pass additional values to the request, use the following approach

```golang
requestStr, err := simpleauthn.NewRequest(keyInput, &simpleauthn.Optional{
    NotBefore: time.Now().UTC().Unix(),
    Expiry:    time.Now().UTC().Unix() + 100,
    Issuer:    "301:11.8888/USER/ABCD",
    Payload:   "anything i want",
})
```

The above are considered optional fields and will not be used by this library with the exception of the `NotBefore` field. If set, the library ensures the time given in `NotBefore` is not in the future. If it is, this library will return an error.


# Verifying JWS signature

This is done by the host side to verify the signature and making sure the request is within the valid timeframe. Only the host side can specify the validity of the request, and it uses the `iat` field to check the validity. This requires both the host and client to ensure their system clock is set correctly without too much of a skew. `iat` is used to check for validity as it is the most viable field to ensure both client and host has a proper system clock. Using expiry (`exp`) allows the requester to set the validity of the request which could be set too far into the future, which breaks the purpose of using a short-lived token.

```golang
keyInput, err := simpleauthn.NewKey(simpleauthn.HS256, "super-secret-key") // create a key using symetric keys (shared secret)
if nil != err {
    log.Println(err)
    os.Exit(1)
}

// the second parameter is the validity period of the JWS in seconds
host, err := simpleauthn.NewHost(keyInput, 30)
if nil != err {
    log.Println(err)
    os.Exit(1)
}

request, err := host.Verify(requestStr)
if nil != err {
    log.Println(err)
    os.Exit(1)
}

// if there is no error, the request string was verified successfully, use the request struct values as needed within the application
fmt.Println(request)
```

# Using ECDSA public/private key

Instead of using symetric keys (shared secret), it is possible to use ECDSA keys to sign and verify the JWS. This assumes a valid ECDSA public/private key already exists. 

The client side uses the private key to sign the request and host uses the public key to verify the request. This library assumes the public and private key will be obtained externally by the caller.

The public and private keys must be passed to the function in JWK string format, after which the function will parse the values to obtain the keys.

## Creating JWS signature using ECDSA private key

```golang
keyPrivate, err := simpleauthn.NewKey(simpleauthn.ED25519, privateKeyJWKString)
if nil != err {
    log.Println(err)
    os.Exit(1)
}

// the second optional parameter field uses the same parameters as shown above
requestStr, err := simpleauthn.NewRequest(keyPrivate, nil)
if nil != err {
    log.Println(err)
    os.Exit(1)
}
fmt.Println(requestStr)

```

## Verifying JWS signature using ECDSA public key

```golang
keyPublic, err := simpleauthn.NewKey(simpleauthn.ED25519, publicKeyJWKString)
if nil != err {
    log.Println(err)
    os.Exit(1)
}

// the second parameter is the validity period of the JWS in seconds
host, err := simpleauthn.NewHost(keyPublic, 30)
if nil != err {
    log.Println(err)
    os.Exit(1)
}

request, err := host.Verify(requestStr)
if nil != err {
    log.Println(err)
    os.Exit(1)
}

// if there is no error, the request string was verified successfully, use the request struct values as needed within the application
fmt.Println(request)
```

# Determining algorithm from `public/private` key

There may come a time when we may not know what public/private key is given, in that case we can use the following approach to determine the algorithm. For symetric keys, the default algorithm selected is `HS256`.

**NOTE**: Ideally, the key type is known so we can specify the explicit algorithm during initalization.

```go
// `inputKey` is a string obtainer from another source
alg, err := simpleauthn.AlgForKey(inputKey)
if nil != err {
    log.Println(err)
    os.Exit(1)
}
fmt.Println(alg)

```
