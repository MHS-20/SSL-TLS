# SSL-TLS

A TLS 1.0–1.2 client and server in C, with every primitive written from scratch (no OpenSSL, no libc crypto). It talks to OpenSSL and to real HTTPS sites, verifying certificate chains against the system trust store.

```
$ ./https https://github.com/
Connecting to host 'github.com'
Connection complete; negotiating TLS parameters
Retrieving document: ''
HTTP/1.1 200 OK
...
```

## What's implemented

| Layer | Pieces | Files |
|---|---|---|
| Big numbers | signed arbitrary precision, 32-bit-limb multiply and Knuth division, mod_pow, modular inverse | `huge.c` |
| Symmetric ciphers | DES, 3DES, AES-128/256 (CBC, CTR, CCM, GCM), RC4 | `des.c`, `aes.c`, `rc4.c` |
| Hashes and MACs | MD5, SHA-1, SHA-256, SHA-384, SHA-512, HMAC, TLS 1.0 and 1.2 PRFs | `md5.c`, `sha.c`, `sha512.c`, `hmac.c`, `prf.c` |
| Public key | RSA (PKCS #1 v1.5 encrypt/sign), DH, DSA, elliptic curves P-192/P-256/P-384, ECDH, ECDSA | `rsa.c`, `dh.c`, `dsa.c`, `ecc.c`, `ecdsa.c` |
| PKI | ASN.1 DER parser, PEM, X.509 (RSA/DSA/ECDSA keys, SHA-1/256/384/512 signatures, basicConstraints, subjectAltName), chain and host name verification, PKCS #1/#8 private keys | `asn1.c`, `base64.c`, `x509.c`, `privkey.c`, `credentials.c` |
| TLS | record layer (MAC-then-encrypt CBC with explicit IVs, AEAD), handshake client and server, TLS 1.0/1.1/1.2 negotiated at run time | `tls.c` |
| Randomness | `getrandom(2)` | `random.c` |
| Programs | `https` client, `ssl_webserver`, `openssl_https` (same client on OpenSSL), `ssl2_https` (SSLv2, Appendix C) | |

Cipher suites: `ECDHE_{RSA,ECDSA}_WITH_AES_128_GCM_SHA256`, `ECDHE_{RSA,ECDSA}_WITH_AES_{128,256}_CBC_SHA`, `RSA_WITH_AES_128_GCM_SHA256`, `{RSA,DHE_RSA,DHE_DSS,DH_anon}_WITH_AES_{128,256}_CBC_SHA`, and the DES/3DES/RC4 suites of TLS 1.0. The server does RSA and ECDHE_RSA key exchange.

Handshake features: session resumption (both sides), client authentication (as a client), secure renegotiation (RFC 5746), SNI, signature_algorithms, supported curves and point formats, handshake messages spanning records, the random-premaster defense against Bleichenbacher's attack.

## Layout

| Directory | Contents |
|---|---|
| `src/util` | hex, base64, file loading, `getrandom` |
| `src/cipher` | DES/3DES, AES (CBC, CTR, CCM, GCM), RC4 |
| `src/hash` | digest framework, MD5, SHA-1/256/384/512, HMAC, PRFs |
| `src/pubkey` | big numbers, RSA, DH, DSA, elliptic curves, ECDSA |
| `src/pki` | ASN.1/PEM, X.509 and chain verification, private keys, credentials |
| `src/tls` | the TLS record layer and handshakes; an SSLv2 client |
| `src/apps` | `https`, `ssl_webserver`, `openssl_https`, `ssl2_https`, plain HTTP examples |
| `tests` | `unit.sh` (known-answer vectors), `interop.sh` (against OpenSSL) |

## Build and test

```
make            # everything, including the *_test programs
make test       # tests/unit.sh (known-answer vectors) + tests/interop.sh (against OpenSSL)
```

Needs gcc, make and OpenSSL 3 (only for the interop tests). The interop script generates its own certificates, starts `openssl s_server` / `s_client` on random ports and checks 26 scenarios: every suite family and version as a client, the server with RSA/ECDHE/GCM/resumption, client authentication, an untrusted chain and a fragmented handshake.

## Using the programs

```
https [-V 1.0|1.1|1.2] [-c <suite hex>] [-C <ca.pem> | -k] [-cert <cert> <key>]
      [-p http://[user:pass@]proxy:port] [-s <session id> -m <master secret>] <https://host[:port]/path>

ssl_webserver [port] [-V <max version>] [-cert <file> -key <file> [-pass <password>]]
```

`https` verifies the server against `/etc/ssl/certs/ca-certificates.crt` unless given `-C` or `-k`. `ssl_webserver` serves its own request back as a page; without `-cert`/`-key` it falls back to `cert.der` + `key.pkcs8` (password `password`) in the working directory.

## Not implemented

TLS 1.3, X25519, ChaCha20-Poly1305, extended master secret (RFC 7627), session tickets, OCSP/CRL revocation, name constraints and policy checks, constant-time big-number arithmetic. RC4, DES, MD5-based suites and SSLv2 are here for study; don't use them.
