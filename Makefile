CC ?= gcc
CFLAGS ?= -g -w
LDLIBS = -lm

TESTS = des_test aes_test rc4_test rsa_test digest_test hmac_test dsa_test ecdsa_test ecc_int_test asn1_test x509_test

all: http webserver https openssl_https ssl2_https ssl2_test prf_test ssl_webserver privkey_test $(TESTS)

http: http.c base64.c
	$(CC) $(CFLAGS) -o $@ $^

webserver: webserver.c
	$(CC) $(CFLAGS) -o $@ $^

des_test: des.c hex.c
	$(CC) $(CFLAGS) -DTEST_DES -o $@ $^

aes_test: aes.c hex.c
	$(CC) $(CFLAGS) -DTEST_AES -o $@ $^

rc4_test: rc4.c hex.c
	$(CC) $(CFLAGS) -DTEST_RC4 -o $@ $^

rsa_test: rsa.c random.c huge.c hex.c
	$(CC) $(CFLAGS) -DTEST_RSA -o $@ $^

digest_test: digest.c md5.c sha.c hex.c
	$(CC) $(CFLAGS) -DTEST_DIGEST -o $@ $^ $(LDLIBS)

hmac_test: hmac.c digest.c md5.c sha.c hex.c
	$(CC) $(CFLAGS) -DTEST_HMAC -o $@ $^ $(LDLIBS)

dsa_test: dsa.c huge.c digest.c md5.c sha.c hex.c
	$(CC) $(CFLAGS) -DTEST_DSA -o $@ $^ $(LDLIBS)

ecdsa_test: ecdsa.c ecc.c dsa.c huge.c digest.c md5.c sha.c hex.c
	$(CC) $(CFLAGS) -O2 -DTEST_ECDSA -o $@ $^ $(LDLIBS)

ecc_int_test: ecc_int.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f http webserver https openssl_https ssl2_https ssl_webserver prf_test privkey_test $(TESTS) *.o

.PHONY: all clean

asn1_test: asn1.c base64.c
	$(CC) $(CFLAGS) -DTEST_ASN1 -o $@ $^

x509_test: x509.c asn1.c base64.c random.c rsa.c dsa.c ecdsa.c ecc.c huge.c digest.c md5.c sha.c hex.c
	$(CC) $(CFLAGS) -DTEST_X509 -o $@ $^ $(LDLIBS)

TLS_OBJS = random.c tls.c privkey.c file.c prf.c x509.c asn1.c base64.c rsa.c dsa.c ecdsa.c ecc.c dh.c huge.c hmac.c digest.c md5.c sha.c des.c aes.c rc4.c hex.c

https: https.c $(TLS_OBJS)
	$(CC) $(CFLAGS) -O2 -o $@ $^ $(LDLIBS)

prf_test: prf.c hmac.c digest.c md5.c sha.c hex.c
	$(CC) $(CFLAGS) -DTEST_PRF -o $@ $^ $(LDLIBS)

ssl_webserver: ssl_webserver.c $(TLS_OBJS)
	$(CC) $(CFLAGS) -O2 -o $@ $^ $(LDLIBS)

privkey_test: privkey.c file.c asn1.c base64.c huge.c digest.c md5.c sha.c des.c hex.c
	$(CC) $(CFLAGS) -DTEST_PRIVKEY -o $@ $^ $(LDLIBS)


# : the same client on top of the OpenSSL library
openssl_https: openssl_https.c
	$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto

# Appendix C: SSLv2 client, and a replay of the original SSLv2 capture
SSL2_OBJS = ssl.c random.c x509.c asn1.c base64.c rsa.c dsa.c ecdsa.c ecc.c huge.c digest.c md5.c sha.c des.c rc4.c hex.c

ssl2_https: ssl2_https.c $(SSL2_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

ssl2_test: $(SSL2_OBJS)
	$(CC) $(CFLAGS) -DTEST_SSL2 -o $@ $^ $(LDLIBS)

test: all
	tests/unit.sh
	tests/interop.sh

.PHONY: test
