CC ?= gcc
CFLAGS ?= -g -w
LDLIBS = -lm

TESTS = des_test aes_test rc4_test rsa_test digest_test hmac_test dsa_test ecdsa_test ecc_int_test

all: http webserver $(TESTS)

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

rsa_test: rsa.c huge.c hex.c
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
	rm -f http webserver $(TESTS) *.o

.PHONY: all clean
