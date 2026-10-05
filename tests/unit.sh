#!/bin/bash
# Known-answer tests for the primitives (reference outputs and standard vectors).
# usage: tests/unit.sh   (run from the repo root after make)
cd "$(dirname "$0")/.."
FAILS=0
check() { # name expected command...
  local name=$1 expected=$2; shift 2
  local got
  got=$("$@" 2>&1)
  if [[ "$got" == *"$expected"* ]]; then echo "PASS $name"
  else echo "FAIL $name"; echo "  expected: $expected"; echo "  got: $got"; FAILS=$(( FAILS + 1 )); fi
}
check des-reference       71828547387b18e5 ./des_test -e password initialz abcdefgh
check aes128-cbc     7649abac8119b246cee98e9b12e9197d \
  ./aes_test -e 0x2b7e151628aed2a6abf7158809cf4f3c 0x000102030405060708090a0b0c0d0e0f 0x6bc1bee22e409f96e93d7e117393172a
check aes-ctr        874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff \
  ./aes_test -ctr 0x2b7e151628aed2a6abf7158809cf4f3c 0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff \
  0x6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51
check aes-ccm-reference   404855688058bb65f9c511 ./aes_test -ccm-e "@ABCDEFGHIJKLMNO" 12345678 abc tuvwxyz
check aes-gcm-reference   87fd0515d242cf110c77b98055c3ad3196aec6 ./aes_test -gcm-e "@ABCDEFGHIJKLMNO" 12345678 abc tuvwxyz
check aes-gcm-nist4  42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e0915bc94fbc3221a5db94fae95ae7121a47 \
  ./aes_test -gcm-e 0xfeffe9928665731c6d6a8f9467308308 0xcafebabefacedbaddecaf888 \
  0xd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39 \
  0xfeedfacedeadbeeffeedfacedeadbeefabaddad2
check rc4-reference       daf70b86e76454eb975e3bfe2cce339c ./rc4_test -e abcdef abcdefghijklmnop
check md5            900150983cd24fb0d6963f7d28e17f72 ./digest_test -md5 abc
check sha1           a9993e364706816aba3e25717850c26c9cd0d89d ./digest_test -sha1 abc
check sha256         ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad ./digest_test -sha256 abc
check hmac-md5       750c783e6ab0b503eaa86e310a5db738 ./hmac_test -md5 Jefe "what do ya want for nothing?"
check hmac-sha1-long aa4ae5e15272d00e95705637ce8a3b55ed402112 ./hmac_test -sha1 \
  0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  "Test Using Larger Than Block-Size Key - Hash Key First"
check prf-reference       b5baf4722b91851a8816d22ebd8c1d8cc2e94d55 ./prf_test secret label seed 20
check dsa-reference       14297f2522458d809b6c5752d3975a00bb0d89e0 ./dsa_test
check ecdsa-reference     "Signature verified." ./ecdsa_test
check sslv2-replay   "GET request      matches the reference" ./ssl2_test
echo "$FAILS failure(s)"
exit $FAILS
