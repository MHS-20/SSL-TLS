#ifndef CREDENTIALS_H
#define CREDENTIALS_H

/**
 * A certificate chain and its RSA private key, loaded from files.
 */

#include "rsa.h"

#define MAX_CHAIN_LENGTH 8

typedef struct
{
  int chain_length;
  unsigned char *certificates[ MAX_CHAIN_LENGTH ]; // DER, leaf first
  int certificate_lengths[ MAX_CHAIN_LENGTH ];
  rsa_key private_key;
  int loaded;
}
tls_credentials;

/**
 * cert_file: one DER certificate, or PEM with one or more (leaf first).
 * key_file: an RSA key as PEM or DER, PKCS #1 ("RSA PRIVATE KEY"),
 * PKCS #8 ("PRIVATE KEY") or encrypted PKCS #8 (PBE-MD5-DES) (password).
 * Returns 0 on success.
 */
int load_credentials( tls_credentials *credentials,
                      const char *cert_file,
                      const char *key_file,
                      const char *password );

void free_credentials( tls_credentials *credentials );

#endif
