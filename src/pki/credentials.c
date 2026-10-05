#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "credentials.h"
#include "privkey.h"
#include "asn1.h"
#include "file.h"

#define PEM_CERTIFICATE "-----BEGIN CERTIFICATE-----"

static int is_pem( const char *buffer )
{
  return strstr( buffer, "-----BEGIN" ) != NULL;
}

/**
 * Parse a DER RSA key in any of the three supported layouts.
 */
static int parse_any_private_key( rsa_key *key,
                                  const unsigned char *der,
                                  int der_length,
                                  const char *password )
{
  struct asn1struct top;
  struct asn1struct *first, *second;
  int status = -1;

  if ( asn1parse( der, der_length, &top ) || !top.children ||
       !top.children->next )
  {
    asn1free( &top );
    return -1;
  }
  first = top.children;
  second = first->next;

  if ( first->tag == ASN1_SEQUENCE )
  {
    // EncryptedPrivateKeyInfo: SEQUENCE { AlgorithmIdentifier, OCTET STRING }
    asn1free( &top );
    return parse_pkcs8_private_key( key, der, der_length,
      ( const unsigned char * ) ( password ? password : "" ) ) ? -1 : 0;
  }
  if ( second->tag == ASN1_SEQUENCE && second->next &&
       second->next->tag == ASN1_OCTET_STRING )
  {
    // PrivateKeyInfo: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING
    // containing an RSAPrivateKey }
    status = parse_private_key( key, second->next->data,
      second->next->length ) ? -1 : 0;
  }
  else if ( second->tag == ASN1_INTEGER )
  {
    // RSAPrivateKey: SEQUENCE { version, n, e, d, ... }
    status = parse_private_key( key, der, der_length ) ? -1 : 0;
  }

  asn1free( &top );

  return status;
}

int load_credentials( tls_credentials *credentials,
                      const char *cert_file,
                      const char *key_file,
                      const char *password )
{
  char *buffer;
  int buffer_length;
  unsigned char *der;
  int der_length;
  int status;

  memset( credentials, 0, sizeof( tls_credentials ) );

  if ( !( buffer = load_file_into_memory( ( char * ) cert_file,
                                          &buffer_length ) ) )
  {
    return -1;
  }
  if ( is_pem( buffer ) )
  {
    char *pos;
    for ( pos = strstr( buffer, PEM_CERTIFICATE );
          pos && credentials->chain_length < MAX_CHAIN_LENGTH;
          pos = strstr( pos + 1, PEM_CERTIFICATE ) )
    {
      der = malloc( buffer_length );
      der_length = pem_decode( ( unsigned char * ) pos, der );
      credentials->certificates[ credentials->chain_length ] = der;
      credentials->certificate_lengths[ credentials->chain_length++ ] =
        der_length;
    }
  }
  else
  {
    der = malloc( buffer_length );
    memcpy( der, buffer, buffer_length );
    credentials->certificates[ 0 ] = der;
    credentials->certificate_lengths[ 0 ] = buffer_length;
    credentials->chain_length = 1;
  }
  free( buffer );
  if ( !credentials->chain_length )
  {
    return -1;
  }

  if ( !( buffer = load_file_into_memory( ( char * ) key_file,
                                          &buffer_length ) ) )
  {
    free_credentials( credentials );
    return -1;
  }
  if ( is_pem( buffer ) )
  {
    der = malloc( buffer_length );
    der_length = pem_decode( ( unsigned char * ) strstr( buffer, "-----BEGIN" ),
      der );
    status = parse_any_private_key( &credentials->private_key, der,
      der_length, password );
    free( der );
  }
  else
  {
    status = parse_any_private_key( &credentials->private_key,
      ( unsigned char * ) buffer, buffer_length, password );
  }
  free( buffer );

  if ( status )
  {
    free_credentials( credentials );
    return -1;
  }
  credentials->loaded = 1;

  return 0;
}

void free_credentials( tls_credentials *credentials )
{
  while ( credentials->chain_length )
  {
    free( credentials->certificates[ --credentials->chain_length ] );
  }
  if ( credentials->loaded )
  {
    free_huge( credentials->private_key.modulus );
    free_huge( credentials->private_key.exponent );
    free( credentials->private_key.modulus );
    free( credentials->private_key.exponent );
  }
  credentials->loaded = 0;
}
