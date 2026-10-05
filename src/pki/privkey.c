#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "privkey.h"
#include "asn1.h"
#include "md5.h"
#include "des.h"
#include "file.h"
#include "hex.h"

/**
 * Parse the modulus and private exponent from the buffer, which
 * should contain a DER-encoded RSA private key file. There's a
 * lot more information in the private key file format, but this
 * app isn't set up to use any of it.
 * This, according to PKCS #1 (note that this is not in pkcs #8 format), is:
 * Version
 * modulus (n)
 * public exponent (e)
 * private exponent (d)
 * prime1 (p)
 * prime2 (q)
 * exponent1 (d mod p-1)
 * exponent2 (d mod q-1)
 * coefficient (inverse of q % p)
 * Here, all we care about is n & d.
 */
int parse_private_key( rsa_key *privkey,
                       const unsigned char *buffer,
                       int buffer_length )
{
  struct asn1struct private_key;
  struct asn1struct *version;
  struct asn1struct *modulus;
  struct asn1struct *public_exponent;
  struct asn1struct *private_exponent;

  if ( asn1parse( buffer, buffer_length, &private_key ) ||
       !( version = ( struct asn1struct * ) private_key.children ) ||
       !( modulus = ( struct asn1struct * ) version->next ) ||
       !( public_exponent = ( struct asn1struct * ) modulus->next ) ||
       !( private_exponent = ( struct asn1struct * ) public_exponent->next ) )
  {
    asn1free( &private_key );
    return 1;
  }

  privkey->modulus = malloc( sizeof( huge ) );
  privkey->exponent = malloc( sizeof( huge ) );
  load_huge( privkey->modulus, modulus->data, modulus->length );
  load_huge( privkey->exponent, private_exponent->data, private_exponent->length );
  // Drop the DER sign byte so the modulus has its real length
  contract( privkey->modulus );
  contract( privkey->exponent );

  asn1free( &private_key );

  return 0;
}

static unsigned char OID_pbeWithMD5andDES_CBC[] =
  { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x03 };
static unsigned char OID_RSAPrivateKey [] =
  { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };

int parse_pkcs8_private_key( rsa_key *privkey,
                             const unsigned char *buffer,
                             const int buffer_length,
                             const unsigned char *passphrase )
{
  struct asn1struct pkcs8_key;
  struct asn1struct private_key;
  struct asn1struct *encryptionId;
  struct asn1struct *salt;
  struct asn1struct *iteration_count;
  struct asn1struct *encrypted_key;
  struct asn1struct *key_type_oid;
  struct asn1struct *priv_key_data;
  digest_ctx initial_hash;
  int counter;
  int i;
  unsigned char passphrase_hash_out[ MD5_RESULT_SIZE * sizeof( int ) ];
  unsigned char *decrypted_key;

  asn1parse( buffer, buffer_length, &pkcs8_key );

  encryptionId = pkcs8_key.children->children;
  if ( memcmp( OID_pbeWithMD5andDES_CBC, encryptionId->data,
               encryptionId->length ) )
  {
    fprintf( stderr, "Unsupported key encryption algorithm\n" );
    asn1free( &pkcs8_key );
    return 1;
  }
  // TODO support more algorithms
  salt = encryptionId->next->children;
  iteration_count = salt->next;
  encrypted_key = pkcs8_key.children->next;

  counter = 0;
  for ( i = 0; i < iteration_count->length; i++ )
  {
    counter = ( counter << 8 ) | iteration_count->data[ i ];
  }

  // Since the passphrase can be any length, not necessarily 8 bytes,
  // must use a digest here.
  new_md5_digest( &initial_hash );
  update_digest( &initial_hash, passphrase, strlen( passphrase ) );
  update_digest( &initial_hash, salt->data, salt->length );
  finalize_digest( &initial_hash );
  memcpy( passphrase_hash_out, initial_hash.hash,
    initial_hash.hash_len * sizeof( int ) );
  free( initial_hash.hash );

  while ( --counter )
  {
    new_md5_digest( &initial_hash );
    update_digest( &initial_hash, passphrase_hash_out,
      sizeof( int ) * MD5_RESULT_SIZE );
    finalize_digest( &initial_hash );
    memcpy( passphrase_hash_out, initial_hash.hash,
      sizeof( int ) * MD5_RESULT_SIZE );
    free( initial_hash.hash );
  }

  decrypted_key = ( unsigned char * ) malloc( encrypted_key->length );
  des_decrypt( encrypted_key->data, encrypted_key->length, decrypted_key,
    ( unsigned char * ) passphrase_hash_out + DES_KEY_SIZE,
    ( unsigned char * ) passphrase_hash_out );

  // sanity check
  if ( decrypted_key[ encrypted_key->length - 1 ] > 8 )
  {
    fprintf( stderr, "Decryption error, bad padding\n");
    asn1free( &pkcs8_key );
    free( decrypted_key );
    return 1;
  }

  asn1parse( decrypted_key,
    encrypted_key->length - decrypted_key[ encrypted_key->length - 1 ],
    &private_key );

  key_type_oid = private_key.children->next->children;
  if ( memcmp( OID_RSAPrivateKey, key_type_oid->data, key_type_oid->length ) )
  {
    fprintf( stderr, "Unsupported private key type" );
    asn1free( &pkcs8_key );
    asn1free( &private_key );
    free( decrypted_key );
    return 1;
  }

  priv_key_data = private_key.children->next->next;

  parse_private_key( privkey, priv_key_data->data, priv_key_data->length );

  asn1free( &pkcs8_key );
  asn1free( &private_key );
  free( decrypted_key );

  return 0;
}

#ifdef TEST_PRIVKEY
int main( int argc, char *argv[ ] )
{
  rsa_key privkey;
  unsigned char *buffer;
  int buffer_length;

  if ( argc < 3 )
  {
    fprintf( stderr, "Usage: %s [-pem|-der|-pkcs8] <rsa private key file> [passphrase]\n",
      argv[ 0 ] );
    exit( 0 );
  }

  if ( !( buffer = load_file_into_memory( argv[ 2 ], &buffer_length ) ) )
  {
    perror( "Unable to load file" );
    exit( 1 );
  }

  if ( !strcmp( argv[ 1 ], "-pem" ) )
  {
    // XXX this overallocates a bit, since it sets aside space for markers, etc.
    unsigned char *pem_buffer = buffer;
    buffer = (unsigned char * ) malloc( buffer_length );
    buffer_length = pem_decode( pem_buffer, buffer );
    free( pem_buffer );
  }

  if ( !strcmp( argv[ 1 ], "-pkcs8" ) )
  {
    if ( parse_pkcs8_private_key( &privkey, buffer, buffer_length,
         argc > 3 ? argv[ 3 ] : "password" ) )
    {
      exit( 1 );
    }
  }
  else
  {
    parse_private_key( &privkey, buffer, buffer_length );
  }

  printf( "Modulus:" );
  show_hex( privkey.modulus->rep, privkey.modulus->size );
  printf( "Private Exponent:" );
  show_hex( privkey.exponent->rep, privkey.exponent->size );

  free( buffer );

  return 0;
}
#endif
