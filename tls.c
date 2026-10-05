#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#endif
#include "tls.h"
#include "md5.h"
#include "sha.h"
#include "hmac.h"
#include "prf.h"
#include "des.h"
#include "aes.h"
#include "rc4.h"
#include "rsa.h"
#include "privkey.h"
#include "file.h"
#include "asn1.h"
#include "ecc.h"
#include "ecdsa.h"
#include "random.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

static CipherSuite suites[ MAX_SUPPORTED_CIPHER_SUITE ] =
{
  { TLS_NULL_WITH_NULL_NULL, 0, 0, 0, 0, NULL, NULL, NULL },
  { TLS_RSA_WITH_NULL_MD5, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL, new_md5_digest },
  { TLS_RSA_WITH_NULL_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
  { TLS_RSA_EXPORT_WITH_RC4_40_MD5, 0, 0, 5, MD5_BYTE_SIZE, rc4_40_encrypt,
    rc4_40_decrypt, new_md5_digest },
  { TLS_RSA_WITH_RC4_128_MD5, 0, 0, 16, MD5_BYTE_SIZE, rc4_128_encrypt,
    rc4_128_decrypt, new_md5_digest },
  { TLS_RSA_WITH_RC4_128_SHA, 0, 0, 16, SHA1_BYTE_SIZE, rc4_128_encrypt,
    rc4_128_decrypt, new_sha1_digest },
  { TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL,
    new_md5_digest },
  { TLS_RSA_WITH_IDEA_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL,
    new_sha1_digest },
  { TLS_RSA_EXPORT_WITH_DES40_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL,
    new_sha1_digest },
  { TLS_RSA_WITH_DES_CBC_SHA, 8, 8, 8, SHA1_BYTE_SIZE, des_encrypt, des_decrypt,
    new_sha1_digest },
  { TLS_RSA_WITH_3DES_EDE_CBC_SHA, 8, 8, 24, SHA1_BYTE_SIZE, des3_encrypt,
    des3_decrypt, new_sha1_digest },
  { TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL,
    new_sha1_digest },
  { TLS_DH_DSS_WITH_DES_CBC_SHA, 8, 8, 8, SHA1_BYTE_SIZE, des_encrypt,
    des_decrypt, new_sha1_digest },
  { TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA, 8, 8, 24, SHA1_BYTE_SIZE, des3_encrypt,
    des3_decrypt, new_sha1_digest },
  { TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL,
    new_sha1_digest },
  { TLS_DH_RSA_WITH_DES_CBC_SHA, 8, 8, 8, SHA1_BYTE_SIZE, des_encrypt,
    des_decrypt, new_sha1_digest },
  { TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA, 8, 8, 24, SHA1_BYTE_SIZE, des3_encrypt,
    des3_decrypt, new_sha1_digest },
  { TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL,
    new_sha1_digest },
  { TLS_DHE_DSS_WITH_DES_CBC_SHA, 8, 8, 8, SHA1_BYTE_SIZE, des_encrypt,
    des_decrypt, new_sha1_digest },
  { TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, 8, 8, 24, SHA1_BYTE_SIZE, des3_encrypt,
    des3_decrypt, new_sha1_digest },
  { TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL,
    new_sha1_digest },
  { TLS_DHE_RSA_WITH_DES_CBC_SHA, 8, 8, 8, SHA1_BYTE_SIZE, des_encrypt,
    des_decrypt, new_sha1_digest },
  { TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, 8, 8, 24, SHA1_BYTE_SIZE, des3_encrypt,
    des3_decrypt, new_sha1_digest },
  { TLS_DH_anon_EXPORT_WITH_RC4_40_MD5, 0, 0, 5, MD5_BYTE_SIZE, rc4_40_encrypt,
    rc4_40_decrypt, new_md5_digest },
  { TLS_DH_anon_WITH_RC4_128_MD5, 0, 0, 16, MD5_BYTE_SIZE, rc4_128_encrypt,
    rc4_128_decrypt, new_md5_digest },
  { TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL,
    new_sha1_digest },
  { TLS_DH_anon_WITH_DES_CBC_SHA, 8, 8, 8, SHA1_BYTE_SIZE, des_encrypt,
    des_decrypt, new_sha1_digest },
  { TLS_DH_anon_WITH_3DES_EDE_CBC_SHA, 8, 8, 24, SHA1_BYTE_SIZE, des3_encrypt,
    des3_decrypt, new_sha1_digest },
  { 0x001C, 0, 0, 0, 0, NULL, NULL, NULL },
  { 0x001D, 0, 0, 0, 0, NULL, NULL, NULL },
  { TLS_KRB5_WITH_DES_CBC_SHA, 0, 0, 0, 0, NULL, NULL, NULL },
  { TLS_KRB5_WITH_3DES_EDE_CBC_SHA, 0, 0, 0, 0, NULL, NULL, NULL },
  { TLS_KRB5_WITH_RC4_128_SHA, 0, 0, 0, 0, NULL, NULL, NULL },
  { TLS_KRB5_WITH_IDEA_CBC_SHA, 0, 0, 0, 0, NULL, NULL, NULL },
  { TLS_KRB5_WITH_DES_CBC_MD5, 0, 0, 0, 0, NULL, NULL, NULL },
  { TLS_KRB5_WITH_3DES_EDE_CBC_MD5, 0, 0, 0, 0, NULL, NULL, NULL },
  { TLS_KRB5_WITH_RC4_128_MD5, 0, 0, 0, 0, NULL, NULL, NULL },
  { TLS_KRB5_WITH_IDEA_CBC_MD5, 0, 0, 0, 0, NULL, NULL, NULL },
  { TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA, 0, 0, 0, 0, NULL, NULL, NULL },
  { TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA, 0, 0, 0, 0, NULL, NULL, NULL },
  { TLS_KRB5_EXPORT_WITH_RC4_40_SHA, 0, 0, 0, 0, NULL, NULL, NULL },
  { TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5, 0, 0, 0, 0, NULL, NULL, NULL },
  { TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5, 0, 0, 0, 0, NULL, NULL, NULL },
  { TLS_KRB5_EXPORT_WITH_RC4_40_MD5, 0, 0, 0, 0, NULL, NULL, NULL },
  { 0x002C, 0, 0, 0, 0, NULL, NULL, NULL },
  { 0x002D, 0, 0, 0, 0, NULL, NULL, NULL },
  { 0x002E, 0, 0, 0, 0, NULL, NULL, NULL },
  { TLS_RSA_WITH_AES_128_CBC_SHA, 16, 16, 16, SHA1_BYTE_SIZE, aes_128_encrypt,
    aes_128_decrypt, new_sha1_digest },
  { TLS_DH_DSS_WITH_AES_128_CBC_SHA, 16, 16, 16, SHA1_BYTE_SIZE, aes_128_encrypt,
    aes_128_decrypt, new_sha1_digest },
  { TLS_DH_RSA_WITH_AES_128_CBC_SHA, 16, 16, 16, SHA1_BYTE_SIZE, aes_128_encrypt,
    aes_128_decrypt, new_sha1_digest },
  { TLS_DHE_DSS_WITH_AES_128_CBC_SHA, 16, 16, 16, SHA1_BYTE_SIZE, aes_128_encrypt,
    aes_128_decrypt, new_sha1_digest },
  { TLS_DHE_RSA_WITH_AES_128_CBC_SHA, 16, 16, 16, SHA1_BYTE_SIZE, aes_128_encrypt,
    aes_128_decrypt, new_sha1_digest },
  { TLS_DH_anon_WITH_AES_128_CBC_SHA, 16, 16, 16, SHA1_BYTE_SIZE, aes_128_encrypt,
    aes_128_decrypt, new_sha1_digest },
  { TLS_RSA_WITH_AES_256_CBC_SHA, 16, 16, 32, SHA1_BYTE_SIZE, aes_256_encrypt,
    aes_256_decrypt, new_sha1_digest },
  { TLS_DH_DSS_WITH_AES_256_CBC_SHA, 16, 16, 32, SHA1_BYTE_SIZE, aes_256_encrypt,
    aes_256_decrypt, new_sha1_digest },
  { TLS_DH_RSA_WITH_AES_256_CBC_SHA, 16, 16, 32, SHA1_BYTE_SIZE, aes_256_encrypt,
    aes_256_decrypt, new_sha1_digest },
  { TLS_DHE_DSS_WITH_AES_256_CBC_SHA, 16, 16, 32, SHA1_BYTE_SIZE, aes_256_encrypt,
    aes_256_decrypt, new_sha1_digest },
  { TLS_DHE_RSA_WITH_AES_256_CBC_SHA, 16, 16, 32, SHA1_BYTE_SIZE, aes_256_encrypt,
    aes_256_decrypt, new_sha1_digest },
  { TLS_DH_anon_WITH_AES_256_CBC_SHA, 16, 16, 32, SHA1_BYTE_SIZE, aes_256_encrypt,
    aes_256_decrypt, new_sha1_digest },
};

static void init_protection_parameters( ProtectionParameters *parameters )
{
  parameters->MAC_secret = NULL;
  parameters->key = NULL;
  parameters->IV = NULL;
  parameters->seq_num = 0;
  parameters->suite = TLS_NULL_WITH_NULL_NULL;
}

static void init_parameters( TLSParameters *parameters,
                             int renegotiate )
{
  init_protection_parameters( &parameters->pending_send_parameters );
  init_protection_parameters( &parameters->pending_recv_parameters );

  if ( !renegotiate )
  {
    init_protection_parameters( &parameters->active_send_parameters );
    init_protection_parameters( &parameters->active_recv_parameters );

    // Always assume secure renegotiation to begin
    parameters->support_secure_renegotiation = 1;
    memset( parameters->client_verify_data, '\0', VERIFY_DATA_LEN );
    memset( parameters->server_verify_data, '\0', VERIFY_DATA_LEN );
  }

  memset( parameters->master_secret, '\0', MASTER_SECRET_LENGTH );
  memset( parameters->client_random, '\0', RANDOM_LENGTH );
  memset( parameters->server_random, '\0', RANDOM_LENGTH );
  // Internal state
  parameters->got_client_hello = 0;
  parameters->got_server_hello = 0;
  parameters->server_hello_done = 0;
  parameters->peer_finished = 0;
  parameters->got_certificate_request = 0;
  parameters->unread_buffer = NULL;
  parameters->unread_length = 0;
  parameters->session_id_length = 0;
}

/**
 * This is just like memcpy, except it returns a pointer to dest + n instead
 * of dest, to simplify the process of repeated appends to a buffer.
 */
static char *append_buffer( char *dest, char *src, size_t n )
{
  memcpy( dest, src, n );
  return dest + n;
}

static char *read_buffer( char *dest, char *src, size_t n )
{
  memcpy( dest, src, n );
  return src + n;
}

static int send_message( int connection,
                         int content_type,
                         const unsigned char *content,
                         short content_len,
                         ProtectionParameters *parameters )
{
  TLSPlaintext header;
  unsigned char *send_buffer;
  int send_buffer_size;
  unsigned char padding_length = 0;
  unsigned char *mac = NULL;
  unsigned char mac_header[ 13 ];
  digest_ctx digest;
  CipherSuite *active_suite;
  int sequence_num;

  active_suite = &suites[ parameters->suite ];

  // Compute the MAC header always, since this will be used
  // for AEAD or other ciphers: the 8-byte sequence number and the 5-byte
  // pseudo header.
  memset( mac_header, '\0', 8 );
  sequence_num = htonl( parameters->seq_num );
  memcpy( mac_header + 4, &sequence_num, sizeof( int ) );

  header.type = content_type;
  header.version.major = TLS_VERSION_MAJOR;
  header.version.minor = TLS_VERSION_MINOR;
  header.length = htons( content_len );
  mac_header[ 8 ] = header.type;
  mac_header[ 9 ] = header.version.major;
  mac_header[ 10 ] = header.version.minor;
  memcpy( mac_header + 11, &header.length, sizeof( short ) );

  if ( active_suite->new_digest )
  {
    unsigned char *mac_buffer = malloc( 13 + content_len );

    mac = ( unsigned char * ) malloc( active_suite->hash_size );
    active_suite->new_digest( &digest );

    memcpy( mac_buffer, mac_header, 13 );
    memcpy( mac_buffer + 13, content, content_len );
    hmac( parameters->MAC_secret,
          active_suite->hash_size,
          mac_buffer, 13 + content_len,
          &digest );
    memcpy( mac, digest.hash, active_suite->hash_size );

    free( mac_buffer );
    free( digest.hash );
  }

  send_buffer_size = content_len + active_suite->hash_size;

  if ( active_suite->block_size )
  {
    padding_length = active_suite->block_size -
      ( send_buffer_size % active_suite->block_size );
    send_buffer_size += padding_length;
  }

  // Add space for the header, but only after computing padding
  send_buffer_size += 5;

  send_buffer = ( unsigned char * ) malloc( send_buffer_size );

  if ( mac )
  {
    memcpy( send_buffer + content_len + 5, mac, active_suite->hash_size );
    free( mac );
  }

  if ( padding_length > 0 )
  {
    unsigned char *padding;
    for ( padding = send_buffer + send_buffer_size - 1;
          padding > ( send_buffer + ( send_buffer_size - padding_length - 1 ) );
          padding-- )
    {
      *padding = ( padding_length - 1 );
    }
  }

  header.length = htons( content_len + active_suite->hash_size +
    padding_length );
  send_buffer[ 0 ] = header.type;
  send_buffer[ 1 ] = header.version.major;
  send_buffer[ 2 ] = header.version.minor;
  memcpy( send_buffer + 3, &header.length, sizeof( short ) );
  memcpy( send_buffer + 5, content, content_len );

  if ( active_suite->bulk_encrypt || active_suite->aead_encrypt )
  {
    unsigned char *encrypted_buffer;
    int explicit_iv_len = 0;

#if TLS_VERSION_MINOR >= 2
    // TLS 1.1+ sends the CBC IV in front of each record instead of
    // chaining it from the previous record
    if ( active_suite->aead_encrypt )
    {
      explicit_iv_len = AEAD_EXPLICIT_NONCE_LEN;
    }
    else if ( active_suite->block_size )
    {
      explicit_iv_len = active_suite->IV_size;
    }
#endif

    encrypted_buffer = malloc( send_buffer_size + explicit_iv_len );
    // The first 5 bytes (the header) and the IV aren't encrypted
    memcpy( encrypted_buffer, send_buffer, 5 );
    header.length = htons( send_buffer_size - 5 + explicit_iv_len );
    memcpy( encrypted_buffer + 3, &header.length, sizeof( short ) );

    if ( active_suite->bulk_encrypt )
    {
      if ( explicit_iv_len )
      {
        random_bytes( parameters->IV, explicit_iv_len );
        memcpy( encrypted_buffer + 5, parameters->IV, explicit_iv_len );
      }
      active_suite->bulk_encrypt( send_buffer + 5, send_buffer_size - 5,
        encrypted_buffer + 5 + explicit_iv_len, parameters->IV,
        parameters->key );
    }
    else
    {
      unsigned char nonce[ 12 ];

      memcpy( nonce, parameters->IV, active_suite->IV_size );
      memcpy( nonce + active_suite->IV_size, mac_header,
        AEAD_EXPLICIT_NONCE_LEN );
      memcpy( encrypted_buffer + 5, mac_header, AEAD_EXPLICIT_NONCE_LEN );
      active_suite->aead_encrypt( send_buffer + 5, content_len,
        mac_header, 13, encrypted_buffer + 5 + explicit_iv_len,
        nonce, parameters->key );
    }

    free( send_buffer );
    send_buffer = encrypted_buffer;
    send_buffer_size += explicit_iv_len;
  }

  if ( send( connection, ( void * ) send_buffer,
       send_buffer_size, 0 ) < send_buffer_size )
  {
    free( send_buffer );
    return -1;
  }

  parameters->seq_num++;

  free( send_buffer );

  return 0;
}

static int send_handshake_message( int connection,
                                   int msg_type,
                                   const unsigned char *message,
                                   int message_len,
                                   TLSParameters *parameters )
{
  Handshake record;
  short send_buffer_size;
  unsigned char *send_buffer;
  int response;

  record.msg_type = msg_type;
  record.length = htons( message_len ) << 8; // To deal with 24-bits...
  send_buffer_size = message_len + 4; // space for the handshake header

  send_buffer = ( unsigned char * ) malloc( send_buffer_size );
  send_buffer[ 0 ] = record.msg_type;
  memcpy( send_buffer + 1, &record.length, 3 );
  memcpy( send_buffer + 4, message, message_len );

  update_digest( &parameters->md5_handshake_digest, send_buffer,
    send_buffer_size );
  update_digest( &parameters->sha256_handshake_digest, send_buffer,
    send_buffer_size );
  update_digest( &parameters->sha1_handshake_digest, send_buffer,
    send_buffer_size );

  response = send_message( connection, content_handshake,
    send_buffer, send_buffer_size, &parameters->active_send_parameters );

  free( send_buffer );

  return response;
}

static int send_alert_message( int connection,
                               int alert_code,
                               ProtectionParameters *parameters )
{
  char buffer[ 2 ];

  // TODO support warnings
  buffer[ 0 ] = fatal;
  buffer[ 1 ] = alert_code;

  return send_message( connection, content_alert, buffer, 2, parameters );
}

// lets the test client offer a different single suite
static unsigned short client_cipher_suite = TLS_RSA_WITH_AES_128_CBC_SHA;

void tls_set_client_cipher_suite( unsigned short suite )
{
  client_cipher_suite = suite;
}

typedef enum
{
  server_name = 0,
  elliptic_curves = 10,       // RFC 4492
  ec_point_formats = 11,      // RFC 4492
  signature_algorithms = 13,  // RFC 5246
  secure_renegotiation = 0xFF01
}
ExtensionType;

typedef enum
{
  secp192r1 = 19,
  secp256r1 = 23
}
named_curve;

typedef enum
{
  explicit_prime = 1,
  explicit_char2 = 2,
  named = 3
}
ec_curve_type;

typedef enum
{
  compressed = 3,
  uncompressed = 4
}
ec_point_type;

static unsigned short add_renegotiation_extension(
                            unsigned char **renegotiation_extension,
                            int renegotiating,
                            TLSParameters *parameters )
{
  unsigned char *write_ptr;
  unsigned char data_length;
  unsigned short renegotiation_length;

  if ( renegotiating )
  {
    renegotiation_length =
      ( parameters->connection_end == connection_end_client ?
        VERIFY_DATA_LEN : ( VERIFY_DATA_LEN * 2 ) );
    write_ptr = *renegotiation_extension = ( unsigned char * ) malloc(
      renegotiation_length + 1 );
    data_length = renegotiation_length;
    write_ptr = append_buffer( write_ptr, ( void * ) &data_length,
      sizeof( unsigned char ) );
    // client_verify_data and server_verify_data are adjacent in TLSParameters
    write_ptr = append_buffer( write_ptr,
      parameters->client_verify_data, renegotiation_length );
    return renegotiation_length + 1;
  }
  else
  {
    renegotiation_length = 1;
    write_ptr = *renegotiation_extension = ( unsigned char * ) malloc(
      renegotiation_length );
    // On an initial handshake client_verify_data is all zeros, so this
    // writes the single length byte 0
    write_ptr = append_buffer( write_ptr,
      parameters->client_verify_data, renegotiation_length );
    return 1;
  }
}

static unsigned char *append_extension( unsigned char *write_ptr,
                                        unsigned short type,
                                        const unsigned char *data,
                                        unsigned short data_length )
{
  unsigned short value;

  value = htons( type );
  write_ptr = append_buffer( write_ptr, ( void * ) &value,
    sizeof( unsigned short ) );
  value = htons( data_length );
  write_ptr = append_buffer( write_ptr, ( void * ) &value,
    sizeof( unsigned short ) );

  return append_buffer( write_ptr, ( void * ) data, data_length );
}

static unsigned short add_client_hello_extensions( unsigned char **extensions,
                                                   TLSParameters *parameters,
                                                   int renegotiating )
{
  unsigned char *write_ptr;
  unsigned char *renegotiation_extension = NULL;
  unsigned short renegotiation_extension_length = 0;
  // RFC 4492 5.1: the named curves and point formats this client handles.
  // without them a server can't tell which curve to pick.
  static const unsigned char supported_curves[] =
    { 0x00, 0x04, 0x00, secp256r1, 0x00, secp192r1 };
  static const unsigned char supported_point_formats[] =
    { 0x01, uncompressed };
#if TLS_VERSION_MINOR >= 3
  // RFC 5246 7.4.1.4.1: without this a TLS 1.2 server assumes SHA-1
  static const unsigned char supported_signature_algorithms[] =
    { 0x00, 0x08, sha256, sig_rsa, sha256, sig_ecdsa,
      sha1, sig_rsa, sha1, sig_ecdsa };
#endif

  if ( parameters->support_secure_renegotiation )
  {
    renegotiation_extension_length =
      add_renegotiation_extension( &renegotiation_extension,
        renegotiating, parameters );
  }

  // 4 bytes of type and length per extension, plus their data
  write_ptr = *extensions = ( unsigned char * ) malloc(
    renegotiation_extension_length + 64 );

  if ( renegotiation_extension )
  {
    write_ptr = append_extension( write_ptr, secure_renegotiation,
      renegotiation_extension, renegotiation_extension_length );
    free( renegotiation_extension );
  }

  write_ptr = append_extension( write_ptr, elliptic_curves,
    supported_curves, sizeof( supported_curves ) );
  write_ptr = append_extension( write_ptr, ec_point_formats,
    supported_point_formats, sizeof( supported_point_formats ) );
#if TLS_VERSION_MINOR >= 3
  write_ptr = append_extension( write_ptr, signature_algorithms,
    supported_signature_algorithms,
    sizeof( supported_signature_algorithms ) );
#endif

  return write_ptr - *extensions;
}

/**
 * Build and submit a TLS client hello handshake on the active
 * connection. It is up to the caller of this function to wait
 * for the server reply.
 */
static int send_client_hello( int connection,
                              TLSParameters *parameters,
                              int renegotiating )
{
  unsigned char *extensions;
  unsigned short extensions_length;
  ClientHello package;
  unsigned short supported_suites[ 1 ];
  unsigned char supported_compression_methods[ 1 ];
  int send_buffer_size;
  char *send_buffer;
  void *write_buffer;
  time_t local_time;
  int status = 1;

  package.client_version.major = TLS_VERSION_MAJOR;
  package.client_version.minor = TLS_VERSION_MINOR;
  time( &local_time );
  package.random.gmt_unix_time = htonl( local_time );
  // This is 28 bytes, but client random is 32 - the first four bytes of
  // "client random" are the GMT unix time computed above.
  memcpy( parameters->client_random, &package.random.gmt_unix_time, 4 );
  random_bytes( parameters->client_random + 4, 28 );
  memcpy( package.random.random_bytes, parameters->client_random + 4, 28 );
  if ( parameters->session_id_length > 0 )
  {
    package.session_id_length = parameters->session_id_length;
    package.session_id = parameters->session_id;
  }
  else
  {
    package.session_id_length = 0;
    package.session_id = NULL;
  }
  // note that this is bytes, not count.
  package.cipher_suites_length = htons( 2 );
  supported_suites[ 0 ] = htons( client_cipher_suite );
  package.cipher_suites = supported_suites;
  package.compression_methods_length = 1;
  supported_compression_methods[ 0 ] = 0;
  package.compression_methods = supported_compression_methods;

  // Compute the size of the ClientHello message after flattening.
  send_buffer_size = sizeof( ProtocolVersion ) +
    sizeof( Random ) +
    sizeof( unsigned char ) +
    ( sizeof( unsigned char ) * package.session_id_length ) +
    sizeof( unsigned short ) +
    ( sizeof( unsigned short ) * 1 ) +
    sizeof( unsigned char ) +
    sizeof( unsigned char );

  extensions_length = add_client_hello_extensions( &extensions,
    parameters, renegotiating );
  if ( extensions_length )
  {
    send_buffer_size += extensions_length + sizeof( unsigned short );
  }

  write_buffer = send_buffer = ( char * ) malloc( send_buffer_size );

  write_buffer = append_buffer( write_buffer, ( void * )
    &package.client_version.major, 1 );
  write_buffer = append_buffer( write_buffer, ( void * )
    &package.client_version.minor, 1 );
  write_buffer = append_buffer( write_buffer, ( void * )
    &package.random.gmt_unix_time, 4 );
  write_buffer = append_buffer( write_buffer, ( void * )
    &package.random.random_bytes, 28 );
  write_buffer = append_buffer( write_buffer, ( void * )
    &package.session_id_length, 1 );
  if ( package.session_id_length > 0 )
  {
    write_buffer = append_buffer( write_buffer,
      ( void * )package.session_id,
      package.session_id_length );
  }
  write_buffer = append_buffer( write_buffer,
    ( void * ) &package.cipher_suites_length, 2 );
  write_buffer = append_buffer( write_buffer,
    ( void * ) package.cipher_suites, 2 );
  write_buffer = append_buffer( write_buffer,
    ( void * ) &package.compression_methods_length, 1 );
  if ( package.compression_methods_length > 0 )
  {
    write_buffer = append_buffer( write_buffer,
      ( void * ) package.compression_methods, 1 );
  }

  if ( extensions_length )
  {
    extensions_length = htons( extensions_length );
    write_buffer = append_buffer( write_buffer, ( void * ) &extensions_length,
      2 );
    write_buffer = append_buffer( write_buffer, ( void * ) extensions,
      ntohs( extensions_length ) );
    free( extensions );
  }

  assert( ( ( char * ) write_buffer - send_buffer ) == send_buffer_size );

  status = send_handshake_message( connection, client_hello, send_buffer,
    send_buffer_size, parameters );

  free( send_buffer );

  return status;
}

/**
 * Compare the server renegotiation data with the stored
 * verify data. If this is the first negotiation attempt,
 * this data should be set to 0.
 */
static int parse_renegotiation_info( const char *read_pos,
                                     const int extension_length,
                                     TLSParameters *parameters )
{
  return !( memcmp( parameters->client_verify_data, read_pos + 1,
    extension_length - 1 ) );
}

static char *parse_server_hello_extensions( char *read_pos,
                                            int extensions_length,
                                            TLSParameters *parameters )
{
  unsigned short advertised_extensions_length;
  unsigned short extension_type;
  unsigned short extension_length;

  parameters->support_secure_renegotiation = 0;

  read_pos = read_buffer( ( void * ) &advertised_extensions_length,
    read_pos, sizeof( unsigned short ) );
  advertised_extensions_length = ntohs( advertised_extensions_length );
  extensions_length -= 2;

  assert( advertised_extensions_length == extensions_length );

  while ( extensions_length )
  {
    read_pos = read_buffer( ( void * ) &extension_type, read_pos,
      sizeof( unsigned short ) );
    read_pos = read_buffer( ( void * ) &extension_length, read_pos,
      sizeof( unsigned short ) );
    extensions_length -= 4;
    extension_type = ntohs( extension_type );
    extension_length = ntohs( extension_length );
    if ( extension_type == secure_renegotiation )
    {
      parameters->support_secure_renegotiation = 1;
      if ( !parse_renegotiation_info( read_pos, extension_length, parameters ) )
      {
        return NULL;
      }
    }
    read_pos += extension_length;
    extensions_length -= extension_length;
  }

  return read_pos;
}

static char *parse_server_hello( char *read_pos,
                                 int pdu_length,
                                 TLSParameters *parameters )
{
  ServerHello hello;
  int extensions_length;
  char *server_hello_begin = read_pos;

  read_pos = read_buffer( ( void * ) &hello.server_version.major,
    ( void * ) read_pos, 1 );
  read_pos = read_buffer( ( void * ) &hello.server_version.minor,
    ( void * ) read_pos, 1 );
  read_pos = read_buffer( ( void * ) &hello.random.gmt_unix_time,
    ( void * ) read_pos, 4 );
  // *DON'T* put this in host order, since it's not used as a time! Just
  // accept it as is
  read_pos = read_buffer( ( void * ) hello.random.random_bytes,
    ( void * ) read_pos, 28 );
  read_pos = read_buffer( ( void * ) &hello.session_id_length,
    ( void * ) read_pos, 1 );
  read_pos = read_buffer( ( void * ) hello.session_id,
    ( void * ) read_pos, hello.session_id_length );
  read_pos = read_buffer( ( void * ) &hello.cipher_suite,
    ( void * ) read_pos, 2 );
  hello.cipher_suite = ntohs( hello.cipher_suite );

  // TODO check that these values were actually in the client hello
  // list.
  parameters->pending_recv_parameters.suite = hello.cipher_suite;
  parameters->pending_send_parameters.suite = hello.cipher_suite;

  read_pos = read_buffer( ( void * ) &hello.compression_method,
    ( void * ) read_pos, 1 );
  if ( hello.compression_method != 0 )
  {
    fprintf( stderr, "Error, server wants compression.\n" );
    return NULL;
  }

  // TODO - abort if version < 3.1 with "protocol_version" alert error

  extensions_length = pdu_length - ( read_pos - server_hello_begin );
  if ( extensions_length )
  {
    read_pos = parse_server_hello_extensions( read_pos, extensions_length,
      parameters );
    // Abort the handshake if the extensions didn't parse.
    if ( read_pos == NULL )
    {
      return NULL;
    }
  }

  // 28 random bytes, but the preceding four bytes are the reported GMT unix
  // time
  memcpy( ( void * ) parameters->server_random,
    &hello.random.gmt_unix_time, 4 );
  memcpy( ( void * ) ( parameters->server_random + 4 ),
    ( void * ) hello.random.random_bytes, 28 );

  parameters->session_id_length = hello.session_id_length;
  memcpy( parameters->session_id, hello.session_id, hello.session_id_length );
  parameters->got_server_hello = 1;

  return read_pos;
}

/**
 * 6.3: Compute a key block, including MAC secrets, keys, and IVs for client & server.
 * Notice that the seed is server random followed by client random (whereas for
 * master secret computation, it's client random followed by server random).
 * Sheesh!
 */
static void calculate_keys( TLSParameters *parameters )
{
  // XXX assuming send suite & recv suite will always be the same
  CipherSuite *suite = &( suites[ parameters->pending_send_parameters.suite ] );
  const char *label = "key expansion";
  int mac_key_size = suite->new_digest ? suite->hash_size : 0;
  int key_block_length =
    mac_key_size * 2 +
    suite->key_size * 2 +
    suite->IV_size * 2;
  char seed[ RANDOM_LENGTH * 2 ];
  unsigned char *key_block = ( unsigned char * ) malloc( key_block_length );
  unsigned char *key_block_ptr;

  ProtectionParameters *send_parameters = &parameters->pending_send_parameters;
  ProtectionParameters *recv_parameters = &parameters->pending_recv_parameters;

  memcpy( seed, parameters->server_random, RANDOM_LENGTH );
  memcpy( seed + RANDOM_LENGTH, parameters->client_random, RANDOM_LENGTH );

  PRF( parameters->master_secret, MASTER_SECRET_LENGTH,
    label, strlen( label ),
    seed, RANDOM_LENGTH * 2,
    key_block, key_block_length );

  send_parameters->MAC_secret = ( unsigned char * ) malloc( mac_key_size );
  recv_parameters->MAC_secret = ( unsigned char * ) malloc( mac_key_size );
  send_parameters->key = ( unsigned char * ) malloc( suite->key_size );
  recv_parameters->key = ( unsigned char * ) malloc( suite->key_size );
  send_parameters->IV = ( unsigned char * ) malloc( suite->IV_size );
  recv_parameters->IV = ( unsigned char * ) malloc( suite->IV_size );

  if ( parameters->connection_end == connection_end_client )
  {
    key_block_ptr = read_buffer( send_parameters->MAC_secret, key_block,
      mac_key_size );
    key_block_ptr = read_buffer( recv_parameters->MAC_secret, key_block_ptr,
      mac_key_size );
    key_block_ptr = read_buffer( send_parameters->key, key_block_ptr,
      suite->key_size );
    key_block_ptr = read_buffer( recv_parameters->key, key_block_ptr,
      suite->key_size );
    key_block_ptr = read_buffer( send_parameters->IV, key_block_ptr,
      suite->IV_size );
    key_block_ptr = read_buffer( recv_parameters->IV, key_block_ptr,
      suite->IV_size );
  }
  else // I'm the server
  {
    key_block_ptr = read_buffer( recv_parameters->MAC_secret, key_block,
      mac_key_size );
    key_block_ptr = read_buffer( send_parameters->MAC_secret, key_block_ptr,
      mac_key_size );
    key_block_ptr = read_buffer( recv_parameters->key, key_block_ptr,
      suite->key_size );
    key_block_ptr = read_buffer( send_parameters->key, key_block_ptr,
      suite->key_size );
    key_block_ptr = read_buffer( recv_parameters->IV, key_block_ptr,
      suite->IV_size );
    key_block_ptr = read_buffer( send_parameters->IV, key_block_ptr,
      suite->IV_size );
  }

  switch ( suite->id )
  {
    case TLS_RSA_EXPORT_WITH_RC4_40_MD5:
    case TLS_RSA_WITH_RC4_128_MD5:
    case TLS_RSA_WITH_RC4_128_SHA:
    case TLS_DH_anon_EXPORT_WITH_RC4_40_MD5:
    case TLS_DH_anon_WITH_RC4_128_MD5:
    case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
      {
        rc4_state *read_state = malloc( sizeof( rc4_state ) );
        rc4_state *write_state = malloc( sizeof( rc4_state ) );
        read_state->i = read_state->j = write_state->i = write_state->j = 0;
        send_parameters->IV = ( unsigned char * ) read_state;
        recv_parameters->IV = ( unsigned char * ) write_state;
        memset( read_state->S, '\0', RC4_STATE_ARRAY_LEN );
        memset( write_state->S, '\0', RC4_STATE_ARRAY_LEN );
      }
      break;
    default:
      break;
  }

  free( key_block );
}

/**
 * Turn the premaster secret into an actual master secret (the
 * server side will do this concurrently) as specified in section 8.1:
 * master_secret = PRF( pre_master_secret, "master secret",
 * ClientHello.random + ServerHello.random );
 * ( premaster_secret, parameters );
 * Note that, with DH, the master secret len is determined by the generator (p)
 * value.
 */
static void compute_master_secret( const unsigned char *premaster_secret,
                                   int premaster_secret_len,
                                   TLSParameters *parameters )
{
  const char *label = "master secret";
  PRF( premaster_secret, premaster_secret_len,
       label, strlen( label ),
       // Note - cheating, since client_random & server_random are defined
       // sequentially in the structure
       parameters->client_random, RANDOM_LENGTH * 2,
       parameters->master_secret, MASTER_SECRET_LENGTH );
}

int rsa_key_exchange( rsa_key *public_key,
                      unsigned char *premaster_secret,
                      unsigned char **key_exchange_message )
{
  int i;
  unsigned char *encrypted_premaster_secret = NULL;
  int encrypted_length;
  unsigned short transmit_len;

  // first two bytes are protocol version
  premaster_secret[ 0 ] = TLS_VERSION_MAJOR;
  premaster_secret[ 1 ] = TLS_VERSION_MINOR;
  random_bytes( premaster_secret + 2, MASTER_SECRET_LENGTH - 2 );

  encrypted_length = rsa_encrypt( premaster_secret, MASTER_SECRET_LENGTH,
    &encrypted_premaster_secret, public_key );

  *key_exchange_message = ( unsigned char * ) malloc( encrypted_length + 2 );
  transmit_len = htons( encrypted_length );
  memcpy( *key_exchange_message, &transmit_len, 2 );
  memcpy( (*key_exchange_message) + 2, encrypted_premaster_secret,
    encrypted_length );

  free( encrypted_premaster_secret );

  return encrypted_length + 2;
}

/**
 * Just compute Yc = g^a % p and return it in "key_exchange_message". The
 * premaster secret is Ys ^ a % p.
 */
int dh_key_exchange( dh_key *server_dh_key,
                     unsigned char *premaster_secret,
                     int *premaster_secret_len,
                     unsigned char **key_exchange_message )
{
  huge Yc;
  huge Z;
  huge a;
  int message_size;
  short transmit_len;

  unsigned char exponent[ 32 ];

  random_bytes( exponent, sizeof( exponent ) );
  load_huge( &a, exponent, sizeof( exponent ) );
  mod_pow( &server_dh_key->g, &a, &server_dh_key->p, &Yc );
  mod_pow( &server_dh_key->Y, &a, &server_dh_key->p, &Z );

  // Now copy Z into premaster secret and Yc into key_exchange_message
  memcpy( premaster_secret, Z.rep, Z.size );
  // RFC 2246 8.1.2 leading zero bytes of Z are stripped, so report Z.size
  *premaster_secret_len = Z.size;
  message_size = Yc.size + 2;
  transmit_len = htons( Yc.size );
  *key_exchange_message = malloc( message_size );
  memcpy( *key_exchange_message, &transmit_len, 2 );
  memcpy( *key_exchange_message + 2, Yc.rep, Yc.size );

  free_huge( &Yc );
  free_huge( &Z );
  free_huge( &a );

  return message_size;
}

/**
 * ECDH counterpart of dh_key_exchange: send A.Q = d * G and
 * use the x coordinate of d * (server point) as the premaster secret.
 * premaster_secret must have room for the curve's field size (p.size).
 */
int ecdh_key_exchange( point *server_ecdh_key,
                       elliptic_curve *curve,
                       unsigned char *premaster_secret,
                       unsigned char **key_exchange_message )
{
  ecc_key A;
  point K;
  int coordinate_length = curve->p.size;

  random_huge_below( &A.d, &curve->n );
  set_huge( &A.Q.x, 0 );
  set_huge( &A.Q.y, 0 );
  copy_huge( &A.Q.x, &curve->G.x );
  copy_huge( &A.Q.y, &curve->G.y );
  multiply_point( &A.Q, &A.d, &curve->a, &curve->p );
  contract( &A.Q.x );
  contract( &A.Q.y );

  // Response is now A.Q; put that into "key_exchange_message" as an
  // uncompressed X9.62 point, preceded by its one-byte length.
  *key_exchange_message = ( unsigned char * ) malloc(
    coordinate_length * 2 + 2 );
  memset( *key_exchange_message, '\0', coordinate_length * 2 + 2 );
  (*key_exchange_message)[ 0 ] = coordinate_length * 2 + 1;
  (*key_exchange_message)[ 1 ] = uncompressed;
  memcpy( (*key_exchange_message) + 2 + coordinate_length - A.Q.x.size,
    A.Q.x.rep, A.Q.x.size );
  memcpy( (*key_exchange_message) + 2 + coordinate_length * 2 - A.Q.y.size,
    A.Q.y.rep, A.Q.y.size );

  // Now compute the premaster secret from the server's point
  set_huge( &K.x, 0 );
  set_huge( &K.y, 0 );
  copy_huge( &K.x, &server_ecdh_key->x );
  copy_huge( &K.y, &server_ecdh_key->y );
  multiply_point( &K, &A.d, &curve->a, &curve->p );
  contract( &K.x );

  // The premaster secret is K.x, padded to the field size
  memset( premaster_secret, '\0', coordinate_length );
  memcpy( premaster_secret + coordinate_length - K.x.size, K.x.rep,
    K.x.size );

  free_huge( &K.x );
  free_huge( &K.y );
  free_huge( &A.d );
  free_huge( &A.Q.x );
  free_huge( &A.Q.y );

  return coordinate_length * 2 + 2;
}

static int is_ecdhe_suite( int suite )
{
  switch ( suite )
  {
    case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
    case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
    case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
      return 1;
    default:
      return 0;
  }
}

/**
 * Send the client key exchange message, as detailed in section 7.4.7
 * Use the server's public key (if it has one) to encrypt a key. (or DH?)
 * Return true if this succeeded, false otherwise.
 */
static int send_client_key_exchange( int connection, TLSParameters *parameters )
{
  unsigned char *key_exchange_message;
  int key_exchange_message_len;
  unsigned char *premaster_secret;
  int premaster_secret_len;

  switch ( parameters->pending_send_parameters.suite ) {
    case TLS_NULL_WITH_NULL_NULL:
      // XXX this is an error, exit here
      return 0;
    case TLS_RSA_WITH_NULL_MD5:
    case TLS_RSA_WITH_NULL_SHA:
    case TLS_RSA_EXPORT_WITH_RC4_40_MD5:
    case TLS_RSA_WITH_RC4_128_MD5:
    case TLS_RSA_WITH_RC4_128_SHA:
    case TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5:
    case TLS_RSA_WITH_IDEA_CBC_SHA:
    case TLS_RSA_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_RSA_WITH_DES_CBC_SHA:
    case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
    case TLS_RSA_WITH_AES_128_CBC_SHA:
    case TLS_RSA_WITH_AES_256_CBC_SHA:
    case TLS_RSA_WITH_AES_128_GCM_SHA256:
      premaster_secret_len = MASTER_SECRET_LENGTH;
      premaster_secret = malloc( premaster_secret_len );
      key_exchange_message_len = rsa_key_exchange(
        &parameters->server_public_key.rsa_public_key,
        premaster_secret, &key_exchange_message );
      break;
    case TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DH_DSS_WITH_DES_CBC_SHA:
    case TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
    case TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DH_RSA_WITH_DES_CBC_SHA:
    case TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
    case TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DHE_DSS_WITH_DES_CBC_SHA:
    case TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
    case TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DHE_RSA_WITH_DES_CBC_SHA:
    case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
    case TLS_DH_anon_EXPORT_WITH_RC4_40_MD5:
    case TLS_DH_anon_WITH_RC4_128_MD5:
    case TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DH_anon_WITH_DES_CBC_SHA:
    case TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:
    case TLS_DH_DSS_WITH_AES_128_CBC_SHA:
    case TLS_DH_RSA_WITH_AES_128_CBC_SHA:
    case TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
    case TLS_DH_anon_WITH_AES_128_CBC_SHA:
    case TLS_DH_DSS_WITH_AES_256_CBC_SHA:
    case TLS_DH_RSA_WITH_AES_256_CBC_SHA:
    case TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
    case TLS_DH_anon_WITH_AES_256_CBC_SHA:
      premaster_secret_len = parameters->server_dh_key.p.size;
      premaster_secret = malloc( premaster_secret_len );
      key_exchange_message_len = dh_key_exchange( &parameters->server_dh_key,
        premaster_secret, &premaster_secret_len, &key_exchange_message );
      break;
    case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
    case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
    case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
      premaster_secret_len = parameters->server_ecdh_params.p.size;
      premaster_secret = malloc( premaster_secret_len );
      key_exchange_message_len = ecdh_key_exchange(
        &parameters->server_ecdh_key, &parameters->server_ecdh_params,
        premaster_secret, &key_exchange_message );
      break;
    default:
      return 0;
  }

  if ( send_handshake_message( connection, client_key_exchange,
       key_exchange_message, key_exchange_message_len, parameters ) )
  {
    free( key_exchange_message );
    return 0;
  }

  free( key_exchange_message );

  // Now, turn the premaster secret into an actual master secret (the
  // server side will do this concurrently).
  compute_master_secret( premaster_secret, premaster_secret_len, parameters );

  // XXX - for security, should also "purge" the premaster secret from
  // memory.
  calculate_keys( parameters );

  free( premaster_secret );

  return 1;
}

static int send_change_cipher_spec( int connection, TLSParameters *parameters )
{
  char send_buffer[ 1 ];
  send_buffer[ 0 ] = 1;

  send_message( connection, content_change_cipher_spec, send_buffer, 1,
    &parameters->active_send_parameters );

  // Per 6.1: The sequence number must be set to zero whenever a connection
  // state is made the active state... the first record which is transmitted
  // under a particular connection state should use sequence number 0.
  parameters->pending_send_parameters.seq_num = 0;

  memcpy( &parameters->active_send_parameters,
          &parameters->pending_send_parameters,
          sizeof( ProtectionParameters ) );

  init_protection_parameters( &parameters->pending_send_parameters );

  return 1;
}

/**
 * Finalize a copy of the running handshake digest(s) into handshake_hash
 * and return its length: MD5 + SHA-1 (36 bytes) for TLS 1.0, SHA-256
 * (32 bytes) for TLS 1.2.
 */
int compute_handshake_hash( TLSParameters *parameters,
                            unsigned char *handshake_hash )
{
#if TLS_VERSION_MINOR >= 3
  digest_ctx tmp_sha256_handshake_digest;

  memcpy( &tmp_sha256_handshake_digest, &parameters->sha256_handshake_digest,
    sizeof( digest_ctx ) );
  tmp_sha256_handshake_digest.hash =
    ( unsigned int * ) malloc( SHA256_BYTE_SIZE );
  memcpy( tmp_sha256_handshake_digest.hash,
    parameters->sha256_handshake_digest.hash, SHA256_BYTE_SIZE );
  finalize_digest( &tmp_sha256_handshake_digest );
  memcpy( handshake_hash, tmp_sha256_handshake_digest.hash, SHA256_BYTE_SIZE );
  free( tmp_sha256_handshake_digest.hash );

  return SHA256_BYTE_SIZE;
#else
  digest_ctx tmp_md5_handshake_digest;
  digest_ctx tmp_sha1_handshake_digest;

  // "cheating". Copy the handshake digests into local memory (and change
  // the hash pointer) so that we can finalize twice (again in "recv")
  memcpy( &tmp_md5_handshake_digest, &parameters->md5_handshake_digest,
    sizeof( digest_ctx ) );
  memcpy( &tmp_sha1_handshake_digest, &parameters->sha1_handshake_digest,
    sizeof( digest_ctx ) );

  tmp_md5_handshake_digest.hash = ( unsigned int * ) malloc( MD5_BYTE_SIZE );
  tmp_sha1_handshake_digest.hash = ( unsigned int * ) malloc( SHA1_BYTE_SIZE );

  memcpy( tmp_md5_handshake_digest.hash, parameters->md5_handshake_digest.hash,
    MD5_BYTE_SIZE );
  memcpy( tmp_sha1_handshake_digest.hash,
    parameters->sha1_handshake_digest.hash, SHA1_BYTE_SIZE );

  finalize_digest( &tmp_md5_handshake_digest );
  finalize_digest( &tmp_sha1_handshake_digest );

  memcpy( handshake_hash, tmp_md5_handshake_digest.hash, MD5_BYTE_SIZE );
  memcpy( handshake_hash + MD5_BYTE_SIZE, tmp_sha1_handshake_digest.hash,
    SHA1_BYTE_SIZE );

  free( tmp_md5_handshake_digest.hash );
  free( tmp_sha1_handshake_digest.hash );

  return MD5_BYTE_SIZE + SHA1_BYTE_SIZE;
#endif
}

/**
 * 7.4.9:
 * verify_data = PRF( master_secret, "client finished", MD5(handshake_messages)
 * + SHA-1(handshake_messages)) [0..11]
 *
 * master_secret = PRF( pre_master_secret, "master secret", ClientHello.random +
 * ServerHello.random );
 * always 48 bytes in length.
 */

static void compute_verify_data( const char *finished_label,
                                 TLSParameters *parameters,
                                 char *verify_data )
{
  // Per 6.2.3.1 - encrypted data should always be followed by a MAC
  unsigned char handshake_hash[ ( MD5_RESULT_SIZE * sizeof( int ) ) +
                                ( SHA1_RESULT_SIZE * sizeof( int ) ) ];

  int handshake_hash_len;

  handshake_hash_len = compute_handshake_hash( parameters, handshake_hash );

  // First, compute the verify data
  PRF( parameters->master_secret, MASTER_SECRET_LENGTH,
       finished_label, strlen( finished_label ),
       handshake_hash, handshake_hash_len,
       verify_data, VERIFY_DATA_LEN );
}

static int send_finished( int connection,
                          TLSParameters *parameters )
{
  unsigned char verify_data[ VERIFY_DATA_LEN ];

  compute_verify_data(
    parameters->connection_end == connection_end_client ?
      "client finished" : "server finished",
    parameters, verify_data );

  // Record the verify data for later secure renegotiation
  memcpy( parameters->connection_end == connection_end_client ?
    parameters->client_verify_data : parameters->server_verify_data,
    verify_data, VERIFY_DATA_LEN );

  send_handshake_message( connection, finished, verify_data, VERIFY_DATA_LEN,
    parameters );

  return 1;
}

static unsigned char *parse_finished( unsigned char *read_pos,
                                      int pdu_length,
                                      TLSParameters *parameters )
{
  unsigned char verify_data[ VERIFY_DATA_LEN ];

  parameters->peer_finished = 1;

  compute_verify_data(
    parameters->connection_end == connection_end_client ?
    "server finished" : "client finished",
    parameters, verify_data );

  // Record the verify data for later secure renegotiation
  memcpy( parameters->connection_end == connection_end_client ?
    parameters->server_verify_data : parameters->client_verify_data,
    verify_data, VERIFY_DATA_LEN );

  if ( memcmp( read_pos, verify_data, VERIFY_DATA_LEN ) )
  {
    return NULL;
  }

  return read_pos + pdu_length;
}


typedef enum
{
  host_name = 0
}
NameType;

static void parse_server_name_extension( unsigned char *data,
                                         unsigned short data_len,
                                         TLSParameters *parameters )
{
  unsigned short server_name_list_len;
  unsigned char name_type;
  unsigned char *data_start;

  data = read_buffer( ( void * ) &server_name_list_len, ( void * ) data, 2 );
  server_name_list_len = ntohs( server_name_list_len );
  data_start = data;

  data = read_buffer( ( void * ) &name_type, ( void * ) data, 1 );

  switch ( name_type )
  {
    case host_name:
      {
        unsigned short host_name_len;
        unsigned char *host_name;
        data = read_buffer( ( void * ) &host_name_len,
          ( void * ) data, 2 );
        host_name_len = ntohs( host_name_len );
        host_name = malloc( host_name_len + 1 );
        data = read_buffer( ( void * ) host_name,
          ( void * ) data, host_name_len );
        host_name[ host_name_len ] = '\0';
        printf( "got host name '%s'\n", host_name );
        // TODO store this and use it to select a certificate
        // TODO return an "unrecognized_name" alert if the host name
        // is unknown
        free( host_name );
      }
      break;
    default:
      // nothing else defined by the spec
      break;
  }
}

static char *parse_client_hello_extensions( char *read_pos,
                                            TLSParameters *parameters )
{
  unsigned short extensions_size, extension_data_size;
  char *init_pos;
  unsigned short type;

  read_pos = read_buffer( ( void * ) &extensions_size, ( void * ) read_pos, 2 );
  extensions_size = ntohs( extensions_size );
  init_pos = read_pos;

  while ( ( read_pos - init_pos ) < extensions_size )
  {
    read_pos = read_buffer( ( void * ) &type, ( void * ) read_pos, 2 );
    read_pos = read_buffer( ( void * ) &extension_data_size,
      ( void * ) read_pos, 2 );
    type = ntohs( type );
    extension_data_size = ntohs( extension_data_size );
    switch ( type )
    {
      case server_name:
        parse_server_name_extension( read_pos, extension_data_size,
          parameters );
        printf( "Got server name extension\n" );
        break;
      default:
        printf( "warning, skipping unsupported client hello extension %d\n",
          type );
        break;
    }
    read_pos += extension_data_size;
  }

  return read_pos;
}

#define HASH_TABLE_SIZE 100

typedef struct StoredSessionsList_t
{
  int session_id_length;
  unsigned char session_id[ MAX_SESSION_ID_LENGTH ];
  unsigned char master_secret[ MASTER_SECRET_LENGTH ];
  struct StoredSessionsList_t *next;
}
StoredSessionsList;

static StoredSessionsList *stored_sessions[ HASH_TABLE_SIZE ];

static void init_cipher_suite( CipherSuiteIdentifier id,
                               int block_size,
                               int IV_size,
                               int key_size,
                               int hash_size,
                               void (*bulk_encrypt)( const unsigned char *,
                                 const int, unsigned char[], void *,
                                 const unsigned char * ),
                               void (*bulk_decrypt)( const unsigned char *,
                                 const int, unsigned char[], void *,
                                 const unsigned char * ),
                               void (*new_digest)( digest_ctx * ),
                               int (*aead_encrypt)( const unsigned char *,
                                 const int, const unsigned char *, const int,
                                 unsigned char[], void *,
                                 const unsigned char * ),
                               int (*aead_decrypt)( const unsigned char *,
                                 const int, const unsigned char *, const int,
                                 unsigned char[], void *,
                                 const unsigned char * ) )
{
  suites[ id ].id = id;
  suites[ id ].block_size = block_size;
  suites[ id ].IV_size = IV_size;
  suites[ id ].key_size = key_size;
  suites[ id ].hash_size = hash_size;
  suites[ id ].bulk_encrypt = bulk_encrypt;
  suites[ id ].bulk_decrypt = bulk_decrypt;
  suites[ id ].new_digest = new_digest;
  suites[ id ].aead_encrypt = aead_encrypt;
  suites[ id ].aead_decrypt = aead_decrypt;
}

/**
 * Must be called once at startup, by clients and servers: sets up the
 * session cache and the cipher suites past 0x3A.
 */
void init_tls()
{
  int i = 0;
  for ( i = 0; i < HASH_TABLE_SIZE; i++ )
  {
    stored_sessions[ i ] = NULL;
  }

  // Extra cipher suites not previously declared
  init_cipher_suite( TLS_RSA_WITH_AES_128_GCM_SHA256, 0, 4, 16, 16,
    NULL, NULL, NULL, aes_gcm_encrypt, aes_gcm_decrypt );
  init_cipher_suite( TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, 0, 0, 16,
    SHA1_BYTE_SIZE, rc4_128_encrypt, rc4_128_decrypt, new_sha1_digest,
    NULL, NULL );
  init_cipher_suite( TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, 8, 8, 24,
    SHA1_BYTE_SIZE, des3_encrypt, des3_decrypt, new_sha1_digest,
    NULL, NULL );
  init_cipher_suite( TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, 16, 16, 16,
    SHA1_BYTE_SIZE, aes_128_encrypt, aes_128_decrypt, new_sha1_digest,
    NULL, NULL );
  init_cipher_suite( TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, 16, 16, 32,
    SHA1_BYTE_SIZE, aes_256_encrypt, aes_256_decrypt, new_sha1_digest,
    NULL, NULL );
  init_cipher_suite( TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 16, 16, 16,
    SHA1_BYTE_SIZE, aes_128_encrypt, aes_128_decrypt, new_sha1_digest,
    NULL, NULL );
  init_cipher_suite( TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, 16, 16, 32,
    SHA1_BYTE_SIZE, aes_256_encrypt, aes_256_decrypt, new_sha1_digest,
    NULL, NULL );
}

/**
 * Store the session in the stored sessions cache
 */
static void remember_session( TLSParameters *parameters )
{
  if ( parameters->session_id_length > 0 )
  {
    int session_id;
    StoredSessionsList *head;
    memcpy( &session_id, parameters->session_id, sizeof( int ) );
    session_id &= 0x7FFFFFFF;
    head = stored_sessions[ session_id % HASH_TABLE_SIZE ];
    if ( head == NULL )
    {
      head = stored_sessions[ session_id % HASH_TABLE_SIZE ] =
        malloc( sizeof( StoredSessionsList ) );
    }
    else
    {
      while ( head->next != NULL )
      {
        head = ( StoredSessionsList * ) head->next;
      }
      head->next = malloc( sizeof( StoredSessionsList ) );
      head = ( StoredSessionsList * ) head->next;
    }

    head->session_id_length = parameters->session_id_length;
    memcpy( head->session_id, parameters->session_id,
      head->session_id_length );
    memcpy( head->master_secret, parameters->master_secret,
      MASTER_SECRET_LENGTH );
    head->next = NULL;
  }
}

/**
 * Check to see if the requested session ID is stored in the local cache.
 * If the session ID is recognized, parameters will be updated to include
 * it, and the master secret will be stored in the parameters.
 * If it is not recognized, the session
 * ID in the parameters will be left empty, indicating that a new handshake
 * should commence.
 */
static void find_stored_session( int session_id_length,
                                 const unsigned char *session_id,
                                 TLSParameters *parameters )
{
  int session_id_num;
  StoredSessionsList *head;

  if ( session_id_length != MAX_SESSION_ID_LENGTH )
  {
    // Definitely didn't come from this server.
    return;
  }

  // The first four bytes are random, so they serve as the hash
  memcpy( &session_id_num, session_id, sizeof( int ) );
  session_id_num &= 0x7FFFFFFF;

  for ( head = stored_sessions[ session_id_num % HASH_TABLE_SIZE ];
        head != NULL;
        head = ( StoredSessionsList * ) head->next )
  {
    if ( head->session_id_length == session_id_length &&
         !memcmp( session_id, head->session_id, session_id_length ) )
    {
      parameters->session_id_length = session_id_length;
      memcpy( parameters->session_id, head->session_id, session_id_length );
      memcpy( parameters->master_secret, head->master_secret,
        MASTER_SECRET_LENGTH );
      break;
    }
  }
}

/**
 * the server only implements RSA key exchange.
 */
static int server_supports_suite( unsigned short id )
{
  switch ( id )
  {
    case TLS_RSA_WITH_RC4_128_MD5:
    case TLS_RSA_WITH_RC4_128_SHA:
    case TLS_RSA_WITH_DES_CBC_SHA:
    case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
    case TLS_RSA_WITH_AES_128_CBC_SHA:
    case TLS_RSA_WITH_AES_256_CBC_SHA:
      return 1;
#if TLS_VERSION_MINOR >= 3
    case TLS_RSA_WITH_AES_128_GCM_SHA256:
      return 1;
#endif
    default:
      return 0;
  }
}

static char *parse_client_hello( char *read_pos,
                                 int pdu_length,
                                 TLSParameters *parameters )
{
  int i;
  ClientHello hello;
  char *init_pos;

  init_pos = read_pos; // keep track of start to check for extensions

  read_pos = read_buffer( ( void * ) &hello.client_version.major,
    ( void * ) read_pos, 1 );
  read_pos = read_buffer( ( void * ) &hello.client_version.minor,
    ( void * ) read_pos, 1 );
  read_pos = read_buffer( ( void * ) &hello.random.gmt_unix_time,
    ( void * ) read_pos, 4 );
  // *DON'T* put this in host order, since it's not used as a time! Just
  // accept it as is
  read_pos = read_buffer( ( void * ) hello.random.random_bytes,
    ( void * ) read_pos, 28 );
  read_pos = read_buffer( ( void * ) &hello.session_id_length,
    ( void * ) read_pos, 1 );
  hello.session_id = NULL;
  if ( hello.session_id_length > 0 )
  {
    hello.session_id = ( unsigned char * ) malloc( hello.session_id_length );
    read_pos = read_buffer( ( void * ) hello.session_id, ( void * ) read_pos,
      hello.session_id_length );
    // TODO if this is non-empty, the client is trying to trigger a restart
  }
  read_pos = read_buffer( ( void * ) &hello.cipher_suites_length,
    ( void * ) read_pos, 2 );
  hello.cipher_suites_length = ntohs( hello.cipher_suites_length );
  hello.cipher_suites = ( unsigned short * ) malloc( hello.cipher_suites_length );
  read_pos = read_buffer( ( void * ) hello.cipher_suites,
                          ( void * ) read_pos,
                          hello.cipher_suites_length );
  read_pos = read_buffer( ( void * ) &hello.compression_methods_length,
    ( void * ) read_pos, 1 );
  hello.compression_methods = ( unsigned char * ) malloc(
    hello.compression_methods_length );
  read_pos = read_buffer( ( void * ) hello.compression_methods,
                          ( void * ) read_pos,
                          hello.compression_methods_length );

  for ( i = 0; i < hello.cipher_suites_length / 2; i++ )
  {
    hello.cipher_suites[ i ] = ntohs( hello.cipher_suites[ i ] );
    if ( server_supports_suite( hello.cipher_suites[ i ] ) )
    {
      parameters->pending_recv_parameters.suite = hello.cipher_suites[ i ];
      parameters->pending_send_parameters.suite = hello.cipher_suites[ i ];
      break;
    }
  }

  if ( i == hello.cipher_suites_length / 2 )
  {
    return NULL;
  }

  parameters->got_client_hello = 1;

  memcpy( ( void * ) parameters->client_random,
    &hello.random.gmt_unix_time, 4 );
  memcpy( ( void * ) ( parameters->client_random + 4 ),
    ( void * ) hello.random.random_bytes, 28 );

  free( hello.cipher_suites );
  free( hello.compression_methods );

  if ( hello.session_id_length > 0 )
  {
    find_stored_session( hello.session_id_length, hello.session_id,
      parameters );
  }

  if ( hello.session_id )
  {
    free( hello.session_id );
  }

  // Parse client hello extensions
  if ( ( read_pos - init_pos ) < pdu_length )
  {
    read_pos = parse_client_hello_extensions( read_pos, parameters );
  }

  return read_pos;
}

static int next_session_id = 1;

static int send_server_hello( int connection, TLSParameters *parameters )
{
  ServerHello package;
  int send_buffer_size;
  char *send_buffer;
  void *write_buffer;
  time_t local_time;

  package.server_version.major = TLS_VERSION_MAJOR;
  package.server_version.minor = TLS_VERSION_MINOR;
  time( &local_time );
  package.random.gmt_unix_time = htonl( local_time );
  // This is 28 bytes, but server random is 32 - the first four bytes of
  // "server random" are the GMT unix time computed above.
  memcpy( parameters->server_random, &package.random.gmt_unix_time, 4 );
  random_bytes( parameters->server_random + 4, 28 );
  memcpy( package.random.random_bytes, parameters->server_random + 4, 28 );
  if ( parameters->session_id_length == 0 )
  {
    // Assign a new session ID
    random_bytes( parameters->session_id, MAX_SESSION_ID_LENGTH );
    parameters->session_id_length = MAX_SESSION_ID_LENGTH;
  }
  package.session_id_length = parameters->session_id_length;
  memcpy( package.session_id, parameters->session_id,
    parameters->session_id_length );
  package.cipher_suite = htons( parameters->pending_send_parameters.suite );
  package.compression_method = 0;

  send_buffer_size = sizeof( ProtocolVersion ) +
    sizeof( Random ) +
    sizeof( unsigned char ) +
    ( sizeof( unsigned char ) * package.session_id_length ) +
    sizeof( unsigned short ) +
    sizeof( unsigned char );

  write_buffer = send_buffer = ( char * ) malloc( send_buffer_size );

  write_buffer = append_buffer( write_buffer,
    ( void * ) &package.server_version.major, 1 );
  write_buffer = append_buffer( write_buffer,
    ( void * ) &package.server_version.minor, 1 );
  write_buffer = append_buffer( write_buffer,
    ( void * ) &package.random.gmt_unix_time, 4 );
  write_buffer = append_buffer( write_buffer,
    ( void * ) &package.random.random_bytes, 28 );
  write_buffer = append_buffer( write_buffer,
    ( void * ) &package.session_id_length, 1 );
  if ( package.session_id_length > 0 )
  {
    write_buffer = append_buffer( write_buffer, ( void * )package.session_id,
      package.session_id_length );
  }
  write_buffer = append_buffer( write_buffer,
    ( void * ) &package.cipher_suite, 2 );
  write_buffer = append_buffer( write_buffer,
    ( void * ) &package.compression_method, 1 );

  assert( ( ( char * ) write_buffer - send_buffer ) == send_buffer_size );

  send_handshake_message( connection, server_hello, send_buffer,
    send_buffer_size, parameters );

  free( send_buffer );

  return 0;
}

static int send_certificate( int connection, TLSParameters *parameters )
{
  short send_buffer_size;
  unsigned char *send_buffer, *read_buffer;
  int certificate_file;
  struct stat certificate_stat;
  short cert_len;

  if ( ( certificate_file = open( "cert.der", O_RDONLY ) ) == -1 )
  {
    perror( "unable to load certificate file" );
    return 1;
  }

  if ( fstat( certificate_file, &certificate_stat ) == -1 )
  {
    perror( "unable to stat certificate file" );
    return 1;
  }

  // Allocate enough space for the certificate file, plus 2 3-byte length
  // entries.
  send_buffer_size = certificate_stat.st_size + 6;
  send_buffer = ( unsigned char * ) malloc( send_buffer_size );
  memset( send_buffer, '\0', send_buffer_size );
  cert_len = certificate_stat.st_size + 3;
  cert_len = htons( cert_len );
  memcpy( ( void * ) ( send_buffer + 1 ), &cert_len, 2 );
  cert_len = certificate_stat.st_size;
  cert_len = htons( cert_len );
  memcpy( ( void * ) ( send_buffer + 4 ), &cert_len, 2 );

  read_buffer = send_buffer + 6;
  cert_len = certificate_stat.st_size;

  while ( ( read_buffer - send_buffer ) < send_buffer_size )
  {
    int read_size;
    read_size = read( certificate_file, read_buffer, cert_len );
    read_buffer += read_size;
    cert_len -= read_size;
  }

  if ( close( certificate_file ) == -1 )
  {
    perror( "unable to close certificate file" );
    return 1;
  }

  send_handshake_message( connection, certificate, send_buffer,
    send_buffer_size, parameters );

  free( send_buffer );

  return 0;
}

static int send_server_hello_done( int connection, TLSParameters *parameters )
{
  send_handshake_message( connection, server_hello_done, NULL, 0, parameters );

  return 0;
}

/**
 * By the time this is called, "read_pos" points at an RSA encrypted (unless
 * RSA isn't used for key exchange) premaster secret. All this routine has to
 * do is decrypt it. See "privkey.c" for details.
 * TODO expand this to support Diffie-Hellman key exchange
 */
static unsigned char *parse_client_key_exchange( unsigned char *read_pos,
                                                 int pdu_length,
                                                 TLSParameters *parameters )
{
  int premaster_secret_length;
  unsigned char *buffer;
  int buffer_length;
  unsigned char *premaster_secret;
  rsa_key private_key;

  // TODO make this configurable
  // XXX this really really should be buffered
  if ( !( buffer = load_file_into_memory( "key.pkcs8", &buffer_length ) ) )
  {
    perror( "Unable to load file" );
    return 0;
  }

  parse_pkcs8_private_key( &private_key, buffer, buffer_length, "password" );
  free( buffer );

  // Skip over the two length bytes, since length is already known anyway
  premaster_secret_length = rsa_decrypt( read_pos + 2, pdu_length - 2,
    &premaster_secret, &private_key );

  if ( premaster_secret_length <= 0 )
  {
    fprintf( stderr, "Unable to decrypt premaster secret.\n" );
    return NULL;
  }

  free_huge( private_key.modulus );
  free_huge( private_key.exponent );
  free( private_key.modulus );
  free( private_key.exponent );

  // Now use the premaster secret to compute the master secret. Don't forget
  // that the first two bytes of the premaster secret are the version 0x03 0x01
  // These are part of the premaster secret (8.1.1 states that the premaster
  // secret for RSA is exactly 48 bytes long).
  compute_master_secret( premaster_secret, MASTER_SECRET_LENGTH, parameters );

  calculate_keys( parameters );

  free( premaster_secret );

  return read_pos + pdu_length;
}

#if TLS_VERSION_MINOR >= 3
static const unsigned char OID_sha1[] =
  { 0x2B, 0x0E, 0x03, 0x02, 0x1A };
static const unsigned char OID_sha256[] =
  { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
#endif

/**
 * Verify the signature on a server key exchange: a hash of client random,
 * server random and the key exchange parameters. hash_alg is only used by
 * TLS 1.2, where the signature names its own hash.
 */
static int verify_signature( unsigned char *message,
                             int message_len,
                             unsigned char *signature,
                             int signature_len,
                             HashAlgorithm hash_alg,
                             TLSParameters *parameters )
{
  // This is needed for RSA, DSA or ECDSA
  digest_ctx sha_digest;

#if TLS_VERSION_MINOR >= 3
  switch ( hash_alg )
  {
    case sha1:
      new_sha1_digest( &sha_digest );
      break;
    case sha256:
      new_sha256_digest( &sha_digest );
      break;
    default:
      fprintf( stderr, "Unsupported signature hash algorithm %d\n", hash_alg );
      return 0;
  }
#else
  new_sha1_digest( &sha_digest );
#endif
  update_digest( &sha_digest, parameters->client_random, RANDOM_LENGTH );
  update_digest( &sha_digest, parameters->server_random, RANDOM_LENGTH );
  update_digest( &sha_digest, message, message_len );
  finalize_digest( &sha_digest );

  if ( parameters->server_public_key.algorithm == rsa )
  {
    unsigned char *decrypted_signature;
    int decrypted_signature_length;
#if TLS_VERSION_MINOR >= 3
    struct asn1struct rsa_signature;
    struct asn1struct *hash_oid;
    struct asn1struct *hash_value;
    int valid;
#else
    digest_ctx md5_digest;
#endif

    decrypted_signature_length = rsa_decrypt( signature, signature_len,
      &decrypted_signature,
      &parameters->server_public_key.rsa_public_key );

    if ( decrypted_signature_length < 0 )
    {
      return 0;
    }

#if TLS_VERSION_MINOR >= 3
    // TLS 1.2; no longer includes MD-5, just one hash,
    // but the RSA signature also includes the signature scheme,
    // so must be DER-decoded
    if ( asn1parse( decrypted_signature, decrypted_signature_length,
                    &rsa_signature ) )
    {
      free( decrypted_signature );
      return 0;
    }

    hash_oid = rsa_signature.children->children;
    hash_value = rsa_signature.children->next;
    valid = ( hash_value->length == sha_digest.hash_len * sizeof( int ) ) &&
      ( hash_alg == sha256 ?
        ( hash_oid->length == sizeof( OID_sha256 ) &&
          !memcmp( hash_oid->data, OID_sha256, sizeof( OID_sha256 ) ) ) :
        ( hash_oid->length == sizeof( OID_sha1 ) &&
          !memcmp( hash_oid->data, OID_sha1, sizeof( OID_sha1 ) ) ) ) &&
      !memcmp( sha_digest.hash, hash_value->data, hash_value->length );

    asn1free( &rsa_signature );
    free( decrypted_signature );

    if ( !valid )
    {
      return 0;
    }
#else
    // If the signature algorithm is RSA, this will be the md5 hash, followed by
    // the sha-1 hash of: client random, server random, params).
    // If DSA, this will just be the sha-1 hash
    new_md5_digest( &md5_digest );
    update_digest( &md5_digest, parameters->client_random, RANDOM_LENGTH );
    update_digest( &md5_digest, parameters->server_random, RANDOM_LENGTH );
    update_digest( &md5_digest, message, message_len );
    finalize_digest( &md5_digest );

    if ( memcmp( md5_digest.hash, decrypted_signature, MD5_BYTE_SIZE ) ||
         memcmp( sha_digest.hash, decrypted_signature + MD5_BYTE_SIZE,
                 SHA1_BYTE_SIZE ) )
    {
      free( decrypted_signature );
      return 0;
    }

    free( decrypted_signature );
#endif
  }
  else if ( ( parameters->server_public_key.algorithm == dsa ) ||
            ( parameters->server_public_key.algorithm == ecdsa ) )
  {
    struct asn1struct decoded_signature;
    dsa_signature received_signature;
    int verified;

    if ( asn1parse( signature, signature_len, &decoded_signature ) )
    {
      return 0;
    }

    set_huge( &received_signature.r, 0 );
    set_huge( &received_signature.s, 0 );
    load_huge( &received_signature.r, decoded_signature.children->data,
      decoded_signature.children->length );
    load_huge( &received_signature.s,
      decoded_signature.children->next->data,
      decoded_signature.children->next->length );
    contract( &received_signature.r );
    contract( &received_signature.s );

    asn1free( &decoded_signature );

    if ( parameters->server_public_key.algorithm == dsa )
    {
      verified = dsa_verify( &parameters->server_public_key.dsa_parameters,
                             &parameters->server_public_key.dsa_public_key,
                             sha_digest.hash,
                             SHA1_BYTE_SIZE,
                             &received_signature );
    }
    else
    {
      verified = ecdsa_verify( &parameters->server_public_key.ecdsa_curve,
                               &parameters->server_public_key.ecdsa_public_key,
                               sha_digest.hash,
                               sha_digest.hash_len,
                               &received_signature );
    }

    free_huge( &received_signature.r );
    free_huge( &received_signature.s );

    if ( !verified )
    {
      free( sha_digest.hash );
      return 0;
    }
  }

  free( sha_digest.hash );

  return 1;
}

static char *parse_server_key_exchange( unsigned char *read_pos,
                                        int pdu_length,
                                        TLSParameters *parameters )
{
  short length;
  int i;
  unsigned char *dh_params = read_pos;
  HashAlgorithm hash_alg = sha1; // implied before TLS 1.2
  SignatureAlgorithm sig_alg;

  if ( is_ecdhe_suite( parameters->pending_send_parameters.suite ) )
  {
    unsigned char curve_type;
    unsigned short curve;
    unsigned char public_key_length;
    unsigned char point_type;

    read_pos = read_buffer( ( void * ) &curve_type, read_pos, 1 );
    switch ( curve_type )
    {
      case named:
        read_pos = read_buffer( ( void * ) &curve, read_pos, 2 );
        curve = ntohs( curve );
        switch ( curve )
        {
          case secp256r1:
            get_named_curve( "prime256v1", &parameters->server_ecdh_params );
            break;
          case secp192r1:
            get_named_curve( "prime192v1", &parameters->server_ecdh_params );
            break;
          default:
            fprintf( stderr, "error, unsupported named curve %d\n", curve );
            return NULL;
        }
        break;
      default:
        fprintf( stderr, "Error, unsupported curve type %d.\n", curve_type );
        return NULL;
    }

    // Followed by a length-delimited (opaque) public key.
    read_pos = read_buffer( ( void * ) &public_key_length, read_pos, 1 );
    read_pos = read_buffer( ( void * ) &point_type, read_pos, 1 );
    if ( point_type != uncompressed )
    {
      fprintf( stderr, "Error, compressed ECDH public keys not supported.\n" );
      return NULL;
    }

    load_huge( &parameters->server_ecdh_key.x, read_pos,
      ( public_key_length - 1 ) / 2 );
    load_huge( &parameters->server_ecdh_key.y,
      ( read_pos + ( ( public_key_length - 1 ) / 2 ) ),
      ( ( public_key_length - 1 ) / 2 ) );
    read_pos += ( public_key_length - 1 );
  }
  else
  {
    // DHE: p, g and Ys, each preceded by its length
    for ( i = 0; i < 3; i++ )
    {
      memcpy( &length, read_pos, 2 );
      length = ntohs( length );
      read_pos += 2;

      switch ( i )
      {
        case 0:
          load_huge( &parameters->server_dh_key.p, read_pos, length );
          break;
        case 1:
          load_huge( &parameters->server_dh_key.g, read_pos, length );
          break;
        case 2:
          load_huge( &parameters->server_dh_key.Y, read_pos, length );
          break;
      }
      read_pos += length;
    }
  }

  // The signature over the parameters, including their length bytes,
  // follows them. DH_anon suites don't send one.
  if ( ( read_pos - dh_params ) < pdu_length )
  {
    int params_length = read_pos - dh_params;

#if TLS_VERSION_MINOR >= 3
    hash_alg = read_pos[ 0 ];
    sig_alg = read_pos[ 1 ];
    read_pos += 2;
#endif

    memcpy( &length, read_pos, 2 );
    length = ntohs( length );
    read_pos += 2;

    if ( !verify_signature( dh_params, params_length, read_pos, length,
                            hash_alg, parameters ) )
    {
      return NULL;
    }
    read_pos += length;
  }

  return read_pos;
}

#define MAX_CERTIFICATE_TYPES 4

typedef enum
{
  rsa_signed = 1,
  dss_signed = 2,
  rsa_fixed_dh = 3,
  dss_fixed_dh = 4
}
certificate_type;

#define MAX_SIGNATURE_ALGORITHMS 28

typedef struct
{
  HashAlgorithm hash;
  SignatureAlgorithm signature;
}
SignatureAndHashAlgorithm;

typedef struct
{
  unsigned char certificate_types_count;
  certificate_type supported_certificate_types[ MAX_CERTIFICATE_TYPES ];
  unsigned short signature_algorithms_count;
  SignatureAndHashAlgorithm
    supported_signature_algorithms[ MAX_SIGNATURE_ALGORITHMS ];
}
CertificateRequest;

static unsigned char *parse_certificate_request( unsigned char *read_pos,
                                                 TLSParameters *parameters )
{
  int i;
  unsigned short trusted_roots_length;
  unsigned char *init_pos;
  CertificateRequest request;

  read_pos = read_buffer( &request.certificate_types_count, read_pos, 1 );
  for ( i = 0; i < request.certificate_types_count; i++ )
  {
    unsigned char type;
    read_pos = read_buffer( ( void * ) &type, read_pos, 1 );
    if ( i < MAX_CERTIFICATE_TYPES )
    {
      request.supported_certificate_types[ i ] = type;
    }
  }

#if TLS_VERSION_MINOR >= 3
  {
    unsigned short signature_algorithms_length;

    read_pos = read_buffer( ( void * ) &signature_algorithms_length,
      read_pos, 2 );
    signature_algorithms_length = ntohs( signature_algorithms_length );
    request.signature_algorithms_count = 0;
    for ( i = 0; i < signature_algorithms_length / 2; i++ )
    {
      unsigned char hash, signature;

      read_pos = read_buffer( ( void * ) &hash, read_pos, 1 );
      read_pos = read_buffer( ( void * ) &signature, read_pos, 1 );
      if ( i < MAX_SIGNATURE_ALGORITHMS )
      {
        request.supported_signature_algorithms[ i ].hash = hash;
        request.supported_signature_algorithms[ i ].signature = signature;
        request.signature_algorithms_count++;
      }
    }
  }
#endif

  read_pos = read_buffer( ( void * ) &trusted_roots_length, read_pos, 2 );
  trusted_roots_length = htons( trusted_roots_length );
  init_pos = read_pos;
  while ( ( read_pos - init_pos ) < trusted_roots_length )
  {
    unsigned short dn_length;
    struct asn1struct dn_data;
    name dn;

    read_pos = read_buffer( ( void * ) &dn_length, read_pos, 2 );
    dn_length = htons( dn_length );

    asn1parse( read_pos, dn_length, &dn_data );
    // the DN is a SEQUENCE of SETs; parse_name walks its children
    parse_name( &dn, &dn_data );
    printf( "Server trusts issuer: C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s\n",
      dn.idAtCountryName, dn.idAtStateOrProvinceName,
      dn.idAtLocalityName, dn.idAtOrganizationName,
      dn.idAtOrganizationalUnitName, dn.idAtCommonName );
    asn1free( &dn_data );
    read_pos += dn_length;
  }

  parameters->got_certificate_request = 1;

  return read_pos;
}

static void report_alert( Alert *alert )
{
  printf( "Alert - " );

  switch ( alert->level )
  {
    case warning:
      printf( "Warning: " );
      break;
    case fatal:
      printf( "Fatal: " );
      break;
    default:
      printf( "UNKNOWN ALERT TYPE %d (!!!): ", alert->level );
      break;
  }

  switch ( alert->description )
  {
    case close_notify:
      printf( "Close notify\n" );
      break;
    case unexpected_message:
      printf( "Unexpected message\n" );
      break;
    case bad_record_mac:
      printf( "Bad Record Mac\n" );
      break;
    case decryption_failed:
      printf( "Decryption Failed\n" );
      break;
    case record_overflow:
      printf( "Record Overflow\n" );
      break;
    case decompression_failure:
      printf( "Decompression Failure\n" );
      break;
    case handshake_failure:
      printf( "Handshake Failure\n" );
      break;
    case bad_certificate:
      printf( "Bad Certificate\n" );
      break;
    case unsupported_certificate:
      printf( "Unsupported Certificate\n" );
      break;
    case certificate_revoked:
      printf( "Certificate Revoked\n" );
      break;
    case certificate_expired:
      printf( "Certificate Expired\n" );
      break;
    case certificate_unknown:
      printf( "Certificate Unknown\n" );
      break;
    case illegal_parameter:
      printf( "Illegal Parameter\n" );
      break;
    case unknown_ca:
      printf( "Unknown CA\n" );
      break;
    case access_denied:
      printf( "Access Denied\n" );
      break;
    case decode_error:
      printf( "Decode Error\n" );
      break;
    case decrypt_error:
      printf( "Decrypt Error\n" );
      break;
    case export_restriction:
      printf( "Export Restriction\n" );
      break;
    case protocol_version:
      printf( "Protocol Version\n" );
      break;
    case insufficient_security:
      printf( "Insufficient Security\n" );
      break;
    case internal_error:
      printf( "Internal Error\n" );
      break;
    case user_canceled:
      printf( "User canceled\n" );
      break;
    case no_renegotiation:
      printf( "No renegotiation\n" );
      break;
    default:
      printf( "UNKNOWN ALERT DESCRIPTION %d (!!!)\n", alert->description );
      break;
  }
}

/**
 * Decrypt a message and verify its MAC according to the active cipher spec
 * (as given by "parameters"). Free the space allocated by encrypted message
 * and allocate new space for the decrypted message (if decrypting is "identity",
 * then decrypted will point to encrypted). The caller must always issue a
 * "free decrypted_message".
 * Return the length of the message, or -1 if the MAC doesn't verify. The return
 * value will almost always be different than "encrypted_length", since it strips
 * off the MAC if present as well as bulk cipher padding (if a block cipher
 * algorithm is being used).
 */
static int tls_decrypt( const unsigned char *header, // needed for MAC verification
                        unsigned char *encrypted_message,
                        short encrypted_length,
                        unsigned char **decrypted_message,
                        ProtectionParameters *parameters )
{
  short decrypted_length;
  digest_ctx digest;
  unsigned char *mac_buffer;
  int sequence_number;
  short length;
  CipherSuite *active_suite = &( suites[ parameters->suite ] );

  *decrypted_message = ( unsigned char * ) malloc( encrypted_length );

  if ( active_suite->bulk_decrypt )
  {
#if TLS_VERSION_MINOR >= 2
    // TLS 1.1+: the first IV_size bytes of a block-ciphered record are its IV
    if ( active_suite->block_size )
    {
      if ( encrypted_length < active_suite->IV_size )
      {
        return -1;
      }
      memcpy( parameters->IV, encrypted_message, active_suite->IV_size );
      encrypted_message += active_suite->IV_size;
      encrypted_length -= active_suite->IV_size;
    }
#endif
    active_suite->bulk_decrypt( encrypted_message, encrypted_length,
      *decrypted_message, parameters->IV, parameters->key );
    decrypted_length = encrypted_length;
    // Strip off padding
    if ( active_suite->block_size )
    {
      decrypted_length -= ( (*decrypted_message)[ encrypted_length - 1 ] + 1 );
    }
  }
  else if ( active_suite->aead_decrypt )
  {
    unsigned char nonce[ 12 ];
    unsigned char mac_header[ 13 ];

    if ( encrypted_length < AEAD_EXPLICIT_NONCE_LEN + active_suite->hash_size )
    {
      return -1;
    }

    memcpy( nonce, parameters->IV, active_suite->IV_size );
    memcpy( nonce + active_suite->IV_size, encrypted_message,
      AEAD_EXPLICIT_NONCE_LEN );
    decrypted_length = encrypted_length - AEAD_EXPLICIT_NONCE_LEN -
      active_suite->hash_size;

    // Compute the MAC header, which is the AD part. This
    // has to be done separately here, since the length computation
    // is slightly different than in the block cipher case
    memset( mac_header, 0x0, 13 );
    sequence_number = htonl( parameters->seq_num );
    memcpy( mac_header + 4, &sequence_number, sizeof( int ) );
    memcpy( mac_header + 8, header, 3 );
    length = htons( decrypted_length );
    memcpy( mac_header + 11, &length, 2 );

    if ( active_suite->aead_decrypt(
           encrypted_message + AEAD_EXPLICIT_NONCE_LEN,
           encrypted_length - AEAD_EXPLICIT_NONCE_LEN, mac_header, 13,
           *decrypted_message, nonce, parameters->key ) )
    {
      // MAC verification failed
      return -1;
    }
  }
  else
  {
    // Do nothing, no bulk cipher algorithm chosen.
    // Still have to memcpy so that "free" in caller is consistent
    decrypted_length = encrypted_length;
    memcpy( *decrypted_message, encrypted_message, encrypted_length );
  }

  // Now, verify the MAC (if the active cipher suite includes one)
  if ( active_suite->new_digest )
  {
    active_suite->new_digest( &digest );

    decrypted_length -= ( digest.hash_len * sizeof( int ) );

    // Allocate enough space for the 8-byte sequence number, the TLSPlainText
    // header, and the fragment (e.g. the decrypted message).
    mac_buffer = malloc( 13 + decrypted_length );
    memset( mac_buffer, 0x0, 13 + decrypted_length );
    sequence_number = htonl( parameters->seq_num );
    memcpy( mac_buffer + 4, &sequence_number, sizeof( int ) );

    // Copy first three bytes of header; last two bytes reflected the
    // message length, with MAC attached. Since the MAC was computed
    // by the other side before it was attached (obviously), that MAC
    // was computed using the original length.
    memcpy( mac_buffer + 8, header, 3 );
    length = htons( decrypted_length );
    memcpy( mac_buffer + 11, &length, 2 );
    memcpy( mac_buffer + 13, *decrypted_message, decrypted_length );

    hmac( parameters->MAC_secret, digest.hash_len * sizeof( int ),
      mac_buffer, decrypted_length + 13, &digest );

    if ( memcmp( digest.hash,
                 (*decrypted_message) + decrypted_length,
                 digest.hash_len * sizeof( int ) ) )
    {
      free( mac_buffer );
      free( digest.hash );
      return -1;
    }

    free( mac_buffer );
    free( digest.hash );
  }

  return decrypted_length;
}

/**
 * Read a TLS packet off of the connection (assuming there's one waiting)
 * and try to update the security parameters based on the type of message
 * received. If the read times out, or if an alert is received, return an error
 * code; return 0 on success.
 * TODO - assert that the message received is of the type expected (for example,
 * if a server hello is expected but not received, this is a fatal error per
 * section 7.3).
 * returns -1 if an error occurred (this routine will have sent an
 * appropriate alert). Otherwise, return the number of bytes read if the packet
 * includes application data; 0 if the packet was a handshake. -1 also
 * indicates that an alert was received.
 */
static int receive_tls_msg( int connection,
                            char *buffer,
                            int bufsz,
                            TLSParameters *parameters )
{
  TLSPlaintext message;
  unsigned char *read_pos, *msg_buf, *decrypted_message, *encrypted_message;
  unsigned char header[ 5 ]; // size of TLSPlaintext
  int bytes_read, accum_bytes;
  int decrypted_length;

  // First, check to see if there's any data left over from a previous read.
  // If there is, pass that back up.
  // This means that if the caller isn't quick about reading available data,
  // TLS alerts can be missed.
  if ( parameters->unread_buffer != NULL )
  {
    decrypted_message = parameters->unread_buffer;
    decrypted_length = parameters->unread_length;
    parameters->unread_buffer = NULL;
    parameters->unread_length = 0;

    message.type = content_application_data;
  }
  else
  {
    // STEP 1 - read off the TLS Record layer
    if ( recv( connection, header, 5, 0 ) <= 0 )
    {
      // No data available; it's up to the caller whether this is an error or not.
      return -1;
    }

    message.type = header[ 0 ];
    message.version.major = header[ 1 ];
    message.version.minor = header[ 2 ];
    memcpy( &message.length, header + 3, 2 );
    message.length = htons( message.length );
    encrypted_message = ( char * ) malloc( message.length );

    // keep looping & appending until all bytes are accounted for
    accum_bytes = 0;
    msg_buf = encrypted_message;
    while ( accum_bytes < message.length )
    {
      if ( ( bytes_read = recv( connection, ( void * ) msg_buf,
             message.length - accum_bytes, 0 ) ) <= 0 )
      {
        int status;
        perror( "While reading a TLS packet" );

        if ( ( status = send_alert_message( connection,
               illegal_parameter, &parameters->active_send_parameters ) ) )
        {
          free( encrypted_message );
          return status;
        }
        return -1;
      }
      accum_bytes += bytes_read;
      msg_buf += bytes_read;
    }

    // If a cipherspec is active, all of "encrypted_message" will be encrypted.
    // Must decrypt it before continuing. This will change the message length
    // in all cases, since decrypting also involves verifying a MAC (unless the
    // active cipher spec is NULL_WITH_NULL_NULL).
    decrypted_message = NULL;
    decrypted_length = tls_decrypt( header, encrypted_message,
      message.length, &decrypted_message, &parameters->active_recv_parameters );

    free( encrypted_message );

    if ( decrypted_length < 0 )
    {
      send_alert_message( connection, bad_record_mac,
        &parameters->active_send_parameters );
      return -1;
    }

    parameters->active_recv_parameters.seq_num++;
  }

  read_pos = decrypted_message;

  if ( message.type == content_handshake )
  {
    while ( ( read_pos - decrypted_message ) < decrypted_length )
    {
      Handshake handshake;

      // Keep track of beginning of message for handshake digest update below
      const unsigned char *handshake_msg_start = read_pos;

      // Now, read the handshake type and length of the next packet
      // TODO - this fails if the read, above, only got part of the message
      read_pos = read_buffer( ( void * ) &handshake.msg_type,
        ( void * ) read_pos, 1 );
      handshake.length = read_pos[ 0 ] << 16 | read_pos[ 1 ] << 8 | read_pos[ 2 ];

      read_pos += 3;

      // TODO check for negative or unreasonably long length
      // Now, depending on the type, read in and process the packet itself.
      switch ( handshake.msg_type )
      {
        // Server-side messages
        case client_hello:
          if ( parse_client_hello( read_pos, handshake.length,
                                   parameters ) == NULL )
          {
            send_alert_message( connection, illegal_parameter,
              &parameters->active_send_parameters );
            return -1;
          }
          read_pos += handshake.length;
          break;
        case client_key_exchange:
          read_pos = parse_client_key_exchange( read_pos, handshake.length,
            parameters );
          if ( read_pos == NULL )
          {
            send_alert_message( connection, illegal_parameter,
              &parameters->active_send_parameters );
            return -1;
          }
          break;
        // Client-side messages
        case server_hello:
          read_pos = parse_server_hello( read_pos, handshake.length, parameters );
          if ( read_pos == NULL ) /* error occurred */
          {
            free( decrypted_message );
            send_alert_message( connection, illegal_parameter,
              &parameters->active_send_parameters );
            return -1;
          }
          break;
        case certificate:
          read_pos = parse_x509_chain( read_pos, handshake.length,
            &parameters->server_public_key );
          if ( read_pos == NULL )
          {
            printf( "Rejected, bad certificate\n" );
            send_alert_message( connection, bad_certificate,
              &parameters->active_send_parameters );
            return -1;
          }
          break;
        case server_key_exchange:
          read_pos = parse_server_key_exchange( read_pos, handshake.length,
            parameters );
          if ( read_pos == NULL )
          {
            send_alert_message( connection, handshake_failure,
              &parameters->active_send_parameters );
            return -1;
          }
          break;
        case certificate_request: // Abort if server requests a certificate?
          read_pos = parse_certificate_request( read_pos, parameters );
          break;
        case server_hello_done:
          parameters->server_hello_done = 1;
          break;
        case hello_request: // Tell the client to start again from the beginning
          // No data in the hello request, nothing to parse
          if ( parameters->connection_end != connection_end_client )
          {
            // This shouldn't be sent to a server, and it shouldn't
            // be sent until the first negotiation is complete.
            send_alert_message( connection, unexpected_message,
              &parameters->active_send_parameters );
            return -1;
          }
          // Per the spec, this isn't an error, just ignore if
          // currently negotiating
          if ( parameters->peer_finished )
          {
            // recursive, but the check for peer_finished above
            // prevents infinite recursion.
            // the hello request must not enter the new
            // handshake's digest, and this record's data is consumed here
            free( decrypted_message );
            tls_connect( connection, parameters, 1 );
            return 0;
          }
          else
          {
            read_pos += handshake.length;
          }
          break;
        case finished:
          {
            read_pos = parse_finished( read_pos, handshake.length, parameters );
            if ( read_pos == NULL )
            {
              send_alert_message( connection, illegal_parameter,
                &parameters->active_send_parameters );
              return -1;
            }
          }
          break;
        default:
          printf( "Ignoring unrecognized handshake message %d\n",
            handshake.msg_type );
          // Silently ignore any unrecognized types per section 6
          // TODO However, out-of-order messages should result in a fatal alert
          // per section 7.4
          read_pos += handshake.length;
          break;
      }

      update_digest( &parameters->md5_handshake_digest, handshake_msg_start,
        handshake.length + 4 );
      update_digest( &parameters->sha1_handshake_digest, handshake_msg_start,
        handshake.length + 4 );
      update_digest( &parameters->sha256_handshake_digest, handshake_msg_start,
        handshake.length + 4 );
    }
  }
  else if ( message.type == content_alert )
  {
    while ( ( read_pos - decrypted_message ) < decrypted_length )
    {
      Alert alert;

      read_pos = read_buffer( ( void * ) &alert.level,
        ( void * ) read_pos, 1 );
      read_pos = read_buffer( ( void * ) &alert.description,
        ( void * ) read_pos, 1 );

      report_alert( &alert );

      if ( alert.level == fatal )
      {
        return -1;
      }
    }
  }
  else if ( message.type == content_change_cipher_spec )
  {
    while ( ( read_pos - decrypted_message ) < decrypted_length )
    {
      unsigned char change_cipher_spec_type;

      read_pos = read_buffer( ( void * ) &change_cipher_spec_type,
        ( void * ) read_pos, 1 );

      if ( change_cipher_spec_type != 1 )
      {
        printf( "Error - received message ChangeCipherSpec, but type != 1\n" );
        exit( 0 );
      }
      else
      {
        parameters->pending_recv_parameters.seq_num = 0;
        memcpy( &parameters->active_recv_parameters,
                &parameters->pending_recv_parameters,
                sizeof( ProtectionParameters ) );
        init_protection_parameters( &parameters->pending_recv_parameters );
      }
    }
  }
  else if ( message.type == content_application_data )
  {
    if ( decrypted_length <= bufsz )
    {
      memcpy( buffer, decrypted_message, decrypted_length );
    }
    else
    {
      // Need to hang on to a buffer of data here and pass it back for the
      // next call
      memcpy( buffer, decrypted_message, bufsz );
      parameters->unread_length = decrypted_length - bufsz;
      parameters->unread_buffer = malloc( parameters->unread_length );
      memcpy( parameters->unread_buffer, decrypted_message + bufsz,
        parameters->unread_length );

      decrypted_length = bufsz;
    }
  }
  else
  {
    // Ignore content types not understood, per section 6 of the RFC.
    printf( "Ignoring non-recognized content type %d\n", message.type );
  }

  free( decrypted_message );

  return decrypted_length;
}

static int send_certificate_verify( int connection,
                                    TLSParameters *parameters )
{
  unsigned char *buffer;
  int buffer_length;
  rsa_key private_key;
  unsigned short handshake_signature_len;
  unsigned char *handshake_signature;
  unsigned short certificate_verify_message_len;
  unsigned char *certificate_verify_message;
  unsigned char handshake_hash[ ( MD5_RESULT_SIZE * sizeof( int ) ) +
                                ( SHA1_RESULT_SIZE * sizeof( int ) ) ];
  int handshake_hash_len;
  unsigned char *signed_data;
  int signed_data_len;
  int header_len = 0;
#if TLS_VERSION_MINOR >= 3
  // DER DigestInfo header for a SHA-256 hash (RFC 3447 9.2)
  static const unsigned char sha256_digest_info[] = { 0x30, 0x31, 0x30, 0x0d,
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20 };
  unsigned char digest_info[ sizeof( sha256_digest_info ) + SHA256_BYTE_SIZE ];
#endif

  handshake_hash_len = compute_handshake_hash( parameters, handshake_hash );
  signed_data = handshake_hash;
  signed_data_len = handshake_hash_len;
#if TLS_VERSION_MINOR >= 3
  // TLS 1.2 signs a DigestInfo of the SHA-256 handshake
  // hash and declares the algorithms in front of the signature
  memcpy( digest_info, sha256_digest_info, sizeof( sha256_digest_info ) );
  memcpy( digest_info + sizeof( sha256_digest_info ), handshake_hash,
    SHA256_BYTE_SIZE );
  signed_data = digest_info;
  signed_data_len = sizeof( digest_info );
  header_len = 2;
#endif

  if ( !( buffer = load_file_into_memory( "key.der", &buffer_length ) ) )
  {
    perror( "Unable to load file" );
    return 0;
  }

  parse_private_key( &private_key, buffer, buffer_length );
  free( buffer );

  handshake_signature_len = ( unsigned short ) rsa_sign( signed_data,
    signed_data_len, &handshake_signature, &private_key );

  certificate_verify_message_len = header_len + handshake_signature_len +
    sizeof( unsigned short );
  certificate_verify_message = ( unsigned char * )
    malloc( certificate_verify_message_len );

#if TLS_VERSION_MINOR >= 3
  certificate_verify_message[ 0 ] = sha256;
  certificate_verify_message[ 1 ] = sig_rsa;
#endif

  // copying this "backwards" so that I can use the signature len
  // as a numeric input but then htons it to send on.
  memcpy( ( void * ) ( certificate_verify_message + header_len + 2 ),
    ( void * ) handshake_signature, handshake_signature_len );
  handshake_signature_len = htons( handshake_signature_len );
  memcpy( ( void * ) certificate_verify_message + header_len,
    ( void * ) &handshake_signature_len, sizeof( unsigned short ) );

  send_handshake_message( connection, certificate_verify,
    certificate_verify_message, certificate_verify_message_len, parameters );

  free( certificate_verify_message );
  free( handshake_signature );

  return 1;
}

/**
 * Negotiate TLS parameters on an already-established socket.
 */
int tls_connect( int connection,
                 TLSParameters *parameters,
                 int renegotiate )
{
  init_parameters( parameters, renegotiate );
  parameters->connection_end = connection_end_client;
  new_md5_digest( &parameters->md5_handshake_digest );
  new_sha1_digest( &parameters->sha1_handshake_digest );
  new_sha256_digest( &parameters->sha256_handshake_digest );

  // Step 1. Send the TLS handshake "client hello" message
  if ( send_client_hello( connection, parameters, renegotiate ) < 0 )
  {
    perror( "Unable to send client hello" );
    return 1;
  }

  // Step 2. Receive the server hello response (will also have gotten
  // the server certificate along the way)
  parameters->server_hello_done = 0;
  parameters->got_certificate_request = 0;
  while ( !parameters->server_hello_done )
  {
    if ( receive_tls_msg( connection, NULL, 0, parameters ) < 0 )
    {
      perror( "Unable to receive server hello" );
      return 2;
    }
  }

  // Certificate precedes key exchange
  if ( parameters->got_certificate_request )
  {
    send_certificate( connection, parameters );
  }

  // Step 3. Send client key exchange, change cipher spec (7.1) and encrypted
  // handshake message
  if ( !( send_client_key_exchange( connection, parameters ) ) )
  {
    perror( "Unable to send client key exchange" );
    return 3;
  }

  // Certificate verify comes after key exchange
  if ( parameters->got_certificate_request )
  {
    if ( !send_certificate_verify( connection, parameters ) )
    {
      perror( "Unable to send certificate verify message" );
      return 3;
    }
  }

  if ( !( send_change_cipher_spec( connection, parameters ) ) )
  {
    perror( "Unable to send client change cipher spec" );
    return 4;
  }

  // This message will be encrypted using the newly negotiated keys
  if ( !( send_finished( connection, parameters ) ) )
  {
    perror( "Unable to send client finished" );
    return 5;
  }

  parameters->peer_finished = 0;
  while ( !parameters->peer_finished )
  {
    if ( receive_tls_msg( connection, NULL, 0, parameters ) < 0 )
    {
      perror( "Unable to receive server finished" );
      return 6;
    }
  }

  return 0;
}

int tls_accept( int connection,
                TLSParameters *parameters )
{
  init_parameters( parameters, 0 );
  parameters->connection_end = connection_end_server;

  new_md5_digest( &parameters->md5_handshake_digest );
  new_sha1_digest( &parameters->sha1_handshake_digest );
  new_sha256_digest( &parameters->sha256_handshake_digest );

  // The client sends the first message
  parameters->got_client_hello = 0;
  while ( !parameters->got_client_hello )
  {
    if ( receive_tls_msg( connection, NULL, 0, parameters ) < 0 )
    {
      perror( "Unable to receive client hello" );
      send_alert_message( connection, handshake_failure,
        &parameters->active_send_parameters );
      return 1;
    }
  }

  if ( parameters->session_id_length > 0 )
  {
    // Client asked for a resumption, and this server recognized the
    // session id. Shortened handshake here. "parse_client_hello"
    // will have already initiated calculate keys.
    if ( send_server_hello( connection, parameters ) )
    {
      send_alert_message( connection, handshake_failure,
        &parameters->active_send_parameters );
      return 3;
    }

    // Can't calculate keys until this point because server random
    // is needed.
    calculate_keys( parameters );

    // send server change cipher spec/finished message
    // Order is reversed when resuming
    if ( !( send_change_cipher_spec( connection, parameters ) ) )
    {
      perror( "Unable to send client change cipher spec" );
      send_alert_message( connection, handshake_failure,
        &parameters->active_send_parameters );
      return 7;
    }

    // This message will be encrypted using the newly negotiated keys
    if ( !( send_finished( connection, parameters ) ) )
    {
      perror( "Unable to send client finished" );
      send_alert_message( connection, handshake_failure,
        &parameters->active_send_parameters );
      return 8;
    }

    parameters->peer_finished = 0;
    while ( !parameters->peer_finished )
    {
      if ( receive_tls_msg( connection, NULL, 0, parameters ) < 0 )
      {
        perror( "Unable to receive client finished" );
        send_alert_message( connection, handshake_failure,
          &parameters->active_send_parameters );
        return 6;
      }
    }

    return 0;
  }

  if ( send_server_hello( connection, parameters ) )
  {
    send_alert_message( connection, handshake_failure,
      &parameters->active_send_parameters );
    return 2;
  }

  if ( send_certificate( connection, parameters ) )
  {
    send_alert_message( connection, handshake_failure,
      &parameters->active_send_parameters );
    return 3;
  }

  if ( send_server_hello_done( connection, parameters ) )
  {
    send_alert_message( connection, handshake_failure,
      &parameters->active_send_parameters );
    return 4;
  }

  // Now the client should send a client key exchange, change cipher spec, and
  // an encrypted "finalize" message
  parameters->peer_finished = 0;
  while ( !parameters->peer_finished )
  {
    if ( receive_tls_msg( connection, NULL, 0, parameters ) < 0 )
    {
      perror( "Unable to receive client finished" );
      send_alert_message( connection, handshake_failure,
        &parameters->active_send_parameters );
      return 5;
    }
  }

  // Finally, send server change cipher spec/finished message
  if ( !( send_change_cipher_spec( connection, parameters ) ) )
  {
    perror( "Unable to send client change cipher spec" );
    send_alert_message( connection, handshake_failure,
      &parameters->active_send_parameters );
    return 6;
  }

  // This message will be encrypted using the newly negotiated keys
  if ( !( send_finished( connection, parameters ) ) )
  {
    perror( "Unable to send client finished" );
    send_alert_message( connection, handshake_failure,
      &parameters->active_send_parameters );
    return 7;
  }

  // Handshake is complete; now ready to start sending encrypted data
  // IFF the handshake was successful, put it into the sesion ID cache
  // list for reuse.
  remember_session( parameters );

  return 0;
}

int tls_resume( int connection,
                int session_id_length,
                const unsigned char *session_id,
                const unsigned char *master_secret,
                TLSParameters *parameters )
{
  int keys_calculated = 0;

  init_parameters( parameters, 0 );
  parameters->connection_end = connection_end_client;
  parameters->session_id_length = session_id_length;
  memcpy( &parameters->session_id, session_id, session_id_length );

  new_md5_digest( &parameters->md5_handshake_digest );
  new_sha1_digest( &parameters->sha1_handshake_digest );
  new_sha256_digest( &parameters->sha256_handshake_digest );

  // Send the TLS handshake "client hello" message
  if ( send_client_hello( connection, parameters, 0 ) < 0 )
  {
    perror( "Unable to send client hello" );
    return 1;
  }

  // Receive server hello, change cipher spec & finished.
  parameters->server_hello_done = 0;
  parameters->peer_finished = 0;
  while ( !parameters->peer_finished )
  {
    if ( receive_tls_msg( connection, NULL, 0, parameters ) < 0 )
    {
      perror( "Unable to receive server finished" );
      return 6;
    }

    if ( parameters->got_server_hello && !keys_calculated )
    {
      // Check to see if the server agreed to resume; if not,
      // abort, even though the server is probably willing to continue
      // with a new session.
      if ( memcmp( session_id, &parameters->session_id, session_id_length ) )
      {
        printf( "Server refused to renegotiate, exiting.\n" );
        return 7;
      }
      else
      {
        memcpy( parameters->master_secret, master_secret,
          MASTER_SECRET_LENGTH );
        calculate_keys( parameters );
        keys_calculated = 1;
      }
    }
  }

  if ( !( send_change_cipher_spec( connection, parameters ) ) )
  {
    perror( "Unable to send client change cipher spec" );
    return 4;
  }

  if ( !( send_finished( connection, parameters ) ) )
  {
    perror( "Unable to send client finished" );
    return 5;
  }

  return 0;
}

int tls_send( int connection,
              const char *application_data,
              int length,
              int options,
              TLSParameters *parameters )
{
  send_message( connection, content_application_data, application_data, length,
    &parameters->active_send_parameters );

  return length;
}

int tls_recv( int connection, char *target_buffer, int buffer_size, int options,
              TLSParameters *parameters )
{
  int bytes_decrypted = 0;

  bytes_decrypted = receive_tls_msg( connection, target_buffer, buffer_size,
    parameters );

  return bytes_decrypted;
}

static void free_protection_parameters( ProtectionParameters *parameters )
{
  if ( parameters->MAC_secret )
  {
    free( parameters->MAC_secret );
  }
  if ( parameters->key )
  {
    free( parameters->key );
  }
  if ( parameters->IV )
  {
    free( parameters->IV );
  }
}

int tls_shutdown( int connection, TLSParameters *parameters )
{
  send_alert_message( connection, close_notify,
    &parameters->active_send_parameters );
  if ( parameters->unread_buffer )
  {
    free( parameters->unread_buffer );
  }
  free_protection_parameters( &parameters->pending_send_parameters );
  free_protection_parameters( &parameters->pending_recv_parameters );
  free_protection_parameters( &parameters->active_send_parameters );
  free_protection_parameters( &parameters->active_recv_parameters );

  return 1;
}
