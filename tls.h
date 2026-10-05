#ifndef TLS_H
#define TLS_H

#include "digest.h"
#include "x509.h"
#include "dh.h"

typedef enum
{
  TLS_NULL_WITH_NULL_NULL = 0x0000,
  TLS_RSA_WITH_NULL_MD5 = 0x0001,
  TLS_RSA_WITH_NULL_SHA = 0x0002,
  TLS_RSA_EXPORT_WITH_RC4_40_MD5 = 0x0003,
  TLS_RSA_WITH_RC4_128_MD5 = 0x0004,
  TLS_RSA_WITH_RC4_128_SHA = 0x0005,
  TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = 0x0006,
  TLS_RSA_WITH_IDEA_CBC_SHA = 0x0007,
  TLS_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0008,
  TLS_RSA_WITH_DES_CBC_SHA = 0x0009,
  TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000A,
  TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x000B,
  TLS_DH_DSS_WITH_DES_CBC_SHA = 0x000C,
  TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = 0x000D,
  TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x000E,
  TLS_DH_RSA_WITH_DES_CBC_SHA = 0x000F,
  TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = 0x0010,
  TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x0011,
  TLS_DHE_DSS_WITH_DES_CBC_SHA = 0x0012,
  TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x0013,
  TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0014,
  TLS_DHE_RSA_WITH_DES_CBC_SHA = 0x0015,
  TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016,
  TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 = 0x0017,
  TLS_DH_anon_WITH_RC4_128_MD5 = 0x0018,
  TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = 0x0019,
  TLS_DH_anon_WITH_DES_CBC_SHA = 0x001A,
  TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = 0x001B,
  // 1C & 1D were used by SSLv3 to describe Fortezza suites
  // End of list of algorithms defined by RFC 2246

  // These are all defined in RFC 4346 (v1.1), not 2246 (v1.0)
  //
  TLS_KRB5_WITH_DES_CBC_SHA = 0x001E,
  TLS_KRB5_WITH_3DES_EDE_CBC_SHA = 0x001F,
  TLS_KRB5_WITH_RC4_128_SHA = 0x0020,
  TLS_KRB5_WITH_IDEA_CBC_SHA = 0x0021,
  TLS_KRB5_WITH_DES_CBC_MD5 = 0x0022,
  TLS_KRB5_WITH_3DES_EDE_CBC_MD5 = 0x0023,
  TLS_KRB5_WITH_RC4_128_MD5 = 0x0024,
  TLS_KRB5_WITH_IDEA_CBC_MD5 = 0x0025,
  TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA = 0x0026,
  TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA = 0x0027,
  TLS_KRB5_EXPORT_WITH_RC4_40_SHA = 0x0028,
  TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 = 0x0029,
  TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 = 0x002A,
  TLS_KRB5_EXPORT_WITH_RC4_40_MD5 = 0x002B,

  // TLS_AES ciphersuites - RFC 3268
  TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F,
  TLS_DH_DSS_WITH_AES_128_CBC_SHA = 0x0030,
  TLS_DH_RSA_WITH_AES_128_CBC_SHA = 0x0031,
  TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0x0032,
  TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033,
  TLS_DH_anon_WITH_AES_128_CBC_SHA = 0x0034,
  TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
  TLS_DH_DSS_WITH_AES_256_CBC_SHA = 0x0036,
  TLS_DH_RSA_WITH_AES_256_CBC_SHA = 0x0037,
  TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 0x0038,
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039,
  TLS_DH_anon_WITH_AES_256_CBC_SHA = 0x003A,

  // AES-GCM - RFC 5288
  TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C,

  // ECC cipher suites - RFC 4492
  TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = 0xC007,
  TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC008,
  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xC009,
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xC00A,
  // ECDHE with an RSA-signed server key exchange
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013,
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014,
  // ECDHE with AES-GCM (RFC 5289), what most servers want
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B,
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,
  MAX_SUPPORTED_CIPHER_SUITE = 0xC030
} CipherSuiteIdentifier;

typedef struct
{
  CipherSuiteIdentifier id;

  int block_size;
  int IV_size;
  int key_size;
  int hash_size;

  void (*bulk_encrypt)( const unsigned char *plaintext,
                        const int plaintext_len,
                        unsigned char ciphertext[],
                        void *iv,
                        const unsigned char *key );
  void (*bulk_decrypt)( const unsigned char *ciphertext,
                        const int ciphertext_len,
                        unsigned char plaintext[],
                        void *iv,
                        const unsigned char *key );
  void (*new_digest)( digest_ctx *context );
  int (*aead_encrypt)( const unsigned char *plaintext,
                       const int plaintext_len,
                       const unsigned char *addldata,
                       const int addldata_len,
                       unsigned char ciphertext[],
                       void *iv,
                       const unsigned char *key );
  int (*aead_decrypt)( const unsigned char *ciphertext,
                       const int ciphertext_len,
                       const unsigned char *addldata,
                       const int addldata_len,
                       unsigned char plaintext[],
                       void *iv,
                       const unsigned char *key );
}
CipherSuite;

// RFC 5288: the GCM nonce is a 4-byte implicit salt from the key block
// followed by an 8-byte explicit part sent with each record.
#define AEAD_EXPLICIT_NONCE_LEN 8

typedef struct
{
  unsigned char *MAC_secret;
  unsigned char *key;
  unsigned char *IV;
  CipherSuiteIdentifier suite;
  unsigned long seq_num;
  // negotiated minor version; decides the record version and whether CBC
  // records carry an explicit IV
  unsigned char version;
}
ProtectionParameters;

#define TLS_VERSION_MAJOR 3
// Minor version numbers. the original compiles one version in (-8 use
// 3.1,  changes it to 3.3); here the version is negotiated at run
// time between tls_set_version_range's bounds (default TLS 1.0 - TLS 1.2).
#define TLS_1_0 1
#define TLS_1_1 2
#define TLS_1_2 3

#define MASTER_SECRET_LENGTH 48
typedef unsigned char master_secret_type[ MASTER_SECRET_LENGTH ];

#define MAX_SESSION_ID_LENGTH 32
#define VERIFY_DATA_LEN 12

#define RANDOM_LENGTH 32
typedef unsigned char random_type[ RANDOM_LENGTH ];

typedef enum { connection_end_client, connection_end_server } ConnectionEnd;

typedef struct
{
  ConnectionEnd connection_end;
  // negotiated minor version (0 until the hellos are exchanged), and the
  // version the client offered (the RSA premaster secret repeats it)
  unsigned char version;
  unsigned char client_version;
  master_secret_type master_secret;
  random_type client_random;
  random_type server_random;

  ProtectionParameters pending_send_parameters;
  ProtectionParameters pending_recv_parameters;
  ProtectionParameters active_send_parameters;
  ProtectionParameters active_recv_parameters;

  // RSA public key, if supplied
  public_key_info server_public_key;

  // DH public key, if supplied (either in a certificate or ephemerally)
  // Note that a server can legitimately have an RSA key for signing and
  // a DH key for key exchange (e.g. DHE_RSA)
  dh_key server_dh_key;

  // ECDH curve and public point from an ECDHE server key exchange
  elliptic_curve server_ecdh_params;
  point server_ecdh_key;
  // the server's ephemeral ECDH secret (server side only)
  huge server_ecdh_secret;

  // Internal state
  int got_client_hello;
  int got_server_hello;
  int server_hello_done;
  int peer_finished;
  int got_certificate_request;
  digest_ctx md5_handshake_digest;
  digest_ctx sha1_handshake_digest;
  // TLS 1.2 hashes the handshake with SHA-256 only; all three
  // are kept so that either version can be compiled
  digest_ctx sha256_handshake_digest;
  char *unread_buffer;
  int unread_length;

  // Session resumption
  int session_id_length;
  unsigned char session_id[ MAX_SESSION_ID_LENGTH ];

  // Secure renegotiation, RFC 5746
  int support_secure_renegotiation;
  unsigned char client_verify_data[ VERIFY_DATA_LEN ];
  unsigned char server_verify_data[ VERIFY_DATA_LEN ];
}
TLSParameters;

/**
 * TLS 1.2 signature and hash algorithm identifiers (RFC 5246 7.4.1.4.1)
 */
typedef enum
{
  none = 0,
  md5 = 1,
  sha1 = 2,
  sha224 = 3,
  sha256 = 4,
  sha384 = 5,
  sha512 = 6
}
HashAlgorithm;

typedef enum
{
  anonymous = 0,
  sig_rsa = 1,
  sig_dsa = 2,
  sig_ecdsa = 3
}
SignatureAlgorithm;

/** This lists the type of higher-level TLS protocols that are defined */
typedef enum {
  content_change_cipher_spec = 20,
  content_alert = 21,
  content_handshake = 22,
  content_application_data = 23
}
ContentType;

typedef enum { warning = 1, fatal = 2 } AlertLevel;

/**
 * Enumerate all of the error conditions specified by TLS.
 */
typedef enum
{
  close_notify = 0,
  unexpected_message = 10,
  bad_record_mac = 20,
  decryption_failed = 21,
  record_overflow = 22,
  decompression_failure = 30,
  handshake_failure = 40,
  bad_certificate = 42,
  unsupported_certificate = 43,
  certificate_revoked = 44,
  certificate_expired = 45,
  certificate_unknown = 46,
  illegal_parameter = 47,
  unknown_ca = 48,
  access_denied = 49,
  decode_error = 50,
  decrypt_error = 51,
  export_restriction = 60,
  protocol_version = 70,
  insufficient_security = 71,
  internal_error = 80,
  user_canceled = 90,
  no_renegotiation = 100
}
AlertDescription;

typedef struct
{
  unsigned char level;
  unsigned char description;
}
Alert;

typedef struct
{
  unsigned char major, minor;
}
ProtocolVersion;

/**
 * Each packet to be encrypted is first inserted into one of these structures.
 */
typedef struct
{
  unsigned char type;
  ProtocolVersion version;
  unsigned short length;
}
TLSPlaintext;

typedef struct
{
  unsigned int gmt_unix_time;
  unsigned char random_bytes[ 28 ];
}
Random;

/**
 * Handshake message types (section 7.4)
 */
typedef enum
{
  hello_request = 0,
  client_hello = 1,
  server_hello = 2,
  certificate = 11,
  server_key_exchange = 12,
  certificate_request = 13,
  server_hello_done = 14,
  certificate_verify = 15,
  client_key_exchange = 16,
  finished = 20
}
HandshakeType;

/**
 * Handshake record definition (section 7.4)
 */
typedef struct
{
  unsigned char msg_type;
  unsigned int length; // 24 bits(!)
}
Handshake;

/**
 * Section 7.4.1.2
 */
typedef struct
{
  ProtocolVersion client_version;
  Random random;
  unsigned char session_id_length;
  unsigned char *session_id;
  unsigned short cipher_suites_length;
  unsigned short *cipher_suites;
  unsigned char compression_methods_length;
  unsigned char *compression_methods;
}
ClientHello;

typedef struct
{
  ProtocolVersion server_version;
  Random random;
  unsigned char session_id_length;
  unsigned char session_id[ 32 ]; // technically, this len should be dynamic.
  unsigned short cipher_suite;
  unsigned char compression_method;
}
ServerHello;

/**
 * Negotiate an TLS channel on an already-established connection
 * (or die trying).
 * @return 1 if successful, 0 if not.
 */
int tls_connect( int connection,
                 TLSParameters *parameters,
                 int renegotiate );

/**
 * Resume a previously negotiated session.
 */
int tls_resume( int connection,
                int session_id_length,
                const unsigned char *session_id,
                const unsigned char *master_secret,
                TLSParameters *parameters );

/**
 * Initialize the server-side session cache; call once at startup.
 */
void init_tls();

/** Test hook: the single cipher suite the client hello offers. */
void tls_set_client_cipher_suite( unsigned short suite );

/**
 * Restrict the protocol versions this side negotiates, as minor version
 * numbers (TLS_1_0 .. TLS_1_2). Applies to clients and servers.
 */
void tls_set_version_range( int min_version, int max_version );

/**
 * Make clients verify the server's certificate chain against the roots in
 * ca_file (a PEM bundle) and, if hostname isn't NULL, check that the leaf
 * certificate names it; hostname is also sent as SNI. ca_file NULL turns
 * verification off (the original behavior). Returns the number of roots
 * loaded, or -1.
 */
int tls_set_verify( const char *ca_file, const char *hostname );

/**
 * The certificate chain and RSA key this side presents: the server's
 * identity, or the client's when the server asks for one. See
 * credentials.h for the accepted formats. Without this the server falls
 * back to the original cert.der + key.pkcs8 ("password"), and the client to
 * cert.der + key.der. Returns 0 on success.
 */
int tls_set_credentials( const char *cert_file, const char *key_file,
                         const char *password );

/**
 * Wait for a client hello and negotiate a TLS channel as the server
 *. Expects cert.der and key.pkcs8 in the working directory.
 * @return 0 if successful, non-zero if not.
 */
int tls_accept( int connection,
                TLSParameters *parameters );

/**
 * Send data over an established TLS channel. tls_connect must already
 * have been called with this socket as a parameter.
 */
int tls_send( int connection,
              const char *application_data,
              int length,
              int options,
              TLSParameters *parameters );
/**
 * Received data from an established TLS channel.
 */
int tls_recv( int connection,
              char *target_buffer,
              int buffer_size,
              int options,
              TLSParameters *parameters );

/**
 * Orderly shutdown of the TLS channel (note that the socket itself will
 * still be open after this is called).
 */
int tls_shutdown( int connection, TLSParameters *parameters );

#endif
