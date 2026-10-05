#ifndef X509_H
#define X509_H

#include <time.h>
#include "huge.h"
#include "rsa.h"
#include "dsa.h"
#include "ecc.h"

typedef enum
{
  rsa,
  dsa,
  dh,
  ecdsa,
  unsupported_key // e.g. P-384 or Ed25519; parsed but unusable
}
algorithmIdentifier;

typedef enum
{
  md5WithRSAEncryption,
  shaWithRSAEncryption,
  shaWithDSA,
  sha256WithECDSA,
  sha256WithRSAEncryption,      // 
  sha384WithRSAEncryption,
  sha512WithRSAEncryption,
  sha384WithECDSA,
  unsupportedSignatureAlgorithm // parsed, but can't be verified
}
signatureAlgorithmIdentifier;

/**
 * A name (or "distinguishedName") is a list of attribute-value pairs.
 * Instead of keeping track of all of them, just keep track of
 * the most interesting ones.
 */
typedef struct
{
  char *idAtCountryName;
  char *idAtStateOrProvinceName;
  char *idAtLocalityName;
  char *idAtOrganizationName;
  char *idAtOrganizationalUnitName;
  char *idAtCommonName;
}
name;

typedef struct
{
  // TODO deal with the "utcTime" or "GeneralizedTime" choice.
  time_t notBefore;
  time_t notAfter;
}
validity_period;

typedef huge uniqueIdentifier;

typedef struct
{
  algorithmIdentifier algorithm;
  // RSA parameters, only if algorithm == rsa
  rsa_key rsa_public_key;
  // DSA or DH parameters, only if algorithm == dsa
  dsa_params dsa_parameters;
  // DSA parameters, only if algorithm == dsa
  huge dsa_public_key;
  // ECDSA curve and public key, only if algorithm == ecdsa
  elliptic_curve ecdsa_curve;
  point ecdsa_public_key;
}
public_key_info;

typedef huge objectIdentifier;

#define MAX_DNS_NAMES 64

typedef struct
{
  int version;
  huge serialNumber; // This can be much longer than a 4-byte long allows
  signatureAlgorithmIdentifier signature;
  name issuer;
  validity_period validity;
  name subject;
  public_key_info subjectPublicKeyInfo;
  uniqueIdentifier issuerUniqueId;
  uniqueIdentifier subjectUniqueId;
  int certificate_authority; // 1 if this is a CA, 0 if not
  // what chain verification needs
  unsigned char *issuer_der;   // raw issuer / subject names, for matching
  int issuer_der_len;          // a certificate to its issuer
  unsigned char *subject_der;
  int subject_der_len;
  int basic_constraints_ca;    // basicConstraints cA flag
  int dns_names_count;         // subjectAltName dNSName entries
  char *dns_names[ MAX_DNS_NAMES ];
}
x509_certificate;

typedef struct
{
  x509_certificate tbsCertificate;
  unsigned int *hash; // hash code of tbsCertificate
  int hash_len;
  signatureAlgorithmIdentifier algorithm;
  huge rsa_signature_value;
  dsa_signature dsa_signature_value;
}
signed_x509_certificate;

void init_x509_certificate( signed_x509_certificate *certificate );
int parse_x509_certificate( const unsigned char *buffer,
                            const unsigned int certificate_length,
                            signed_x509_certificate *parsed_certificate );
void free_x509_certificate( signed_x509_certificate *certificate );
struct asn1struct;
int parse_name( name *target, struct asn1struct *source );

/**
 * Check that certificate's signature was made by issuer_key.
 */
int x509_verify_signature( signed_x509_certificate *certificate,
                           public_key_info *issuer_key );

/**
 * Load every certificate from a PEM bundle (e.g.
 * /etc/ssl/certs/ca-certificates.crt). Returns the number loaded, or -1.
 * Certificates that fail to parse are skipped.
 */
int x509_load_pem_bundle( const char *path,
                          signed_x509_certificate **certificates );

typedef enum
{
  X509_OK = 0,
  X509_BAD_SIGNATURE,
  X509_UNTRUSTED,
  X509_EXPIRED,
  X509_NOT_YET_VALID,
  X509_NOT_A_CA,
  X509_HOSTNAME_MISMATCH,
  X509_EMPTY_CHAIN
}
x509_verify_result;

const char *x509_verify_result_string( x509_verify_result result );

/**
 * Verify a chain sent by a peer (leaf first): every certificate is within
 * its validity period at "now", is signed by the next one (which must be a
 * CA), and the last one is, or is signed by, one of the trusted roots. If
 * hostname is not NULL, the leaf must name it in its subjectAltName
 * dNSNames (or, if it has none, its common name); "*." wildcards match one
 * label.
 */
x509_verify_result x509_verify_chain( signed_x509_certificate *chain,
                                      int chain_length,
                                      signed_x509_certificate *roots,
                                      int roots_count,
                                      const char *hostname,
                                      time_t now );

/**
 * Parse a TLS certificate message body into an array of certificates
 * (leaf first); returns the count, or -1 on error.
 */
int parse_x509_chain_all( unsigned char *buffer,
                          int pdu_length,
                          signed_x509_certificate **chain );
char *parse_x509_chain( unsigned char *buffer,
                        int pdu_length,
                        public_key_info *server_public_key );

#endif
