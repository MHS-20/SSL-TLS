#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>
#include "x509.h"
#include "ecdsa.h"
#include "asn1.h"
#include "md5.h"
#include "sha.h"
#include "sha512.h"
#include "hex.h"

void init_x509_certificate( signed_x509_certificate *certificate )
{
  set_huge( &certificate->tbsCertificate.serialNumber, 1 );
  memset( &certificate->tbsCertificate.issuer, 0, sizeof( name ) );
  memset( &certificate->tbsCertificate.subject, 0, sizeof( name ) );
  certificate->tbsCertificate.subjectPublicKeyInfo.rsa_public_key.modulus =
    malloc( sizeof( huge ) );
  certificate->tbsCertificate.subjectPublicKeyInfo.rsa_public_key.exponent =
    malloc( sizeof( huge ) );
  set_huge(
    certificate->tbsCertificate.subjectPublicKeyInfo.rsa_public_key.modulus,
    0 );
  set_huge(
    certificate->tbsCertificate.subjectPublicKeyInfo.rsa_public_key.exponent,
    0 );
  set_huge( &certificate->rsa_signature_value, 0 );
  set_huge( &certificate->dsa_signature_value.r, 0 );
  set_huge( &certificate->dsa_signature_value.s, 0 );
  certificate->hash = NULL;
  certificate->tbsCertificate.certificate_authority = 0;
  certificate->tbsCertificate.issuer_der = NULL;
  certificate->tbsCertificate.issuer_der_len = 0;
  certificate->tbsCertificate.subject_der = NULL;
  certificate->tbsCertificate.subject_der_len = 0;
  certificate->tbsCertificate.basic_constraints_ca = 0;
  certificate->tbsCertificate.dns_names_count = 0;
}

static void free_x500_name( name *x500_name )
{
  if ( x500_name->idAtCountryName ) { free( x500_name->idAtCountryName ); }
  if ( x500_name->idAtStateOrProvinceName ) { free( x500_name->idAtStateOrProvinceName ); }
  if ( x500_name->idAtLocalityName ) { free( x500_name->idAtLocalityName ); }
  if ( x500_name->idAtOrganizationName ) { free( x500_name->idAtOrganizationName ); }
  if ( x500_name->idAtOrganizationalUnitName ) { free( x500_name->idAtOrganizationalUnitName ); }
  if ( x500_name->idAtCommonName ) { free( x500_name->idAtCommonName ); }
}

void free_x509_certificate( signed_x509_certificate *certificate )
{
  free_huge( &certificate->tbsCertificate.serialNumber );
  free_x500_name( &certificate->tbsCertificate.issuer );
  free_x500_name( &certificate->tbsCertificate.subject );
  free_huge(
    certificate->tbsCertificate.subjectPublicKeyInfo.rsa_public_key.modulus );
  free_huge(
    certificate->tbsCertificate.subjectPublicKeyInfo.rsa_public_key.exponent );
  free(
    certificate->tbsCertificate.subjectPublicKeyInfo.rsa_public_key.modulus );
  free(
    certificate->tbsCertificate.subjectPublicKeyInfo.rsa_public_key.exponent );
  free_huge( &certificate->rsa_signature_value );
  if ( certificate->hash )
  {
    free( certificate->hash );
  }
  free( certificate->tbsCertificate.issuer_der );
  free( certificate->tbsCertificate.subject_der );
  while ( certificate->tbsCertificate.dns_names_count )
  {
    free( certificate->tbsCertificate.dns_names[
      --certificate->tbsCertificate.dns_names_count ] );
  }
}

static int parse_huge( huge *target, struct asn1struct *source )
{
  target->sign = 0;
  target->size = source->length;
  target->rep = ( char * ) malloc( target->size );
  memcpy( target->rep, source->data, target->size );

  return 0;
}

static const unsigned char OID_md5WithRSA[] =
  { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04 };
static const unsigned char OID_sha1WithRSA[] =
  { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05 };
static const unsigned char OID_sha1WithDSA[] =
  { 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x03 };
static const unsigned char OID_sha256WithECDSA[] =
  { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
static const unsigned char OID_sha256WithRSA[] =
  { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B };
static const unsigned char OID_sha384WithRSA[] =
  { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C };
static const unsigned char OID_sha512WithRSA[] =
  { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D };
static const unsigned char OID_sha384WithECDSA[] =
  { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03 };

#define OID_IS( node, oid ) \
  ( ( node )->length == sizeof( oid ) && \
    !memcmp( ( node )->data, oid, sizeof( oid ) ) )

static int parse_algorithm_identifier( signatureAlgorithmIdentifier *target,
                                       struct asn1struct *source )
{
  struct asn1struct *oid = ( struct asn1struct * ) source->children;

  if ( OID_IS( oid, OID_md5WithRSA ) )
  {
    *target = md5WithRSAEncryption;
  }
  else if ( OID_IS( oid, OID_sha1WithRSA ) )
  {
    *target = shaWithRSAEncryption;
  }
  else if ( OID_IS( oid, OID_sha1WithDSA ) )
  {
    *target = shaWithDSA;
  }
  else if ( OID_IS( oid, OID_sha256WithECDSA ) )
  {
    *target = sha256WithECDSA;
  }
  else if ( OID_IS( oid, OID_sha256WithRSA ) )
  {
    *target = sha256WithRSAEncryption;
  }
  else if ( OID_IS( oid, OID_sha384WithRSA ) )
  {
    *target = sha384WithRSAEncryption;
  }
  else if ( OID_IS( oid, OID_sha512WithRSA ) )
  {
    *target = sha512WithRSAEncryption;
  }
  else if ( OID_IS( oid, OID_sha384WithECDSA ) )
  {
    *target = sha384WithECDSA;
  }
  else
  {
    *target = unsupportedSignatureAlgorithm;
  }

  return 0;
}

static unsigned char OID_idAtCommonName[] = { 0x55, 0x04, 0x03 };
static unsigned char OID_idAtCountryName[] = { 0x55, 0x04, 0x06 };
static unsigned char OID_idAtLocalityName[] = { 0x55, 0x04, 0x07 };
static unsigned char OID_idAtStateOrProvinceName[] = { 0x55, 0x04, 0x08 };
static unsigned char OID_idAtOrganizationName[] = { 0x55, 0x04, 0x0A };
static unsigned char OID_idAtOrganizationalUnitName[] = { 0x55, 0x04, 0x0B };

static char *copy_value( struct asn1struct *value )
{
  char *target = ( char * ) malloc( value->length + 1 );
  memcpy( target, value->data, value->length );
  target[ value->length ] = 0;

  return target;
}

/**
 * Name parsing is a bit different. Loop through all of the
 * children of the source, each of which is going to be a struct containing
 * an OID and a value. If the OID is recognized, copy its contents
 * to the correct spot in "target". Otherwise, ignore it.
 */
int parse_name( name *target, struct asn1struct *source )
{
  struct asn1struct *typeValuePair;
  struct asn1struct *typeValuePairSequence;
  struct asn1struct *type;
  struct asn1struct *value;

  target->idAtCountryName = NULL;
  target->idAtStateOrProvinceName = NULL;
  target->idAtLocalityName = NULL;
  target->idAtOrganizationName = NULL;
  target->idAtOrganizationalUnitName = NULL;
  target->idAtCommonName = NULL;

  typeValuePair = source->children;
  while ( typeValuePair )
  {
    typeValuePairSequence = ( struct asn1struct * ) typeValuePair->children;
    type = ( struct asn1struct * ) typeValuePairSequence->children;
    value = ( struct asn1struct * ) type->next;

    if ( !memcmp( type->data, OID_idAtCountryName, type->length ) )
    {
      target->idAtCountryName = copy_value( value );
    }
    else if ( !memcmp( type->data, OID_idAtStateOrProvinceName, type->length ) )
    {
      target->idAtStateOrProvinceName = copy_value( value );
    }
    else if ( !memcmp( type->data, OID_idAtLocalityName, type->length ) )
    {
      target->idAtLocalityName = copy_value( value );
    }
    else if ( !memcmp( type->data, OID_idAtOrganizationName, type->length ) )
    {
      target->idAtOrganizationName = copy_value( value );
    }
    else if ( !memcmp( type->data, OID_idAtOrganizationalUnitName,
                       type->length ) )
    {
      target->idAtOrganizationalUnitName = copy_value( value );
    }
    else if ( !memcmp( type->data, OID_idAtCommonName, type->length ) )
    {
      target->idAtCommonName = copy_value( value );
    }
    else
    {
      int i;

      // This is just advisory - NOT a problem
    }

    typeValuePair = typeValuePair->next;
  }

  return 0;
}

/**
 * UTCTime is YYMMDDHHMMSSZ (YY < 50 means 20YY, RFC 5280 4.1.2.5.1);
 * GeneralizedTime is YYYYMMDDHHMMSSZ. Both are UTC.
 */
static int parse_time( struct asn1struct *time, struct tm *target )
{
  char text[ 16 ];
  int year_digits = ( time->tag == ASN1_GENERALIZED_TIME ) ? 4 : 2;

  if ( time->length < year_digits + 10 || time->length >= sizeof( text ) )
  {
    return 1;
  }
  memcpy( text, time->data, time->length );
  text[ time->length ] = '\0';

  if ( sscanf( text, year_digits == 4 ? "%4d%2d%2d%2d%2d%2d" :
                                        "%2d%2d%2d%2d%2d%2d",
       &target->tm_year, &target->tm_mon, &target->tm_mday,
       &target->tm_hour, &target->tm_min, &target->tm_sec ) < 6 )
  {
    return 1;
  }

  if ( year_digits == 2 )
  {
    target->tm_year += ( target->tm_year < 50 ) ? 2000 : 1900;
  }
  target->tm_year -= 1900;
  target->tm_mon -= 1;

  return 0;
}

static int parse_validity( validity_period *target, struct asn1struct *source )
{
  struct asn1struct *not_before;
  struct asn1struct *not_after;
  struct tm not_before_tm;
  struct tm not_after_tm;

  not_before = source->children;
  not_after = not_before->next;

  memset( &not_before_tm, 0, sizeof( struct tm ) );
  memset( &not_after_tm, 0, sizeof( struct tm ) );

  // Convert time instances into time_t
  if ( parse_time( not_before, &not_before_tm ) )
  {
    fprintf( stderr, "Error parsing not before; malformed date." );
    return 6;
  }
  if ( parse_time( not_after, &not_after_tm ) )
  {
    fprintf( stderr, "Error parsing not after; malformed date." );
    return 7;
  }

  target->notBefore = timegm( &not_before_tm );
  target->notAfter = timegm( &not_after_tm );

  return 0;
}

static int parse_dsa_params( public_key_info *target, struct asn1struct *source )
{
  struct asn1struct *p;
  struct asn1struct *q;
  struct asn1struct *g;

  p = source->children;
  q = p->next;
  g = q->next;

  parse_huge( &target->dsa_parameters.p, p );
  parse_huge( &target->dsa_parameters.q, q );
  parse_huge( &target->dsa_parameters.g, g );

  return 0;
}

static const unsigned char OID_RSA[] =
  { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
static const unsigned char OID_DSA[] =
  { 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01 };
static const unsigned char OID_DH[] =
  { 0x2A, 0x86, 0x48, 0xCE, 0x3E, 0x02, 0x01 };
static const unsigned char OID_ECDSA[] =
  { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
// A.K.A. secp192R1, AKA NIST P-192
static const unsigned char OID_PRIME192V1[] =
  { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01 };
// A.K.A. secp256R1, AKA NIST P-256 
static const unsigned char OID_PRIME256V1[] =
  { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static const unsigned char OID_SECP384R1[] =
  { 0x2B, 0x81, 0x04, 0x00, 0x22 };

static int parse_public_key_info( public_key_info *target,
                                  struct asn1struct *source )
{
  struct asn1struct *oid;
  struct asn1struct *public_key;
  struct asn1struct public_key_value;

  oid = source->children->children;
  public_key = source->children->next;

  if ( !memcmp( oid->data, &OID_ECDSA, sizeof( OID_ECDSA ) ) )
  {
    // TODO this only supports named curves.
    struct asn1struct *curve = oid->next;
    target->algorithm = ecdsa;

    if ( !memcmp( curve->data, &OID_PRIME192V1, sizeof( OID_PRIME192V1 ) ) )
    {
      // TODO generate a mapping of OIDs to curve names
      if ( get_named_curve( "prime192v1", &target->ecdsa_curve ) )
      {
        return 1;
      }
    }
    else if ( !memcmp( curve->data, &OID_PRIME256V1,
                       sizeof( OID_PRIME256V1 ) ) )
    {
      if ( get_named_curve( "prime256v1", &target->ecdsa_curve ) )
      {
        return 1;
      }
    }
    else if ( OID_IS( curve, OID_SECP384R1 ) )
    {
      get_named_curve( "secp384r1", &target->ecdsa_curve );
    }
    else
    {
      target->algorithm = unsupported_key;
      return 0;
    }

    // Skip the bit string's leading 0 byte and the X9.62
    // compressed/uncompressed marker; the rest is x followed by y.
    load_huge( &target->ecdsa_public_key.x, public_key->data + 2,
      ( public_key->length - 2 ) / 2 );
    load_huge( &target->ecdsa_public_key.y,
      ( public_key->data + 2 ) + ( ( public_key->length - 2 ) / 2 ),
      ( public_key->length - 2 ) / 2 );

    return 0;
  }

  if ( !OID_IS( oid, OID_RSA ) && !OID_IS( oid, OID_DSA ) )
  {
    target->algorithm = unsupported_key;
    return 0;
  }

  // The public key is a bit string encoding yet another ASN.1 DER-encoded
  // value - need to parse *that* here
  // Skip over the "0" byte in the public key.
  if ( asn1parse( public_key->data + 1,
                  public_key->length - 1,
                  &public_key_value ) )
  {
    fprintf( stderr,
      "Error; public key node is malformed (not ASN.1 DER-encoded)\n" );
    return 5;
  }

  if ( !memcmp( oid->data, &OID_RSA, sizeof( OID_RSA ) ) )
  {
    target->algorithm = rsa;
    parse_huge( target->rsa_public_key.modulus, public_key_value.children );
    parse_huge( target->rsa_public_key.exponent,
      public_key_value.children->next );
    // This is important. Most times, the response includes a trailing 0 byte
    // to stop implementations from interpreting it as a twos-complement
    // negative number. However, in this implementation, this causes the
    // results to be the wrong size, so they need to be contracted.
    contract( target->rsa_public_key.modulus );
    contract( target->rsa_public_key.exponent );
  }
  else if ( !memcmp( oid->data, &OID_DSA, sizeof( OID_DSA ) ) )
  {
    struct asn1struct *params;
    target->algorithm = dsa;
    parse_huge( &target->dsa_public_key, &public_key_value );
    params = oid->next;
    parse_dsa_params( target, params );
  }
  else
  {
    target->algorithm = unsupported_key;
  }

  asn1free( &public_key_value );

  return 0;
}

static const unsigned char OID_keyUsage[] = { 0x55, 0x1D, 0x0F };
static const unsigned char OID_basicConstraints[] = { 0x55, 0x1D, 0x13 };
static const unsigned char OID_subjectAltName[] = { 0x55, 0x1D, 0x11 };
#define GENERAL_NAME_DNS 2
#define BIT_CERT_SIGNER 5

static int parse_extension( x509_certificate *certificate,
                            struct asn1struct *source )
{
  struct asn1struct *oid;
  struct asn1struct *critical;
  struct asn1struct *data;

  oid = ( struct asn1struct * ) source->children;
  critical = ( struct asn1struct * ) oid->next;
  if ( critical->tag == ASN1_BOOLEAN )
  {
    data = ( struct asn1struct * ) critical->next;
  }
  else
  {
    // critical defaults to false
    data = critical;
    critical = NULL;
  }

  if ( OID_IS( oid, OID_keyUsage ) )
  {
    struct asn1struct key_usage_bit_string;
    asn1parse( data->data, data->length, &key_usage_bit_string );
    if ( asn1_get_bit( key_usage_bit_string.length,
                       key_usage_bit_string.data,
                       BIT_CERT_SIGNER ) )
    {
      certificate->certificate_authority = 1;
    }
    asn1free( &key_usage_bit_string );
  }

  else if ( OID_IS( oid, OID_basicConstraints ) )
  {
    // SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPT }
    struct asn1struct constraints;
    if ( !asn1parse( data->data, data->length, &constraints ) )
    {
      if ( constraints.children &&
           constraints.children->tag == ASN1_BOOLEAN &&
           constraints.children->length == 1 &&
           constraints.children->data[ 0 ] )
      {
        certificate->basic_constraints_ca = 1;
      }
      asn1free( &constraints );
    }
  }
  else if ( OID_IS( oid, OID_subjectAltName ) )
  {
    // SEQUENCE OF GeneralName; dNSName is [2] IA5String
    struct asn1struct names;
    struct asn1struct *general_name;
    if ( !asn1parse( data->data, data->length, &names ) )
    {
      for ( general_name = names.children; general_name;
            general_name = general_name->next )
      {
        if ( general_name->tag_class == ASN1_CONTEXT_SPECIFIC &&
             general_name->tag == GENERAL_NAME_DNS &&
             certificate->dns_names_count < MAX_DNS_NAMES )
        {
          char *dns_name = malloc( general_name->length + 1 );
          memcpy( dns_name, general_name->data, general_name->length );
          dns_name[ general_name->length ] = '\0';
          certificate->dns_names[ certificate->dns_names_count++ ] = dns_name;
        }
      }
      asn1free( &names );
    }
  }

  return 0;
}

static int parse_extensions( x509_certificate *certificate,
                             struct asn1struct *source )
{
  // Parse each extension; if one is recognized, update the certificate
  // in some way
  source = source->children->children;
  while ( source )
  {
    if ( parse_extension( certificate, source ) )
    {
      return 1;
    }
    source = source->next;
  }

  return 0;
}

static int parse_tbs_certificate( x509_certificate *target,
                                  struct asn1struct *source )
{
  struct asn1struct *version;
  struct asn1struct *serialNumber;
  struct asn1struct *signatureAlgorithmIdentifier;
  struct asn1struct *issuer;
  struct asn1struct *validity;
  struct asn1struct *subject;
  struct asn1struct *publicKeyInfo;
  struct asn1struct *extensions;

  // Figure out if there's an explicit version or not; if there is, then
  // everything else "shifts down" one spot.
  version = ( struct asn1struct * ) source->children;

  if ( version->tag == 0 && version->tag_class == ASN1_CONTEXT_SPECIFIC )
  {
    struct asn1struct *versionNumber =
      ( struct asn1struct * ) version->children;

    // This will only ever be one byte; safe
    target->version = ( *versionNumber->data ) + 1;
    serialNumber = ( struct asn1struct * ) version->next;
  }
  else
  {
    target->version = 1; // default if not provided
    serialNumber = ( struct asn1struct * ) version;
  }

  signatureAlgorithmIdentifier = ( struct asn1struct * ) serialNumber->next;
  issuer = ( struct asn1struct * ) signatureAlgorithmIdentifier->next;
  validity = ( struct asn1struct * ) issuer->next;
  subject = ( struct asn1struct * ) validity->next;
  publicKeyInfo = ( struct asn1struct * ) subject->next;
  extensions = ( struct asn1struct * ) publicKeyInfo->next;

  if ( parse_huge( &target->serialNumber, serialNumber ) ) { return 2; }
  if ( parse_algorithm_identifier( &target->signature,
                                   signatureAlgorithmIdentifier ) )
    { return 3; }
  if ( parse_name( &target->issuer, issuer ) ) { return 4; }
  target->issuer_der = malloc( issuer->length );
  memcpy( target->issuer_der, issuer->data, issuer->length );
  target->issuer_der_len = issuer->length;
  target->subject_der = malloc( subject->length );
  memcpy( target->subject_der, subject->data, subject->length );
  target->subject_der_len = subject->length;
  if ( parse_validity( &target->validity, validity ) ) { return 5; }
  if ( parse_name( &target->subject, subject ) ) { return 6; }
  if ( parse_public_key_info( &target->subjectPublicKeyInfo, publicKeyInfo ) )
    { return 7; }
  if ( extensions )
  {
    if ( parse_extensions( target, extensions ) ) { return 8; }
  }

  return 0;
}

static int parse_rsa_signature_value( signed_x509_certificate *target,
                                      struct asn1struct *source )
{
  parse_huge( &target->rsa_signature_value, source );
  contract( &target->rsa_signature_value );

  return 0;
}

static int parse_dsa_signature_value( signed_x509_certificate *target,
                                      struct asn1struct *source )
{
  struct asn1struct dsa_signature;

  if ( asn1parse( source->data + 1, source->length - 1, &dsa_signature ) )
  {
    fprintf( stderr, "Unable to parse ASN.1 DER-encoded signature.\n" );
    return 1;
  }

  parse_huge( &target->dsa_signature_value.r, dsa_signature.children );
  parse_huge( &target->dsa_signature_value.s, dsa_signature.children->next );
  contract( &target->dsa_signature_value.r );
  contract( &target->dsa_signature_value.s );

  asn1free( &dsa_signature );

  return 0;
}

int parse_x509_certificate( const unsigned char *buffer,
                            const unsigned int certificate_length,
                            signed_x509_certificate *parsed_certificate )
{
  struct asn1struct certificate;
  struct asn1struct *tbsCertificate;
  struct asn1struct *algorithmIdentifier;
  struct asn1struct *signatureValue;
  digest_ctx digest;

  // First, read the whole thing into a traversable ASN.1 structure
  asn1parse( buffer, certificate_length, &certificate );

  tbsCertificate = ( struct asn1struct * ) certificate.children;
  algorithmIdentifier = ( struct asn1struct * ) tbsCertificate->next;
  signatureValue = ( struct asn1struct * ) algorithmIdentifier->next;

  if ( parse_tbs_certificate( &parsed_certificate->tbsCertificate,
                              tbsCertificate ) )
  {
    fprintf( stderr, "Error trying to parse TBS certificate\n" );
    return 42;
  }
  if ( parse_algorithm_identifier( &parsed_certificate->algorithm,
                                   algorithmIdentifier ) )
  {
    return 42;
  }

  switch ( parsed_certificate->algorithm )
  {
    case md5WithRSAEncryption:
    case shaWithRSAEncryption:
    case sha256WithRSAEncryption:
    case sha384WithRSAEncryption:
    case sha512WithRSAEncryption:
      if ( parse_rsa_signature_value( parsed_certificate, signatureValue ) )
      {
        return 42;
      }
      break;
    case shaWithDSA:
    case sha256WithECDSA:
    case sha384WithECDSA:
      if ( parse_dsa_signature_value( parsed_certificate, signatureValue ) )
      {
        return 42;
      }
      break;
  }

  switch ( parsed_certificate->algorithm )
  {
    case md5WithRSAEncryption:
      new_md5_digest( &digest );
      break;
    case shaWithRSAEncryption:
    case shaWithDSA:
      new_sha1_digest( &digest );
      break;
    case sha256WithECDSA:
    case sha256WithRSAEncryption:
      new_sha256_digest( &digest );
      break;
    case sha384WithECDSA:
    case sha384WithRSAEncryption:
      new_sha384_digest( &digest );
      break;
    case sha512WithRSAEncryption:
      new_sha512_digest( &digest );
      break;
    default:
      parsed_certificate->hash = NULL;
      parsed_certificate->hash_len = 0;
      asn1free( &certificate );
      return 0;
  }

  update_digest( &digest, tbsCertificate->data, tbsCertificate->length );
  finalize_digest( &digest );

  parsed_certificate->hash = digest.hash;
  parsed_certificate->hash_len = digest.hash_len;

  asn1free( &certificate );

  return 0;
}


/**
 * This is called by "receive_server_hello" when the "certificate" PDU
 * is encountered. The input to this function should be a certificate chain.
 * The most important certificate is the first one, since this contains the
 * public key of the subject as well as the DNS name information (which
 * has to be verified against).
 * Each subsequent certificate acts as a signer for the previous certificate.
 * Each signature is verified by this function.
 * The public key of the first certificate in the chain will be returned in
 * "server_public_key" (subsequent certificates are just needed for signature
 * verification).
 * TODO verify signatures.
 */
char *parse_x509_chain( unsigned char *buffer,
                        int pdu_length,
                        public_key_info *server_public_key )
{
  int pos;
  signed_x509_certificate certificate;
  unsigned int chain_length, certificate_length;
  unsigned char *ptr;

  ptr = buffer;

  pos = 0;

  // TODO this won't work on a big-endian machine
  chain_length = ( *ptr << 16 ) | ( *( ptr + 1 ) << 8 ) | ( *( ptr + 2 ) );
  ptr += 3;

  // The chain length is actually redundant since the length of the PDU has
  // already been input.
  assert ( chain_length == ( pdu_length - 3 ) );

  while ( ( ptr - buffer ) < pdu_length )
  {
    // TODO this won't work on a big-endian machine
    certificate_length = ( *ptr << 16 ) | ( *( ptr + 1 ) << 8 ) |
      ( *( ptr + 2 ) );
    ptr += 3;

    init_x509_certificate( &certificate );

    parse_x509_certificate( ( void * ) ptr, certificate_length, &certificate );
    if ( !pos++ )
    {
      server_public_key->algorithm =
        certificate.tbsCertificate.subjectPublicKeyInfo.algorithm;
      switch ( server_public_key->algorithm )
      {
        case rsa:
          server_public_key->rsa_public_key.modulus =
            ( huge * ) malloc( sizeof( huge ) );
          server_public_key->rsa_public_key.exponent =
            ( huge * ) malloc( sizeof( huge ) );
          set_huge( server_public_key->rsa_public_key.modulus, 0 );
          set_huge( server_public_key->rsa_public_key.exponent, 0 );
          copy_huge( server_public_key->rsa_public_key.modulus,
            certificate.tbsCertificate.subjectPublicKeyInfo.
            rsa_public_key.modulus );
          copy_huge( server_public_key->rsa_public_key.exponent,
            certificate.tbsCertificate.subjectPublicKeyInfo.
            rsa_public_key.exponent );
          break;
        case dsa:
          set_huge( &server_public_key->dsa_parameters.g, 0 );
          set_huge( &server_public_key->dsa_parameters.p, 0 );
          set_huge( &server_public_key->dsa_parameters.q, 0 );
          set_huge( &server_public_key->dsa_public_key, 0 );
          copy_huge( &server_public_key->dsa_parameters.g,
            &certificate.tbsCertificate.subjectPublicKeyInfo.dsa_parameters.g );
          copy_huge( &server_public_key->dsa_parameters.p,
            &certificate.tbsCertificate.subjectPublicKeyInfo.dsa_parameters.p );
          copy_huge( &server_public_key->dsa_parameters.q,
            &certificate.tbsCertificate.subjectPublicKeyInfo.dsa_parameters.q );
          copy_huge( &server_public_key->dsa_public_key,
            &certificate.tbsCertificate.subjectPublicKeyInfo.dsa_public_key );
          break;
        case ecdsa:
          set_huge( &server_public_key->ecdsa_curve.a, 0 );
          set_huge( &server_public_key->ecdsa_curve.b, 0 );
          set_huge( &server_public_key->ecdsa_curve.G.x, 0 );
          set_huge( &server_public_key->ecdsa_curve.G.y, 0 );
          set_huge( &server_public_key->ecdsa_curve.p, 0 );
          set_huge( &server_public_key->ecdsa_curve.n, 0 );
          set_huge( &server_public_key->ecdsa_public_key.x, 0 );
          set_huge( &server_public_key->ecdsa_public_key.y, 0 );
          copy_huge( &server_public_key->ecdsa_curve.a,
            &certificate.tbsCertificate.subjectPublicKeyInfo.ecdsa_curve.a );
          copy_huge( &server_public_key->ecdsa_curve.b,
            &certificate.tbsCertificate.subjectPublicKeyInfo.ecdsa_curve.b );
          copy_huge( &server_public_key->ecdsa_curve.G.x,
            &certificate.tbsCertificate.subjectPublicKeyInfo.ecdsa_curve.G.x );
          copy_huge( &server_public_key->ecdsa_curve.G.y,
            &certificate.tbsCertificate.subjectPublicKeyInfo.ecdsa_curve.G.y );
          copy_huge( &server_public_key->ecdsa_curve.p,
            &certificate.tbsCertificate.subjectPublicKeyInfo.ecdsa_curve.p );
          copy_huge( &server_public_key->ecdsa_curve.n,
            &certificate.tbsCertificate.subjectPublicKeyInfo.ecdsa_curve.n );
          copy_huge( &server_public_key->ecdsa_public_key.x,
            &certificate.tbsCertificate.subjectPublicKeyInfo.ecdsa_public_key.x );
          copy_huge( &server_public_key->ecdsa_public_key.y,
            &certificate.tbsCertificate.subjectPublicKeyInfo.ecdsa_public_key.y );
          break;
        default:
          // Diffie-Hellman certificates not supported in this implementation
          break;
      }
    }

    ptr += certificate_length;

    // TODO compute the hash of the certificate so that it can be validated by
    // the next one

    free_x509_certificate( &certificate );
  }

  return ptr;
}

/**
 * An RSA signature is an ASN.1 DER-encoded PKCS-7 structure including
 * the OID of the signature algorithm (again), and the signature value.
 */
static int validate_certificate_rsa( signed_x509_certificate *certificate,
                                     rsa_key *public_key )
{
  unsigned char *pkcs7_signature_decrypted;
  int pkcs7_signature_len;
  struct asn1struct pkcs7_signature;
  struct asn1struct *hash_value;
  int valid = 0;

  pkcs7_signature_len = rsa_decrypt( certificate->rsa_signature_value.rep,
    certificate->rsa_signature_value.size, &pkcs7_signature_decrypted,
    public_key );

  if ( pkcs7_signature_len == -1 )
  {
    return valid;
  }
  if ( asn1parse( pkcs7_signature_decrypted, pkcs7_signature_len,
                  &pkcs7_signature ) )
  {
    free( pkcs7_signature_decrypted );
    return valid;
  }

  hash_value = pkcs7_signature.children ? pkcs7_signature.children->next :
    NULL;

  valid = hash_value &&
    hash_value->length == certificate->hash_len * 4 &&
    !memcmp( hash_value->data, certificate->hash, certificate->hash_len * 4 );

  asn1free( &pkcs7_signature );
  free( pkcs7_signature_decrypted );

  return valid;
}

int x509_verify_signature( signed_x509_certificate *certificate,
                           public_key_info *issuer_key )
{
  if ( !certificate->hash )
  {
    return 0; // unsupported signature algorithm
  }

  switch ( certificate->algorithm )
  {
    case md5WithRSAEncryption:
    case shaWithRSAEncryption:
    case sha256WithRSAEncryption:
    case sha384WithRSAEncryption:
    case sha512WithRSAEncryption:
      return issuer_key->algorithm == rsa &&
        validate_certificate_rsa( certificate, &issuer_key->rsa_public_key );
    case shaWithDSA:
      return issuer_key->algorithm == dsa &&
        dsa_verify( &issuer_key->dsa_parameters,
                    &issuer_key->dsa_public_key,
                    certificate->hash,
                    certificate->hash_len * 4,
                    &certificate->dsa_signature_value );
    case sha256WithECDSA:
    case sha384WithECDSA:
      return issuer_key->algorithm == ecdsa &&
        ecdsa_verify( &issuer_key->ecdsa_curve,
                      &issuer_key->ecdsa_public_key,
                      certificate->hash,
                      certificate->hash_len,
                      &certificate->dsa_signature_value );
    default:
      return 0;
  }
}

static int same_name( unsigned char *a, int a_len,
                      unsigned char *b, int b_len )
{
  return a_len == b_len && !memcmp( a, b, a_len );
}

static int is_issuer_of( x509_certificate *issuer, x509_certificate *subject )
{
  return same_name( issuer->subject_der, issuer->subject_der_len,
                    subject->issuer_der, subject->issuer_der_len );
}

/**
 * Case-insensitive match of a certificate name against a host name; a
 * leading "*." matches exactly one label (RFC 6125 6.4.3).
 */
static int hostname_matches( const char *pattern, const char *hostname )
{
  if ( !strncmp( pattern, "*.", 2 ) )
  {
    const char *dot = strchr( hostname, '.' );
    return dot && dot != hostname && !strcasecmp( pattern + 1, dot );
  }
  return !strcasecmp( pattern, hostname );
}

const char *x509_verify_result_string( x509_verify_result result )
{
  switch ( result )
  {
    case X509_OK: return "ok";
    case X509_BAD_SIGNATURE: return "bad certificate signature";
    case X509_UNTRUSTED: return "certificate not signed by a trusted root";
    case X509_EXPIRED: return "certificate expired";
    case X509_NOT_YET_VALID: return "certificate not yet valid";
    case X509_NOT_A_CA: return "issuer is not a CA";
    case X509_HOSTNAME_MISMATCH: return "certificate doesn't match host name";
    case X509_EMPTY_CHAIN: return "no certificate";
  }
  return "unknown error";
}

x509_verify_result x509_verify_chain( signed_x509_certificate *chain,
                                      int chain_length,
                                      signed_x509_certificate *roots,
                                      int roots_count,
                                      const char *hostname,
                                      time_t now )
{
  int i, j;
  x509_certificate *leaf;

  if ( chain_length < 1 )
  {
    return X509_EMPTY_CHAIN;
  }

  leaf = &chain[ 0 ].tbsCertificate;
  if ( hostname )
  {
    int matched = 0;

    if ( leaf->dns_names_count )
    {
      for ( i = 0; i < leaf->dns_names_count && !matched; i++ )
      {
        matched = hostname_matches( leaf->dns_names[ i ], hostname );
      }
    }
    else if ( leaf->subject.idAtCommonName )
    {
      matched = hostname_matches( leaf->subject.idAtCommonName, hostname );
    }
    if ( !matched )
    {
      return X509_HOSTNAME_MISMATCH;
    }
  }

  for ( i = 0; i < chain_length; i++ )
  {
    x509_certificate *certificate = &chain[ i ].tbsCertificate;

    if ( now < certificate->validity.notBefore )
    {
      return X509_NOT_YET_VALID;
    }
    if ( now > certificate->validity.notAfter )
    {
      return X509_EXPIRED;
    }

    // A certificate that is itself a trusted root ends the chain
    for ( j = 0; j < roots_count; j++ )
    {
      x509_certificate *root = &roots[ j ].tbsCertificate;
      if ( same_name( root->subject_der, root->subject_der_len,
                      certificate->subject_der,
                      certificate->subject_der_len ) &&
           chain[ i ].hash_len == roots[ j ].hash_len && chain[ i ].hash &&
           !memcmp( chain[ i ].hash, roots[ j ].hash,
                    chain[ i ].hash_len * 4 ) )
      {
        return X509_OK;
      }
    }

    // Otherwise it must be signed by a trusted root...
    for ( j = 0; j < roots_count; j++ )
    {
      if ( is_issuer_of( &roots[ j ].tbsCertificate, certificate ) &&
           x509_verify_signature( &chain[ i ],
             &roots[ j ].tbsCertificate.subjectPublicKeyInfo ) )
      {
        return X509_OK;
      }
    }

    // ...or by the next certificate in the chain, which must be a CA
    if ( i + 1 >= chain_length ||
         !is_issuer_of( &chain[ i + 1 ].tbsCertificate, certificate ) )
    {
      return X509_UNTRUSTED;
    }
    if ( !chain[ i + 1 ].tbsCertificate.basic_constraints_ca )
    {
      return X509_NOT_A_CA;
    }
    if ( !x509_verify_signature( &chain[ i ],
           &chain[ i + 1 ].tbsCertificate.subjectPublicKeyInfo ) )
    {
      return X509_BAD_SIGNATURE;
    }
  }

  return X509_UNTRUSTED;
}

int x509_load_pem_bundle( const char *path,
                          signed_x509_certificate **certificates )
{
  int file;
  struct stat file_stat;
  unsigned char *pem, *pos, *der;
  int count = 0, der_len;

  *certificates = NULL;
  if ( ( file = open( path, O_RDONLY ) ) == -1 ||
       fstat( file, &file_stat ) )
  {
    return -1;
  }
  pem = malloc( file_stat.st_size + 1 );
  if ( read( file, pem, file_stat.st_size ) != file_stat.st_size )
  {
    close( file );
    free( pem );
    return -1;
  }
  close( file );
  pem[ file_stat.st_size ] = '\0';
  der = malloc( file_stat.st_size );

  for ( pos = strstr( pem, "-----BEGIN CERTIFICATE-----" ); pos;
        pos = strstr( pos + 1, "-----BEGIN CERTIFICATE-----" ) )
  {
    der_len = pem_decode( pos, der );
    *certificates = realloc( *certificates,
      ( count + 1 ) * sizeof( signed_x509_certificate ) );
    init_x509_certificate( &( *certificates )[ count ] );
    if ( !parse_x509_certificate( der, der_len, &( *certificates )[ count ] ) )
    {
      count++;
    }
    else
    {
      free_x509_certificate( &( *certificates )[ count ] );
    }
  }

  free( der );
  free( pem );

  return count;
}

int parse_x509_chain_all( unsigned char *buffer,
                          int pdu_length,
                          signed_x509_certificate **chain )
{
  unsigned char *ptr = buffer + 3;
  unsigned int certificate_length;
  int count = 0;

  *chain = NULL;
  if ( pdu_length < 3 )
  {
    return -1;
  }

  while ( ( ptr - buffer ) + 3 <= pdu_length )
  {
    certificate_length = ( *ptr << 16 ) | ( *( ptr + 1 ) << 8 ) |
      ( *( ptr + 2 ) );
    ptr += 3;
    if ( ( ptr - buffer ) + certificate_length > pdu_length )
    {
      break;
    }
    *chain = realloc( *chain, ( count + 1 ) * sizeof( signed_x509_certificate ) );
    init_x509_certificate( &( *chain )[ count ] );
    if ( parse_x509_certificate( ptr, certificate_length,
                                 &( *chain )[ count ] ) )
    {
      free_x509_certificate( &( *chain )[ count ] );
      return count ? count : -1;
    }
    count++;
    ptr += certificate_length;
  }

  return count;
}

#ifdef TEST_X509
static void output_x500_name( name *x500_name )
{
  printf( "C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s\n",
    ( x500_name->idAtCountryName ? x500_name->idAtCountryName : "?" ),
    ( x500_name->idAtStateOrProvinceName ? x500_name->idAtStateOrProvinceName : "?" ),
    ( x500_name->idAtLocalityName ? x500_name->idAtLocalityName : "?" ),
    ( x500_name->idAtOrganizationName ? x500_name->idAtOrganizationName : "?" ),
    ( x500_name->idAtOrganizationalUnitName ? x500_name->idAtOrganizationalUnitName : "?" ),
    ( x500_name->idAtCommonName ? x500_name->idAtCommonName : "?" ) );
}

static void print_huge( huge *h )
{
  show_hex( h->rep, h->size );
}

static void display_x509_certificate( signed_x509_certificate *certificate )
{
  printf( "Certificate details:\n" );
  printf( "Version: %d\n", certificate->tbsCertificate.version );
  printf( "Serial number: " );
  print_huge( &certificate->tbsCertificate.serialNumber );
  printf( "issuer: " );
  output_x500_name( &certificate->tbsCertificate.issuer );
  printf( "subject: " );
  output_x500_name( &certificate->tbsCertificate.subject );
  printf( "not before: %s", asctime( gmtime(
    &certificate->tbsCertificate.validity.notBefore ) ) );
  printf( "not after: %s", asctime( gmtime(
    &certificate->tbsCertificate.validity.notAfter ) ) );
  printf( "Public key algorithm: " );
  switch ( certificate->tbsCertificate.subjectPublicKeyInfo.algorithm )
  {
    case rsa:
      printf( "RSA\n" );
      printf( "modulus: " );
      print_huge(
        certificate->tbsCertificate.subjectPublicKeyInfo.rsa_public_key.modulus );
      printf( "exponent: " );
      print_huge(
        certificate->tbsCertificate.subjectPublicKeyInfo.rsa_public_key.exponent );
      break;
    case dsa:
      printf( "DSA\n" );
      printf( "y: " );
      print_huge(
        &certificate->tbsCertificate.subjectPublicKeyInfo.dsa_public_key );
      printf( "p: " );
      print_huge(
        &certificate->tbsCertificate.subjectPublicKeyInfo.dsa_parameters.p );
      printf( "q: " );
      print_huge(
        &certificate->tbsCertificate.subjectPublicKeyInfo.dsa_parameters.q );
      printf( "g: " );
      print_huge(
        &certificate->tbsCertificate.subjectPublicKeyInfo.dsa_parameters.g );
      break;
    case dh:
      printf( "DH\n" );
      break;
    case ecdsa:
      printf( "ECDSA\n" );
      printf( "x: " );
      print_huge(
        &certificate->tbsCertificate.subjectPublicKeyInfo.ecdsa_public_key.x );
      printf( "y: " );
      print_huge(
        &certificate->tbsCertificate.subjectPublicKeyInfo.ecdsa_public_key.y );
      break;
    default:
      printf( "?\n" );
      break;
  }

  printf( "Signature algorithm: " );
  switch ( certificate->algorithm )
  {
    case md5WithRSAEncryption:
      printf( "MD5 with RSA Encryption\n" );
      break;
    case shaWithRSAEncryption:
      printf( "SHA-1 with RSA Encryption\n" );
      break;
    case shaWithDSA:
      printf( "SHA-1 with DSA\n" );
      break;
    case sha256WithECDSA:
      printf( "SHA-256 with ECDSA\n" );
      break;
    case sha256WithRSAEncryption:
      printf( "SHA-256 with RSA Encryption\n" );
      break;
    default:
      printf( "unsupported\n" );
      break;
  }

  printf( "Signature value: " );
  switch ( certificate->algorithm )
  {
    case md5WithRSAEncryption:
    case shaWithRSAEncryption:
      print_huge( &certificate->rsa_signature_value );
      break;
    case shaWithDSA:
    case sha256WithECDSA:
      printf( "\n\tr:" );
      print_huge( &certificate->dsa_signature_value.r );
      printf( "\ts:" );
      print_huge( &certificate->dsa_signature_value.s );
      break;
  }
  printf( "\n" );

  if ( certificate->tbsCertificate.certificate_authority )
  {
    printf( "is a CA\n" );
  }
  else
  {
    printf( "is not a CA\n" );
  }
}

int main( int argc, char *argv[ ] )
{
  int certificate_file;
  struct stat certificate_file_stat;
  char *buffer, *bufptr;
  int buffer_size;
  int bytes_read;
  int error_code;

  signed_x509_certificate certificate;

  if ( argc == 5 && !strcmp( argv[ 1 ], "-verify" ) )
  {
    // x509_test -verify <trusted roots.pem> <hostname> <chain.pem>
    signed_x509_certificate *roots, *chain;
    int roots_count = x509_load_pem_bundle( argv[ 2 ], &roots );
    int chain_length = x509_load_pem_bundle( argv[ 4 ], &chain );
    x509_verify_result result;

    printf( "%d trusted roots, %d certificates in chain\n", roots_count,
      chain_length );
    result = x509_verify_chain( chain, chain_length, roots, roots_count,
      argv[ 3 ], time( NULL ) );
    printf( "%s\n", x509_verify_result_string( result ) );
    return result;
  }

  if ( argc < 3 )
  {
    fprintf( stderr, "Usage: x509 [-pem|-der] [certificate file]\n" );
    exit( 0 );
  }

  if ( ( certificate_file = open( argv[ 2 ], O_RDONLY ) ) == -1 )
  {
    perror( "Unable to open certificate file" );
    return 1;
  }

  // Slurp the whole thing into memory
  if ( fstat( certificate_file, &certificate_file_stat ) )
  {
    perror( "Unable to stat certificate file" );
    return 2;
  }

  buffer_size = certificate_file_stat.st_size;
  buffer = ( char * ) malloc( buffer_size + 1 );

  if ( !buffer )
  {
    perror( "Not enough memory" );
    return 3;
  }

  bufptr = buffer;
  while ( ( bytes_read = read( certificate_file, ( void * ) bufptr,
                               buffer_size - ( bufptr - buffer ) ) ) > 0 )
  {
    bufptr += bytes_read;
  }
  buffer[ buffer_size ] = 0;

  if ( !strcmp( argv[ 1 ], "-pem" ) )
  {
    // XXX this overallocates a bit, since it sets aside space for markers, etc.
    unsigned char *pem_buffer = buffer;
    buffer = (unsigned char * ) malloc( buffer_size );
    buffer_size = pem_decode( pem_buffer, buffer );
    free( pem_buffer );
  }

  // now parse it
  init_x509_certificate( &certificate );
  if ( !( error_code = parse_x509_certificate( buffer, buffer_size,
                                               &certificate ) ) )
  {
    printf( "X509 Certificate:\n" );
    display_x509_certificate( &certificate );

    // Assume it's a self-signed certificate and try to validate it that
    switch ( certificate.algorithm )
    {
      case md5WithRSAEncryption:
      case shaWithRSAEncryption:
      case sha256WithRSAEncryption:
        if ( x509_verify_signature( &certificate,
          &certificate.tbsCertificate.subjectPublicKeyInfo ) )
        {
          printf( "Certificate is a valid self-signed certificate.\n" );
        }
        else
        {
          printf( "Certificate is corrupt or not self-signed.\n" );
        }
        break;
      case sha256WithECDSA:
        if ( x509_verify_signature( &certificate,
          &certificate.tbsCertificate.subjectPublicKeyInfo ) )
        {
          printf( "Certificate is a valid self-signed certificate.\n" );
        }
        else
        {
          printf( "Certificate is corrupt or not self-signed.\n" );
        }
        break;
      case shaWithDSA:
        if ( x509_verify_signature( &certificate,
          &certificate.tbsCertificate.subjectPublicKeyInfo ) )
        {
          printf( "Certificate is a valid self-signed certificate.\n" );
        }
        else
        {
          printf( "Certificate is corrupt or not self-signed.\n" );
        }
        break;
    }
  }
  else
  {
    printf( "error parsing certificate: %d\n", error_code );
  }

  free_x509_certificate( &certificate );
  free( buffer );

  return 0;
}
#endif
