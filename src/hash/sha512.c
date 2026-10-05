/**
 * SHA-384 and SHA-512 (FIPS 180-4), needed to verify the
 * sha384WithRSA / ecdsa-with-SHA384 signatures on current certificates.
 * The state lives in the digest_ctx hash buffer as big-endian bytes, so
 * that, as with SHA-256 in sha.c, the finished hash can be copied out
 * directly.
 */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sha512.h"

static const uint64_t k[ 80 ] = {
  0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
  0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
  0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
  0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
  0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
  0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
  0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
  0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
  0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
  0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
  0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
  0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
  0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
  0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
  0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
  0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
  0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
  0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
  0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
  0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
  0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
  0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
  0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static const uint64_t sha512_initial_hash[ 8 ] = {
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
  0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint64_t sha384_initial_hash[ 8 ] = {
  0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL,
  0x152fecd8f70e5939ULL, 0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
  0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL
};

#define ROTR( x, n ) ( ( ( x ) >> ( n ) ) | ( ( x ) << ( 64 - ( n ) ) ) )

static uint64_t load64( const unsigned char *p )
{
  int i;
  uint64_t v = 0;
  for ( i = 0; i < 8; i++ )
  {
    v = ( v << 8 ) | p[ i ];
  }
  return v;
}

static void store64( unsigned char *p, uint64_t v )
{
  int i;
  for ( i = 7; i >= 0; i-- )
  {
    p[ i ] = v & 0xFF;
    v >>= 8;
  }
}

static void sha512_block_operate( const unsigned char *block,
                                  unsigned int hash[] )
{
  unsigned char *state = ( unsigned char * ) hash;
  uint64_t W[ 80 ], H[ 8 ], a, b, c, d, e, f, g, h, T1, T2;
  int t;

  for ( t = 0; t < 8; t++ )
  {
    H[ t ] = load64( state + t * 8 );
  }
  for ( t = 0; t < 16; t++ )
  {
    W[ t ] = load64( block + t * 8 );
  }
  for ( ; t < 80; t++ )
  {
    uint64_t s0 = ROTR( W[ t - 15 ], 1 ) ^ ROTR( W[ t - 15 ], 8 ) ^
      ( W[ t - 15 ] >> 7 );
    uint64_t s1 = ROTR( W[ t - 2 ], 19 ) ^ ROTR( W[ t - 2 ], 61 ) ^
      ( W[ t - 2 ] >> 6 );
    W[ t ] = W[ t - 16 ] + s0 + W[ t - 7 ] + s1;
  }

  a = H[ 0 ]; b = H[ 1 ]; c = H[ 2 ]; d = H[ 3 ];
  e = H[ 4 ]; f = H[ 5 ]; g = H[ 6 ]; h = H[ 7 ];
  for ( t = 0; t < 80; t++ )
  {
    T1 = h + ( ROTR( e, 14 ) ^ ROTR( e, 18 ) ^ ROTR( e, 41 ) ) +
      ( ( e & f ) ^ ( ~e & g ) ) + k[ t ] + W[ t ];
    T2 = ( ROTR( a, 28 ) ^ ROTR( a, 34 ) ^ ROTR( a, 39 ) ) +
      ( ( a & b ) ^ ( a & c ) ^ ( b & c ) );
    h = g; g = f; f = e; e = d + T1;
    d = c; c = b; b = a; a = T1 + T2;
  }
  H[ 0 ] += a; H[ 1 ] += b; H[ 2 ] += c; H[ 3 ] += d;
  H[ 4 ] += e; H[ 5 ] += f; H[ 6 ] += g; H[ 7 ] += h;

  for ( t = 0; t < 8; t++ )
  {
    store64( state + t * 8, H[ t ] );
  }
}

static void sha512_finalize( const unsigned char *block, int length_in_bits )
{
  unsigned char *padded_block = ( unsigned char * ) block;
  unsigned int length = length_in_bits;

  // The length is a 128-bit big-endian number; only 32 bits are tracked
  padded_block[ 124 ] = ( length >> 24 ) & 0xFF;
  padded_block[ 125 ] = ( length >> 16 ) & 0xFF;
  padded_block[ 126 ] = ( length >> 8 ) & 0xFF;
  padded_block[ 127 ] = length & 0xFF;
}

static void new_sha512_family_digest( digest_ctx *context,
                                      const uint64_t *initial_hash,
                                      int hash_len )
{
  int i;

  context->hash_len = hash_len;
  context->input_len = 0;
  context->block_len = 0;
  context->block_size = 128;
  // Always room for the full 512-bit state; SHA-384 just reports less
  context->hash = ( unsigned int * ) malloc( 64 );
  for ( i = 0; i < 8; i++ )
  {
    store64( ( unsigned char * ) context->hash + i * 8, initial_hash[ i ] );
  }
  memset( context->block, '\0', MAX_DIGEST_BLOCK_SIZE );
  context->block_operate = sha512_block_operate;
  context->block_finalize = sha512_finalize;
}

void new_sha512_digest( digest_ctx *context )
{
  new_sha512_family_digest( context, sha512_initial_hash,
    SHA512_BYTE_SIZE / 4 );
}

void new_sha384_digest( digest_ctx *context )
{
  new_sha512_family_digest( context, sha384_initial_hash,
    SHA384_BYTE_SIZE / 4 );
}
