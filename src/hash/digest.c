#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "digest.h"
#include "md5.h"
#include "sha.h"
#include "sha512.h"
#include "hex.h"

void update_digest( digest_ctx *context, const unsigned char *input, int input_len )
{
  int block_size = context->block_size;

  context->input_len += input_len;

  // Process any left over from the last call to "update_digest"
  if ( context->block_len > 0 )
  {
    // How much we need to make a full block
    int borrow_amt = block_size - context->block_len;

    if ( input_len < borrow_amt )
    {
      memcpy( context->block + context->block_len, input, input_len );
      context->block_len += input_len;
      input_len = 0;
    }
    else
    {
      memcpy( context->block + context->block_len, input, borrow_amt );
      context->block_operate( context->block, context->hash );
      context->block_len = 0;
      input += borrow_amt;
      input_len -= borrow_amt;
    }
  }

  while ( input_len >= block_size )
  {
    context->block_operate( input, context->hash );

    input += block_size;
    input_len -= block_size;
  }

  // Have some non-aligned data left over; save it for next call, or
  // "finalize" call.
  if ( input_len > 0 )
  {
    memcpy( context->block, input, input_len );
    context->block_len = input_len;
  }
}

/**
 * SHA-384/512 use 128-byte blocks with a 16-byte length.
 */
void finalize_digest( digest_ctx *context )
{
  int block_size = context->block_size;
  int input_block_size = block_size - block_size / 8;

  memset( context->block + context->block_len, 0, block_size -
    context->block_len );
  context->block[ context->block_len ] = 0x80;
  // special handling if the last block is too full to hold the length
  if ( context->block_len >= input_block_size )
  {
    context->block_operate( context->block, context->hash );
    context->block_len = 0;
    memset( context->block + context->block_len, 0, block_size -
      context->block_len );
  }
  // Only append the length for the very last block
  // Technically, this allows for 64 bits of length, but since we can only
  // process 32 bits worth, we leave the upper four bytes empty
  context->block_finalize( context->block, context->input_len * 8 );

  context->block_operate( context->block, context->hash );
}

#ifdef TEST_DIGEST
int main( int argc, char *argv[ ] )
{
  digest_ctx ctx;
  unsigned char *decoded_input;
  int decoded_len;

  if ( argc < 3 )
  {
    fprintf( stderr, "Usage: %s [-md5|-sha1|-sha256|-sha384|-sha512] [0x]<input>\n", argv[ 0 ] );
    exit( 0 );
  }

  decoded_len = hex_decode( argv[ 2 ], &decoded_input );

  if ( !( strcmp( argv[ 1 ], "-md5" ) ) )
  {
    new_md5_digest( &ctx );
  }
  else if ( !( strcmp( argv[ 1 ], "-sha1" ) ) )
  {
    new_sha1_digest( &ctx );
  }
  else if ( !( strcmp( argv[ 1 ], "-sha384" ) ) )
  {
    new_sha384_digest( &ctx );
  }
  else if ( !( strcmp( argv[ 1 ], "-sha512" ) ) )
  {
    new_sha512_digest( &ctx );
  }
  else if ( !( strcmp( argv[ 1 ], "-sha256" ) ) )
  {
    new_sha256_digest( &ctx );
  }
  else
  {
    fprintf( stderr, "unsupported digest algorithm '%s'\n", argv[ 1 ] );
    exit( 0 );
  }

  update_digest( &ctx, decoded_input, decoded_len );
  finalize_digest( &ctx );
  show_hex( ( unsigned char * ) ctx.hash, ctx.hash_len * 4 );

  free( ctx.hash );
  free( decoded_input );

  return 0;
}
#endif
