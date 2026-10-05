#ifndef SHA_H
#define SHA_H

#include "digest.h"

#define SHA1_RESULT_SIZE 5
#define SHA1_BYTE_SIZE 20
#define SHA256_RESULT_SIZE 8
#define SHA256_BYTE_SIZE 32

void sha1_block_operate( const unsigned char *block, unsigned int hash[ 5 ] );
void sha256_block_operate( const unsigned char *block, unsigned int hash[ 8 ] );
void sha1_finalize( const unsigned char *padded_block, int length_in_bits );
void new_sha1_digest( digest_ctx *context );
void new_sha256_digest( digest_ctx *context );

#endif
