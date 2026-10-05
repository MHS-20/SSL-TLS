#ifndef MD5_H
#define MD5_H

#include "digest.h"

// Size of MD5 hash in ints (128 bits)
#define MD5_RESULT_SIZE 4
#define MD5_BYTE_SIZE 16

void md5_block_operate( const unsigned char *input, unsigned int hash[ MD5_RESULT_SIZE ] );
void md5_finalize( const unsigned char *padded_block, int length_in_bits );
void new_md5_digest( digest_ctx *context );

#endif
