#ifndef DIGEST_H
#define DIGEST_H

#define DIGEST_BLOCK_SIZE 64
#define INPUT_BLOCK_SIZE 56
// SHA-384/512 use 128-byte blocks
#define MAX_DIGEST_BLOCK_SIZE 128

typedef struct
{
  unsigned int *hash;
  int hash_len;
  unsigned int input_len;

  void (*block_operate)(const unsigned char *input, unsigned int hash[] );
  void (*block_finalize)(const unsigned char *block, int length );

  // Temporary storage
  unsigned char block[ MAX_DIGEST_BLOCK_SIZE ];
  int block_len;
  int block_size; // 64, or 128 for SHA-384/512
}
digest_ctx;

void update_digest( digest_ctx *context, const unsigned char *input, int input_len );
void finalize_digest( digest_ctx *context );

#endif
