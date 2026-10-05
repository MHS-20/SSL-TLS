#ifndef SHA512_H
#define SHA512_H

#include "digest.h"

#define SHA384_BYTE_SIZE 48
#define SHA512_BYTE_SIZE 64

void new_sha384_digest( digest_ctx *context );
void new_sha512_digest( digest_ctx *context );

#endif
