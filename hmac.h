#ifndef HMAC_H
#define HMAC_H

#include "digest.h"

void hmac( const unsigned char *key,
           int key_length,
           const unsigned char *text,
           int text_length,
           digest_ctx *digest );

#endif
