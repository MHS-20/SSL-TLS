#ifndef RANDOM_H
#define RANDOM_H

#include "huge.h"

/**
 * Fill buf with len bytes from the operating system's CSPRNG
 * (getrandom(2), falling back to /dev/urandom). Aborts if neither works:
 * carrying on with predictable keys would be worse than stopping.
 */
void random_bytes( unsigned char *buf, int len );

/**
 * Like random_bytes, but none of the bytes is zero (PKCS #1 type 2 padding).
 */
void random_nonzero_bytes( unsigned char *buf, int len );

/**
 * Set k to a uniformly random value in [1, n-1].
 */
void random_huge_below( huge *k, huge *n );

#endif
