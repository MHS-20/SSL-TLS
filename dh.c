#include "dh.h"

/**
 * Diffie-Hellman key agreement: Y = g^e % p (sent to the peer), then
 * Z = Y_peer^e % p (the shared secret).
 */
void dh_agree( huge *p, huge *g, huge *e, huge *Y )
{
  mod_pow( g, e, p, Y );
}

void dh_finalize( huge *p, huge *Y, huge *e, huge *Z )
{
  mod_pow( Y, e, p, Z );
}
