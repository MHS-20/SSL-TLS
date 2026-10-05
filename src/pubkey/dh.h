#ifndef DH_H
#define DH_H

#include "huge.h"

typedef struct
{
  huge p;
  huge g;
  huge Y;
}
dh_key;

void dh_agree( huge *p, huge *g, huge *e, huge *Y );
void dh_finalize( huge *p, huge *Y, huge *e, huge *Z );

#endif
