#ifndef HUGE_H
#define HUGE_H

typedef struct
{
  int sign;
  unsigned int size;
  unsigned char *rep;
}
huge;

void set_huge( huge *h, unsigned int val );
void copy_huge( huge *tgt, huge *src );
void load_huge( huge *h, const unsigned char *bytes, int length );
void unload_huge( const huge *h, unsigned char *bytes, int length );
void free_huge( huge *h );

void add( huge *h1, huge *h2 );
void subtract( huge *h1, huge *h2 );
void multiply( huge *h1, huge *h2 );
void divide( huge *dividend, huge *divisor, huge *quotient );
void exponentiate( huge *h1, huge *exp );
void mod_pow( huge *h1, huge *exp, huge *n, huge *h2 );
void inv( huge *z, huge *a );
int compare( huge *h1, huge *h2 );
void left_shift( huge *h1 );
void contract( huge *h );

#endif
