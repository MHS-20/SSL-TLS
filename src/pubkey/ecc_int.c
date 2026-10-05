/**
 * Small-integer elliptic-curve Diffie-Hellman demo.
 */
#include <stdio.h>

typedef struct
{
  int x;
  int y;
}
point;

typedef struct
{
  int private_key;
  point public_key;
}
key_pair;

/**
 * Describe y^2 = (x^3 + ax + b) % p
 */
typedef struct
{
  int p;
  int a;
  int b;
  point G; // base point
}
domain_parameters;

int ext_euclid( int z, int a )
{
  int i, j, y2, y1, y, quotient, remainder;

  i = a;
  j = z;
  y2 = 0;
  y1 = 1;

  while ( j > 0 )
  {
    quotient = i / j;
    remainder = i % j;
    y = y2 - ( y1 * quotient );
    i = j;
    j = remainder;
    y2 = y1;
    y1 = y;
  }

  return ( y2 % a );
}

/**
 * Extended Euclidean algorithm to perform a modular inversion
 * of x by y (e.g. (x/y) % p).
 */
static int invert( int x, int y, int p )
{
  int inverse = ext_euclid( y, p );

  return x * inverse;
}

static void add_points( point *p1, point *p2, int p )
{
  point p3;
  int lambda = invert( p2->y - p1->y, p2->x - p1->x, p );

  p3.x = ( ( lambda * lambda ) - p1->x - p2->x ) % p;
  p3.y = ( ( lambda * ( p1->x - p3.x ) ) - p1->y ) % p;

  p1->x = p3.x;
  p1->y = p3.y;
}

static void double_point( point *p1, int p, int a )
{
  point p3;
  int lambda = invert( 3 * ( p1->x * p1->x ) + a, 2 * p1->y, p );

  p3.x = ( ( lambda * lambda ) - ( 2 * p1->x ) ) % p;
  p3.y = ( ( lambda * ( p1->x - p3.x ) ) - p1->y ) % p;

  p1->x = p3.x;
  p1->y = p3.y;
}

static void multiply_point( point *p1, int k, int a, int p )
{
  point dp;
  int mask;
  int paf = 1;

  dp.x = p1->x;
  dp.y = p1->y;

  for ( mask = 0x00000001; mask; mask <<= 1 )
  {
    if ( mask & k )
    {
      if ( paf )
      {
        paf = 0;
        p1->x = dp.x;
        p1->y = dp.y;
      }
      else
      {
        add_points( p1, &dp, p );
      }
    }
    double_point( &dp, p, a );
  }
}

// Normalize a possibly-negative coordinate into [0, p) for display
static int pos( int v, int p ) { return ( ( v % p ) + p ) % p; }

int main( int argc, char *argv[ ] )
{
  domain_parameters T;
  key_pair A;
  key_pair B;
  point Z1, Z2;

  T.p = 23;
  T.a = 1;
  T.b = 1;
  T.G.x = 5;
  T.G.y = 19;

  A.private_key = 4;
  B.private_key = 2;

  A.public_key.x = T.G.x;
  A.public_key.y = T.G.y;
  multiply_point( &A.public_key, A.private_key, T.a, T.p );

  B.public_key.x = T.G.x;
  B.public_key.y = T.G.y;
  multiply_point( &B.public_key, B.private_key, T.a, T.p );

  Z1.x = A.public_key.x;
  Z1.y = A.public_key.y;
  multiply_point( &Z1, B.private_key, T.a, T.p );

  Z2.x = B.public_key.x;
  Z2.y = B.public_key.y;
  multiply_point( &Z2, A.private_key, T.a, T.p );

  printf( "A public (%d, %d), B public (%d, %d)\n",
    pos( A.public_key.x, T.p ), pos( A.public_key.y, T.p ),
    pos( B.public_key.x, T.p ), pos( B.public_key.y, T.p ) );
  printf( "Z1 = (%d, %d), Z2 = (%d, %d)\n", pos( Z1.x, T.p ), pos( Z1.y, T.p ),
    pos( Z2.x, T.p ), pos( Z2.y, T.p ) );

  return 0;
}
