#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "huge.h"

/**
 * Extend the space for h by 1 char and set the LSB of that int
 * to 1.
 */
void expand( huge *h )
{
  unsigned char *tmp = h->rep;
  h->size++;
  h->rep = ( unsigned char * )
    calloc( h->size, sizeof( unsigned char ) );
  memcpy( h->rep + 1, tmp,
    ( h->size - 1 ) * sizeof( unsigned char ) );
  h->rep[ 0 ] = 0x01;
  free( tmp );
}

/**
 * Go through h and see how many of the left-most bytes are unused.
 * Remove them and resize h appropriately.
 */
void contract( huge *h )
{
  int i = 0;

  while ( !( h->rep[ i ] ) && ( i < h->size ) ) { i++; }

  if ( i && i < h->size )
  {
    unsigned char *tmp = &h->rep[ i ];
    h->rep = ( unsigned char * ) calloc( h->size - i,
      sizeof( unsigned char ) );
    memcpy( h->rep, tmp, h->size - i );
    h->size -= i;
  }
}

/**
 * Add two huges - overwrite h1 with the result.
 */
static void add_magnitude( huge *h1, huge *h2 )
{
  unsigned int i, j;
  unsigned int sum;
  unsigned int carry = 0;

  // Adding h2 to h1. If h2 is > h1 to begin with, resize h1.
  if ( h2->size > h1->size )
  {
    unsigned char *tmp = h1->rep;
    h1->rep = ( unsigned char * ) calloc( h2->size,
      sizeof( unsigned char ) );
    memcpy( h1->rep + ( h2->size - h1->size ), tmp, h1->size );
    h1->size = h2->size;
    free( tmp );
  }

  i = h1->size;
  j = h2->size;

  do
  {
    i--;
    if ( j )
    {
      j--;
      sum = h1->rep[ i ] + h2->rep[ j ] + carry;
    }
    else
    {
      sum = h1->rep[ i ] + carry;
    }

    carry = sum > 0xFF;
    h1->rep[ i ] = sum;
  }
  while ( i );

  if ( carry )
  {
    // Still overflowed; allocate more space
    expand( h1 );
  }
}

/**
 * Subtract h2 from h1, overwriting the value of h1.
 */
static void subtract_magnitude( huge *h1, huge *h2 )
{
  int i = h1->size;
  int j = h2->size;
  int difference; // signed int - important!
  unsigned int borrow = 0;

  do
  {
    i--;
    if ( j )
    {
      j--;
      difference = h1->rep[ i ] - h2->rep[ j ] - borrow;
    }
    else
    {
      difference = h1->rep[ i ] - borrow;
    }
    borrow = ( difference < 0 );
    h1->rep[ i ] = difference;
  }
  while ( i );

  if ( borrow && i )
  {
    if ( h1->rep[ i - 1 ] ) // Don't borrow i
    {
      // negative reults are now OK
      h1->rep[ i - 1 ]--;
    }
  }

  contract( h1 );
}

void add( huge *h1, huge *h2 )
{
  int result_sign;

  // First compute sign of result, then compute magnitude
  if ( compare( h1, h2 ) > 0 )
  {
    result_sign = h1->sign;

    if ( h1->sign == h2->sign )
    {
      add_magnitude( h1, h2 );
    }
    else
    {
      subtract_magnitude( h1, h2 );
    }
  }
  else
  {
    huge tmp;

    // put h1 into tmp and h2 into h1 to swap the operands
    set_huge( &tmp, 0 ); // initialize
    copy_huge( &tmp, h1 );
    copy_huge( h1, h2 );

    if ( h1->sign == tmp.sign )
    {
      result_sign = h1->sign;
      add_magnitude( h1, &tmp );
    }
    else
    {
      result_sign = h2->sign;
      subtract_magnitude( h1, &tmp );
    }

    free_huge( &tmp );
  }

  // Use the stored sign to set the result
  h1->sign = result_sign;
}

void subtract( huge *h1, huge *h2 )
{
  int result_sign;

  // First compute sign of result, then compute magnitude
  if ( compare( h1, h2 ) > 0 )
  {
    result_sign = h1->sign;

    if ( h1->sign == h2->sign )
    {
      subtract_magnitude( h1, h2 );
    }
    else
    {
      add_magnitude( h1, h2 );
    }
  }
  else
  {
    huge tmp;

    // put h1 into tmp and h2 into h1 to swap the operands
    set_huge( &tmp, 0 ); // initialize
    copy_huge( &tmp, h1 );
    copy_huge( h1, h2 );

    if ( h1->sign == tmp.sign )
    {
      result_sign = !( h1->sign );
      subtract_magnitude( h1, &tmp );
    }
    else
    {
      result_sign = !( h2->sign );
      add_magnitude( h1, &tmp );
    }

    free_huge( &tmp );
  }

  // Use the stored sign to set the result
  h1->sign = result_sign;
}

void copy_huge( huge *tgt, huge *src )
{
  if ( tgt->rep )
  {
    // TODO make this a little more efficient by reusing "rep"
    // if it's big enough
    free( tgt->rep );
  }

  tgt->sign = src->sign;
  tgt->size = src->size;
  tgt->rep = ( unsigned char * )
    calloc( src->size, sizeof( unsigned char ) );
  memcpy( tgt->rep, src->rep,
    ( src->size * sizeof( unsigned char ) ) );
}

void free_huge( huge *h )
{
  if ( h->rep )
  {
    free( h->rep );
  }
}

void set_huge( huge *h, unsigned int val )
{
  unsigned int mask, i, shift;

  // Negative number support
  h->sign = 0; // sign of 0 means positive

  h->size = 4;

  // Figure out the minimum amount of space this "val" will take
  // up in chars (leave at least one byte, though, if "val" is 0).
  for ( mask = 0xFF000000; mask > 0x000000FF; mask >>=8 )
  {
    if ( val & mask )
    {
      break;
    }
    h->size--;
  }

  h->rep = ( unsigned char * ) malloc( h->size );

  // Now work backward through the int, masking off each 8-bit
  // byte (up to the first 0 byte) and copy it into the "huge"
  // array in big-endian format.
  mask = 0x000000FF;
  shift = 0;
  for ( i = h->size; i; i-- )
  {
    h->rep[ i - 1 ] = ( val & mask ) >> shift;
    mask <<= 8;
    shift += 8;
  }
}

void left_shift( huge *h1 )
{
  int i;
  int old_carry, carry = 0;

  i = h1->size;
  do
  {
    i--;
    old_carry = carry;
    carry = ( h1->rep[ i ] & 0x80 ) == 0x80;
    h1->rep[ i ] = ( h1->rep[ i ] << 1 ) | old_carry;
    // Again, if C exposed the overflow bit...
  }
  while ( i );

  if ( carry )
  {
    expand( h1 );
  }
}

static void right_shift( huge *h1 )
{
  int i;
  unsigned int old_carry, carry = 0;

  i = 0;
  do
  {
    old_carry = carry;
    carry = ( h1->rep[ i ] & 0x01 ) << 7;
    h1->rep[ i ] = ( h1->rep[ i ] >> 1 ) | old_carry;
  }
  while ( ++i < h1->size );

  contract( h1 );
}

/**
 * Multiply h1 by h2, overwriting the value of h1.
 */
/*
 * multiply and divide below work on 32-bit limbs instead
 * of one bit at a time (shift-and-add / shift-and-subtract, reallocating
 * on every shift). Same interface and results; ECDSA over P-384 went from
 * seconds to milliseconds.
 */
#include <stdint.h>

// Little-endian 32-bit limbs from the big-endian byte representation
static uint32_t *to_limbs( const huge *h, int *count )
{
  int i, n = ( h->size + 3 ) / 4;
  uint32_t *limbs = calloc( n + 1, sizeof( uint32_t ) );

  for ( i = 0; i < h->size; i++ )
  {
    int byte = h->size - 1 - i; // i-th least significant byte
    limbs[ i / 4 ] |= ( uint32_t ) h->rep[ byte ] << ( 8 * ( i % 4 ) );
  }
  while ( n > 1 && !limbs[ n - 1 ] )
  {
    n--;
  }
  *count = n;

  return limbs;
}

// Replace h's magnitude with the limbs, dropping leading zero bytes
static void from_limbs( huge *h, const uint32_t *limbs, int count )
{
  int i, size = count * 4;

  while ( size > 1 &&
          !( ( limbs[ ( size - 1 ) / 4 ] >> ( 8 * ( ( size - 1 ) % 4 ) ) ) &
             0xFF ) )
  {
    size--;
  }
  free( h->rep );
  h->size = size;
  h->rep = malloc( size );
  for ( i = 0; i < size; i++ )
  {
    h->rep[ size - 1 - i ] = ( limbs[ i / 4 ] >> ( 8 * ( i % 4 ) ) ) & 0xFF;
  }
}

void multiply( huge *h1, huge *h2 )
{
  int n1, n2, i, j;
  uint32_t *a = to_limbs( h1, &n1 );
  uint32_t *b = to_limbs( h2, &n2 );
  uint32_t *r = calloc( n1 + n2, sizeof( uint32_t ) );
  int result_sign = !( h1->sign == h2->sign );

  for ( i = 0; i < n1; i++ )
  {
    uint64_t carry = 0;
    for ( j = 0; j < n2; j++ )
    {
      uint64_t t = ( uint64_t ) a[ i ] * b[ j ] + r[ i + j ] + carry;
      r[ i + j ] = ( uint32_t ) t;
      carry = t >> 32;
    }
    r[ i + n2 ] = ( uint32_t ) carry;
  }

  from_limbs( h1, r, n1 + n2 );
  h1->sign = result_sign;

  free( a );
  free( b );
  free( r );
}

/**
 * Compare h1 to h2. Return:
 * 0 if h1 == h2
 * a positive number if h1 > h2
 * a negative number if h1 < h2
 */
int compare( huge *h1, huge *h2 )
{
  const unsigned char *p1 = h1->rep, *p2 = h2->rep;
  int s1 = h1->size, s2 = h2->size;

  while ( s1 > 0 && !*p1 ) { p1++; s1--; }
  while ( s2 > 0 && !*p2 ) { p2++; s2--; }

  if ( s1 != s2 )
  {
    return s1 > s2 ? 1 : -1;
  }
  while ( s1-- )
  {
    if ( *p1 != *p2 )
    {
      return *p1 > *p2 ? 1 : -1;
    }
    p1++;
    p2++;
  }

  return 0;
}

/**
 * dividend = numerator, divisor = denominator
 *
 * Note that this process destroys divisor (and, of course,
 * overwrites quotient). The dividend is the remainder of the
 * division (if that's important to the caller). The divisor will
 * be modified by this routine, but it will end up back where it
 * "started".
 */
/**
 * dividend = dividend mod divisor (keeping dividend's sign); quotient (if not NULL) = |dividend| / |divisor| with the sign of
 * the true quotient. Knuth's Algorithm D (TAOCP 4.3.1).
 */
void divide( huge *dividend, huge *divisor, huge *quotient )
{
  int m, n, i, j, shift;
  uint32_t *u0 = to_limbs( dividend, &m );
  uint32_t *v0 = to_limbs( divisor, &n );
  uint32_t *u, *v, *q;
  int quotient_sign = !( dividend->sign == divisor->sign );

  if ( n == 1 && !v0[ 0 ] )
  {
    fprintf( stderr, "divide by zero\n" );
    abort();
  }

  if ( m < n )
  {
    // |dividend| < |divisor|: remainder is the dividend, quotient 0
    if ( quotient )
    {
      uint32_t zero = 0;
      quotient->rep = NULL;
      from_limbs( quotient, &zero, 1 );
      quotient->sign = 0;
    }
    from_limbs( dividend, u0, m );
    free( u0 );
    free( v0 );
    return;
  }

  q = calloc( m - n + 1, sizeof( uint32_t ) );
  u = calloc( m + 1, sizeof( uint32_t ) );
  v = calloc( n, sizeof( uint32_t ) );

  // Normalize so the divisor's top limb has its high bit set
  shift = 0;
  while ( !( ( v0[ n - 1 ] << shift ) & 0x80000000 ) )
  {
    shift++;
  }
  for ( i = n - 1; i > 0; i-- )
  {
    v[ i ] = ( v0[ i ] << shift ) |
      ( shift ? ( v0[ i - 1 ] >> ( 32 - shift ) ) : 0 );
  }
  v[ 0 ] = v0[ 0 ] << shift;
  u[ m ] = shift ? ( u0[ m - 1 ] >> ( 32 - shift ) ) : 0;
  for ( i = m - 1; i > 0; i-- )
  {
    u[ i ] = ( u0[ i ] << shift ) |
      ( shift ? ( u0[ i - 1 ] >> ( 32 - shift ) ) : 0 );
  }
  u[ 0 ] = u0[ 0 ] << shift;

  for ( j = m - n; j >= 0; j-- )
  {
    // Estimate the quotient digit from the top two limbs
    uint64_t numerator = ( ( uint64_t ) u[ j + n ] << 32 ) | u[ j + n - 1 ];
    uint64_t qhat = numerator / v[ n - 1 ];
    uint64_t rhat = numerator % v[ n - 1 ];
    int64_t borrow;
    uint64_t carry;

    while ( qhat > 0xFFFFFFFFULL ||
            ( n > 1 && qhat * v[ n - 2 ] >
              ( ( rhat << 32 ) | u[ j + n - 2 ] ) ) )
    {
      qhat--;
      rhat += v[ n - 1 ];
      if ( rhat > 0xFFFFFFFFULL )
      {
        break;
      }
    }

    // Multiply and subtract
    borrow = 0;
    carry = 0;
    for ( i = 0; i < n; i++ )
    {
      uint64_t p = qhat * v[ i ] + carry;
      int64_t t;
      carry = p >> 32;
      t = ( int64_t ) u[ i + j ] - ( int64_t ) ( p & 0xFFFFFFFF ) + borrow;
      u[ i + j ] = ( uint32_t ) t;
      borrow = t >> 32;
    }
    {
      int64_t t = ( int64_t ) u[ j + n ] - ( int64_t ) carry + borrow;
      u[ j + n ] = ( uint32_t ) t;
      borrow = t >> 32;
    }

    // Overshot by one: add the divisor back
    if ( borrow < 0 )
    {
      uint64_t c = 0;
      qhat--;
      for ( i = 0; i < n; i++ )
      {
        uint64_t t = ( uint64_t ) u[ i + j ] + v[ i ] + c;
        u[ i + j ] = ( uint32_t ) t;
        c = t >> 32;
      }
      u[ j + n ] += ( uint32_t ) c;
    }
    q[ j ] = ( uint32_t ) qhat;
  }

  // Unnormalize the remainder
  for ( i = 0; i < n; i++ )
  {
    u0[ i ] = ( u[ i ] >> shift ) |
      ( shift ? ( u[ i + 1 ] << ( 32 - shift ) ) : 0 );
  }
  from_limbs( dividend, u0, n );

  if ( quotient )
  {
    quotient->rep = NULL;
    from_limbs( quotient, q, m - n + 1 );
    quotient->sign = quotient_sign;
  }

  free( u0 );
  free( v0 );
  free( u );
  free( v );
  free( q );
}

/**
 * Raise h1 to the power of exp. Return the result in h1.
 */
void exponentiate( huge *h1, huge *exp )
{
  int i = exp->size, mask;
  huge tmp1, tmp2;

  set_huge( &tmp1, 0 );
  set_huge( &tmp2, 0 );

  copy_huge( &tmp1, h1 );
  set_huge( h1, 1 );

  do
  {
    i--;
    for ( mask = 0x01; mask; mask <<= 1 )
    {
      if ( exp->rep[ i ] & mask )
      {
        multiply( h1, &tmp1 );
      }
      // Square tmp1
      copy_huge( &tmp2, &tmp1 );
      multiply( &tmp1, &tmp2 );
    }
  }
  while ( i );

  free_huge( &tmp1 );
  free_huge( &tmp2 );
}

/**
 * Given a byte array, load it into a "huge", aligning integers
 * appropriately
 */
void load_huge( huge *h, const unsigned char *bytes, int length )
{
  while ( !( *bytes ) )
  {
    bytes++;
    length--;
  }

  h->sign = 0;
  h->size = length;
  h->rep = ( unsigned char * ) malloc( length );
  memcpy( h->rep, bytes, length );
}

void unload_huge( const huge *h, unsigned char *bytes, int length )
{
  memcpy( bytes + ( length - h->size ), h->rep, length );
}

/**
 * Compute c = m^e mod n.
 *
 * Note that this same routine is used for encryption and
 * decryption; the only difference is in the exponent passed in.
 * This is the "exponentiate" algorithm, with the addition of a
 * modulo computation at each stage.
 */
void mod_pow( huge *h1, huge *exp, huge *n, huge *h2 )
{
  unsigned int i = exp->size;
  unsigned char mask;
  huge tmp1, tmp2;

  set_huge( &tmp1, 0 );
  set_huge( &tmp2, 0 );
  copy_huge( &tmp1, h1 );
  set_huge( h2, 1 );

  do
  {
    i--;
    for ( mask = 0x01; mask; mask <<= 1 )
    {
      if ( exp->rep[ i ] & mask )
      {
        multiply( h2, &tmp1 );
        divide( h2, n, NULL );
      }
      // square tmp1
      copy_huge( &tmp2, &tmp1 );
      multiply( &tmp1, &tmp2 );
      divide( &tmp1, n, NULL );
    }
  }
  while ( i );

  free_huge( &tmp1 );
  free_huge( &tmp2 );

  // Result is now in "h2"
}

void inv( huge *z, huge *a )
{
  huge i, j, y2, y1, y, quotient, remainder, a_temp;

  set_huge( &i, 1 ); // initialize for copy
  set_huge( &j, 1 ); // initialize for copy
  set_huge( &remainder, 1 ); // initialize for copy
  set_huge( &y, 1 );
  set_huge( &a_temp, 1 );

  set_huge( &y2, 0 );
  set_huge( &y1, 1 );

  copy_huge( &i, a );
  copy_huge( &j, z );
  if ( z->sign )
  {
    divide( &j, a, NULL );
    // force positive remainder always
    j.sign = 0;
    subtract( &j, a );
    j.sign = 0;
  }

  while ( !( ( j.size == 1 ) && ( !j.rep[ 0 ] ) ) )
  {
    copy_huge( &remainder, &i );
    copy_huge( &i, &j );
    divide( &remainder, &j, &quotient );

    multiply( &quotient, &y1 ); // quotient = y1 * quotient
    copy_huge( &y, &y2 );
    subtract( &y, &quotient ); // y = y2 - ( y1 * quotient )

    copy_huge( &j, &remainder );
    copy_huge( &y2, &y1 );
    copy_huge( &y1, &y );
  }

  copy_huge( z, &y2 );
  copy_huge( &a_temp, a );
  divide( z, &a_temp, NULL ); // inv_z = y2 % a

  if ( z->sign )
  {
    z->sign = 0;
    subtract( z, &a_temp );
    if ( z->sign )
    {
      z->sign = 0;
    }
  }
}
