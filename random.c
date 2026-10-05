#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/random.h>
#endif
#include "random.h"

void random_bytes( unsigned char *buf, int len )
{
  int fd;
  ssize_t got;

#ifdef __linux__
  while ( len > 0 )
  {
    got = getrandom( buf, len, 0 );
    if ( got < 0 )
    {
      if ( errno == EINTR )
      {
        continue;
      }
      break;
    }
    buf += got;
    len -= got;
  }
  if ( len == 0 )
  {
    return;
  }
#endif

  if ( ( fd = open( "/dev/urandom", O_RDONLY ) ) == -1 )
  {
    perror( "Unable to open /dev/urandom" );
    abort();
  }
  while ( len > 0 )
  {
    got = read( fd, buf, len );
    if ( got <= 0 )
    {
      if ( got < 0 && errno == EINTR )
      {
        continue;
      }
      perror( "Unable to read /dev/urandom" );
      abort();
    }
    buf += got;
    len -= got;
  }
  close( fd );
}

void random_nonzero_bytes( unsigned char *buf, int len )
{
  int i;

  random_bytes( buf, len );
  for ( i = 0; i < len; i++ )
  {
    while ( !buf[ i ] )
    {
      random_bytes( buf + i, 1 );
    }
  }
}

void random_huge_below( huge *k, huge *n )
{
  unsigned char *bytes = malloc( n->size );
  unsigned char top_mask = 0xFF;

  // Mask the top byte down to n's bit length, then retry until the value
  // falls in [1, n-1]; fewer than half the draws are rejected.
  while ( top_mask >> 1 >= n->rep[ 0 ] && top_mask )
  {
    top_mask >>= 1;
  }

  for ( ;; )
  {
    random_bytes( bytes, n->size );
    bytes[ 0 ] &= top_mask;
    load_huge( k, bytes, n->size );
    contract( k );
    if ( compare( k, n ) < 0 && !( k->size == 1 && k->rep[ 0 ] == 0 ) )
    {
      break;
    }
    free_huge( k );
  }

  free( bytes );
}
