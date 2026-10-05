/**
 * The  HTTP client on top of the SSLv2 library (Listings C-2 and
 * C-3). There's no ssl_shutdown; SSLv2 didn't explicitly mark the end of a
 * secure session.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "ssl.h"

#define HTTPS_PORT 443
#define MAX_GET_COMMAND 255
#define BUFFER_SIZE 255

/**
 * Split "https://host[:port]/path" into its parts. Returns 0 on success.
 */
static int parse_url( char *uri, char **host, int *port, char **path )
{
  char *pos;

  if ( strncmp( "https://", uri, 8 ) )
  {
    return -1;
  }
  *host = uri + 8;

  if ( !( pos = strchr( *host, '/' ) ) )
  {
    *path = "";
  }
  else
  {
    *pos = '\0';
    *path = pos + 1;
  }

  *port = HTTPS_PORT;
  if ( ( pos = strchr( *host, ':' ) ) )
  {
    *pos = '\0';
    *port = atoi( pos + 1 );
  }

  return 0;
}

int http_get( int connection, const char *path, const char *host,
              SSLParameters *ssl_context )
{
  static char get_command[ MAX_GET_COMMAND ];

  sprintf( get_command, "GET /%s HTTP/1.1\r\n", path );
  if ( ssl_send( connection, get_command, strlen( get_command ),
                 0, ssl_context ) == -1 )
  {
    return -1;
  }

  sprintf( get_command, "Host: %s\r\n", host );
  if ( ssl_send( connection, get_command, strlen( get_command ),
                 0, ssl_context ) == -1 )
  {
    return -1;
  }

  strcpy( get_command, "Connection: Close\r\n\r\n" );
  if ( ssl_send( connection, get_command, strlen( get_command ),
                 0, ssl_context ) == -1 )
  {
    return -1;
  }

  return 0;
}

void display_result( int connection, SSLParameters *ssl_context )
{
  int received = 0;
  static char recv_buf[ BUFFER_SIZE + 1 ];

  // Can't exit when return value is 0 like in http.c, since empty SSL
  // messages can be sent (openssl does this)
  while ( ( received = ssl_recv( connection, recv_buf, BUFFER_SIZE,
                                 0, ssl_context ) ) >= 0 )
  {
    recv_buf[ received ] = '\0';
    printf( "data: %s", recv_buf );
  }
  printf( "\n" );
}

int main( int argc, char *argv[ ] )
{
  int client_connection;
  char *host, *path;
  int port;
  struct hostent *host_name;
  struct sockaddr_in host_address;
  SSLParameters ssl_context;

  if ( argc < 2 || parse_url( argv[ 1 ], &host, &port, &path ) )
  {
    fprintf( stderr, "Usage: %s: https://host[:port]/path\n", argv[ 0 ] );
    return 1;
  }

  if ( !( host_name = gethostbyname( host ) ) )
  {
    perror( "Error in name resolution" );
    return 3;
  }

  client_connection = socket( PF_INET, SOCK_STREAM, 0 );
  host_address.sin_family = AF_INET;
  host_address.sin_port = htons( port );
  memcpy( &host_address.sin_addr, host_name->h_addr_list[ 0 ],
    sizeof( struct in_addr ) );

  if ( connect( client_connection, ( struct sockaddr * ) &host_address,
                sizeof( host_address ) ) == -1 )
  {
    perror( "Unable to connect to host" );
    return 2;
  }

  if ( ssl_connect( client_connection, &ssl_context ) )
  {
    fprintf( stderr, "Error: unable to negotiate SSL connection.\n" );
    return 3;
  }

  http_get( client_connection, path, host, &ssl_context );

  display_result( client_connection, &ssl_context );

  close( client_connection );

  return 0;
}
