/**
 * The HTTPS client from , reworked to use the OpenSSL library
 *. the original elides the URL parsing and socket setup ("…");
 * they are filled in here the same way as in https.c, without the proxy.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

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

int http_get( int connection,
              const char *path,
              const char *host,
              SSL *ssl )
{
  static char get_command[ MAX_GET_COMMAND ];

  sprintf( get_command, "GET /%s HTTP/1.1\r\n", path );
  if ( SSL_write( ssl, get_command, strlen( get_command ) ) == -1 )
  {
    return -1;
  }

  sprintf( get_command, "Host: %s\r\n", host );
  if ( SSL_write( ssl, get_command, strlen( get_command ) ) == -1 )
  {
    return -1;
  }

  strcpy( get_command, "Connection: Close\r\n\r\n" );
  if ( SSL_write( ssl, get_command, strlen( get_command ) ) == -1 )
  {
    return -1;
  }

  return 0;
}

void display_result( int connection, SSL *ssl )
{
  int received = 0;
  static char recv_buf[ BUFFER_SIZE + 1 ];

  while ( SSL_get_error( ssl,
          ( received = SSL_read( ssl, recv_buf, BUFFER_SIZE ) ) ) ==
          SSL_ERROR_NONE )
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
  SSL_CTX *ctx;
  SSL *ssl;
  BIO *sbio;
  const SSL_METHOD *meth;

  if ( argc < 2 || parse_url( argv[ 1 ], &host, &port, &path ) )
  {
    fprintf( stderr, "Usage: %s: https://host[:port]/path\n", argv[ 0 ] );
    return 1;
  }

  // OpenSSL-specific setup stuff
  // OpenSSL 1.1+ initializes itself and calls the method TLS_client_method
  meth = TLS_client_method();
  ctx = SSL_CTX_new( meth );

  // set up the connection itself
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
    return 4;
  }

  ssl = SSL_new( ctx );
  sbio = BIO_new_socket( client_connection, BIO_NOCLOSE );
  SSL_set_bio( ssl, sbio, sbio );

  if ( SSL_connect( ssl ) <= 0 )
  {
    fprintf( stderr, "Error: unable to negotiate SSL connection.\n" );
    ERR_print_errors_fp( stderr );
    if ( close( client_connection ) == -1 )
    {
      perror( "Error closing client connection" );
      return 2;
    }
    return 3;
  }

  http_get( client_connection, path, host, ssl );

  display_result( client_connection, ssl );

  SSL_shutdown( ssl );
  SSL_free( ssl );
  SSL_CTX_free( ctx );

  if ( close( client_connection ) == -1 )
  {
    perror( "Error closing client connection" );
    return 2;
  }

  return 0;
}
