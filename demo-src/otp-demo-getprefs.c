/* ------------------------------------------------------------------------ *
 *                                                                          *
 * otp-demo-getprefs.c                                                      *
 *                                                                          *
 * This program demonstrates the communication with a OpenVAS Scanner       *
 * and  counts the returned scanner server settings to the screen.          *
 * OpenSSL libraries provide the required encryption functions. No client   *
 * certs are used, and we use username/password together with the default   *
 * connection method TLSv1.                                                 *
 *                                                                          *
 * The Following settings according to OTP 1.0 are retrieved:               *
 * SERVER <|> PLUGIN_LIST <|> [data] <|> SERVER                             *
 * SERVER <|> PREFERENCES <|> [data] <|> SERVER                             *
 * SERVER <|> RULES <|> [data] <|> SERVER                                   *
 *                                                                          *
 * this program has been written and tested with openvassd version 3.2.5    *
 * 20120110 frank4dd                                                        *
 *                                                                          *
 * compile instructions:                                                    *
 * gcc * -lssl -lcrypt ntp-demo.c -o ntp-demo                               *
 * ------------------------------------------------------------------------ */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

/* DEBUG = 0: connects and returns number of plugins, preferences, rules */
/* DEBUG = 1: adds the OTP protocol strings received, and sends a progress dot after 10 plugins */
/* DEBUG = 2: shows in addition the fully received plugin data and counters */
/* DEBUG = 3: shows plugin info as "Len   529 Counter 24069 Plugin ID: 1.3.6.1.4.1.25623.1.0.100294 <|>" */
#define DEBUG 0

#define CIPHER_LIST "EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC3-SHA:DES-CBC3-MD5:DHE-DSS-RC4-SHA:IDEA-CBC-SHA:RC4-SHA:RC4-MD5:IDEA-CBC-MD5:RC2-CBC-MD5:RC4-MD5"

#define DEST_IP "127.0.0.1"
#define DEST_PORT 9391
#define MAXTRANS 1
/* MAXDATASIZE should be large enough to handle a huge plugin *
 * description so we get a newline. If it is to small, we get *
 * chunks with no newline counted and its just a mess.        */
#define MAXDATASIZE 16384
#define USERPROMPT "User : "
#define PASSPROMPT "Password : "
#define USERNAME "fm2"
#define PASSWORD "test"
#define CLIENT_OTP_VERSION "< OTP/1.0 >"
#define SERVER_OTP_VERSION "< OTP/1.0 >"
#define PLUGS_MD5   "SERVER <|> PLUGINS_MD5 <|>"
#define PLUGS_START "SERVER <|> PLUGIN_LIST <|>"
#define PREFS_START "SERVER <|> PREFERENCES <|>"
#define RULES_START "SERVER <|> RULES <|>"
#define SERVER_END_MARKER "<|> SERVER"
#define CLIENT_END_MARKER "<|> CLIENT"
#define PLUGS_REQ "CLIENT <|> COMPLETE_LIST <|>" /* request plugins from server */
#define PREFS_REQ "CLIENT <|> PREFERENCES <|>"   /* request prefs from  server */
#define RULES_REQ "CLIENT <|> RULES <|>"         /* request rules from server */

const char newline[2] = {'\n', '\0'};
char server_ntp_version[255];

int  plugs_counter = 0;
int  prefs_counter = 0;
int  rules_counter = 0;
SSL           *ssl;


/* ------------------------------------------------------------------------- *
 * scanner_connect creates a new tcp session to the scan server and returns  *
 * the file descriptor to it.                                                *
 * ------------------------------------------------------------------------- */
int scanner_connect(char * ip, int port) {
  int sockfd;
  struct sockaddr_in dest_addr;

  static SSL_CTX        *ssl_ctx = NULL;
  X509			*servercert;

  if(DEBUG) printf("Creating socket file descriptor.\n");
  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  if(DEBUG) printf("Loading content into filedescriptor.\n");
  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(port);
  dest_addr.sin_addr.s_addr=inet_addr(ip);

  /* Zeroing the rest of the struct */

  memset(&(dest_addr.sin_zero), '\0', 8);

  if(DEBUG) printf("Try connecting to %s.\n", DEST_IP);

  if ( connect(sockfd, (struct sockaddr *) &dest_addr,
                              sizeof(struct sockaddr)) == -1 ) {
    if(DEBUG) perror("Error connecting");
    return -1;
  } else {
    if(DEBUG) printf("Connected to: %s.\n", DEST_IP);
  }

  ssl = NULL;

  /* initialize SSL library and register algorithms */
  if(SSL_library_init() < 0)
    printf("Could not initialize the OpenSSL library !\n");

  /* load  the SSL error messages */
  SSL_load_error_strings();

  /* create a new SSL_CTX object as framework for TLS/SSL enabled functions */
  if((ssl_ctx = SSL_CTX_new(TLSv1_client_method())) == NULL)
    printf("SSL_CTX_new() context creation error\n");

  /* enable all SSL engine bug workaround options (i.e. Netscape, Microsoft) */
  /* only if SSLv3_client_method() is used above                             */
  // if(SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL) < 0)
  //  printf("SSL_CTX_set_options(SSL_OP_ALL) error\n");

  /* choose list of available SSL_CIPHERs with a control string */
  if(! SSL_CTX_set_cipher_list(ssl_ctx, CIPHER_LIST))
    printf("SSL_CTX_set_cipher_list error\n");

  /* create a new SSL structure for a connection */
  if((ssl = SSL_new(ssl_ctx)) == NULL)
     printf("SSL_new() general error\n");

  /* connect the SSL object with the socket file descriptor */
  if(! SSL_set_fd(ssl, sockfd))
     printf("SSL_set_fd() error connecting to socket.\n");

  /* initiate the TLS/SSL handshake with an TLS/SSL server */
  if(SSL_connect(ssl) <= 0)
     printf("SSL_connect() error during SSL handshake\n");

  /* show the connection cipher that is used */
  if(DEBUG)
       printf("SSL_get_cipher = %s\n", SSL_get_cipher(ssl));

  /* get the received scan server certificate */
  if(! (servercert = SSL_get_peer_certificate(ssl)))
    printf("SSL_get_peer_certificate() error: cannot get server certificate\n");

  /* print the received scan server certificate */
  if(DEBUG == 2) {
    BIO                  *outbio;
    outbio = BIO_new_fd(fileno(stdout), BIO_NOCLOSE);
    if (! (X509_print_ex(outbio, servercert, 0, XN_FLAG_SEP_MULTILINE)))
      BIO_printf(outbio, "Error printing certificate text information\n");
  }
  return 0;
}

/* ------------------------------------------------------------------------- *
 * scanner_login tries to log in with the username and password provided. It *
 * returns 1 for success, 0 for failure.                                     *
 * ------------------------------------------------------------------------- */

int scanner_login(int fd, char * username, char * password){

  char * buf = NULL;
  //size_t len;
  int login = 0 , retcode = 0;

  /* send the client protocol version, followed by a newline */
  if(DEBUG) printf("Sending Data: %s%c", CLIENT_OTP_VERSION, '\n');

  buf = (char *) malloc(MAXDATASIZE);

  retcode = SSL_write(ssl, CLIENT_OTP_VERSION, strlen(CLIENT_OTP_VERSION));
  retcode = SSL_write(ssl, newline, 1);

  /* receive the server protocol version, followed by a newline */
  retcode=SSL_read(ssl, buf, strlen(SERVER_OTP_VERSION)+1);

  /* clear the buffer */
  memset(buf, '\0', MAXDATASIZE);

  if(DEBUG) printf("Receive Data: %s", buf);

  /* set global variable server protocol version, remove the newline */
  strncpy(server_ntp_version, buf, retcode-1);

  /* clear the buffer */
  memset(buf, '\0', MAXDATASIZE);

  /* receive the username prompt */
  retcode=SSL_read(ssl, buf, MAXDATASIZE);
  if(DEBUG) printf("Receive Data: %s\n", buf);

  /* clear the buffer */
  memset(buf, '\0', MAXDATASIZE);

  /* send the username followed by a newline */
  if(DEBUG) printf("Sending Data: %s%c", USERNAME, '\n');

  retcode = SSL_write(ssl, USERNAME, strlen(USERNAME));
  retcode = SSL_write(ssl, newline, 1);

  /* receive the password prompt */
  retcode=SSL_read(ssl, buf, MAXDATASIZE);
  if(DEBUG) printf("Receive Data: %s\n", buf);

  /* clear the buffer */
  memset(buf, '\0', MAXDATASIZE);

  /* send the password followed by a newline */
  if(DEBUG) printf("Sending Data: %s%c", PASSWORD, '\n');

  retcode = SSL_write(ssl, PASSWORD, strlen(PASSWORD));
  retcode = SSL_write(ssl, newline, 1);

  /* clear the buffer */
  memset(buf, '\0', MAXDATASIZE);

  /* Now we take the data out */
  retcode=SSL_read(ssl, buf, MAXDATASIZE);
  if(DEBUG) printf("Receive Data: %s", buf);

  /* Check if we got the "Bad Login" info or the Plugin MD5 hash marker */
  if(strstr(buf, PLUGS_MD5)) login = 1;

  /* Take the last newline out */
  retcode=recv(fd, buf, 1, 0);

  free(buf);
  return login;
}

/* ------------------------------------------------------------------------- *
 * scanner_getplugs tries to retrieve the list of plugins from the server.   *
 * It returns the number of retrieved plugins for success, 0 for failure.    *
 * ------------------------------------------------------------------------- */

int scanner_getplugs(int fd){

  char * buf = NULL;
  size_t len;
  int i = 0;
  int j = 0;
  int retcode = 0;

  /* client request to get the server plugins, + newline */
  if(DEBUG) printf("Sending Data: %s%c", PLUGS_REQ, '\n');

  retcode = SSL_write(ssl, PLUGS_REQ, strlen(PLUGS_REQ));
  retcode = SSL_write(ssl, newline, 1);

  buf = (char *) malloc(MAXDATASIZE);
  memset(buf, '\0', MAXDATASIZE);

  /* Now we take the data out */
  retcode=SSL_read(ssl, buf, MAXDATASIZE);
  if(DEBUG) printf("Receive Data: %s", buf);

  /* Check if we got the plugin list start marker */
  if(strstr(buf, PLUGS_START)) printf("Plugin list marker received. All plugins should follow...\n");

  /* cycle through the big chunk of preferences data we */
  /* are receiving.                                     */
  memset(buf, '\0', MAXDATASIZE);
 
  while(1) {
    len=SSL_read(ssl, buf, MAXDATASIZE);

    /* check if the end marker hits */
    if(strstr(buf, SERVER_END_MARKER)) { 
      if(DEBUG) printf("Receive Data: %s\n", buf);
      break;
    }

    plugs_counter++;

    if(DEBUG == 1 ) { i++; if (i == 10) { printf("."); i=0; } }
    if(DEBUG == 2 ) printf("%s\n", buf);
    if(DEBUG == 3) {
      printf("Len %5.0d Counter %5.0d Plugin ID: ", len, plugs_counter);
      for(j=0;j!=' ';j++) putchar(buf[i]);
      putchar('\n');
    }

    /* clear the buffer */
    memset(buf, '\0', MAXDATASIZE);
  }

  free(buf);
  return plugs_counter;
}

/* ------------------------------------------------------------------------- *
 * scanner_getprefs retrieves the list of preferences from the server. It    *
 * returns the number of retrieved preferences for success, 0 for failure.   *
 * ------------------------------------------------------------------------- */

int scanner_getprefs(int fd) {

  char * buf = NULL;
  int i = 0;
  int retcode = 0;
  size_t len;

  /* client request to get the server preferences, + newline */
  if(DEBUG) printf("Sending Data: %s%c", PREFS_REQ, '\n');

  retcode = SSL_write(ssl, PREFS_REQ, strlen(PREFS_REQ));
  retcode = SSL_write(ssl, newline, 1);

  buf = (char *) malloc(MAXDATASIZE);
  memset(buf, '\0', MAXDATASIZE);

  /* receive the Preferences List start marker */
    len=SSL_read(ssl, buf, strlen(PREFS_START)+1);
  if(DEBUG) printf("Receive Data: %s", buf);

  if(! strstr(buf, PREFS_START)) exit(1);

  /* clear the buffer */
  memset(buf, '\0', MAXDATASIZE);

  while(1) {
    len=SSL_read(ssl, buf, MAXDATASIZE);

    /* check if the end marker hits */
    if(strstr(buf, SERVER_END_MARKER)) {
      if(DEBUG) printf("Receive Data: %s\n", buf);
      break;
    }

    prefs_counter++;

    if(DEBUG == 1 ) { i++; if (i == 10) { printf("."); i=0; } }
    if(DEBUG == 2 ) printf("%s\n", buf);
    if(DEBUG == 3) {
      printf("Len %3.0d Counter %3.0d Pref: ", len, prefs_counter);
      printf("%s", buf);
    }

    /* clear the buffer */
    memset(buf, '\0', MAXDATASIZE);
  }
 
  /* Take the last newline out */
  retcode=recv(fd, buf, 1, 0);

  free(buf);
  return prefs_counter;
}

/* ------------------------------------------------------------------------- *
 * scanner_getrules retrieves the list of rules from the server. It          *
 * returns the number of retrieved rules for success, 0 for failure.         *
 * ------------------------------------------------------------------------- */

int scanner_getrules(int fd){

  char * buf = NULL;
  int i = 0;
  int retcode = 0;
  size_t len;

  /* client request to get the server rules, + newline */
  if(DEBUG) printf("Sending Data: %s%c", RULES_REQ, '\n');

  retcode = SSL_write(ssl, RULES_REQ, strlen(RULES_REQ));
  retcode = SSL_write(ssl, newline, 1);

  buf = (char *) malloc(MAXDATASIZE);
  memset(buf, '\0', MAXDATASIZE);

  /* receive the Rules List start marker */
  len=SSL_read(ssl, buf, strlen(RULES_START)+1);
  if(DEBUG) printf("Receive Data: %s", buf);

  if(! strstr(buf, RULES_START)) exit(1);

  while(1) {
    len=SSL_read(ssl, buf, MAXDATASIZE);

    /* check if the end marker hits */
    if(strstr(buf, SERVER_END_MARKER)) { 
      if(DEBUG) printf("Receive Data: %s\n", buf);
      break;
    }

    prefs_counter++;

    if(DEBUG == 1 ) { i++; if (i == 10) { printf("."); i=0; } }
    if(DEBUG == 2 ) printf("%s\n", buf);
    if(DEBUG == 3) {
      printf("Len %3.0d Counter %3.0d Rules: ", len, rules_counter);
      printf("%s\n", buf);
    }

    /* Now we take the newline out */
    retcode=recv(fd, buf, 1, 0);

    /* clear the buffer */
    memset(buf, '\0', MAXDATASIZE);
  }

  /* Take the last newline out */
  retcode=recv(fd, buf, 1, 0);

  free(buf);
  return rules_counter;
}

int main() {

  int fd;
  int ret;

  fd = scanner_connect(DEST_IP, DEST_PORT);

  ret = scanner_login(fd, USERNAME, PASSWORD);

  if(ret == 0) {
    printf("login of %s with %s failed.\n", USERNAME, PASSWORD);
    close(fd);
    exit(1);
  }

  printf("sucessful login\n");

  plugs_counter = scanner_getplugs(fd);

  if(plugs_counter) printf("Found %d Plugins.\n", plugs_counter);
  else printf("\nFailed to receive any plugins.\n");

  prefs_counter = scanner_getprefs(fd);

  if(prefs_counter) printf("Found %d Prefs.\n", prefs_counter);
  else printf("\nFailed to receive any preferences.\n");

  rules_counter = scanner_getrules(fd);

  if(rules_counter >= 0) printf("Found %d Rules.\n", rules_counter);
  else printf("\nFailed to receive any Rules.\n");
 
  printf("Closing connection to %s.\n", DEST_IP);
  close(fd);
  exit(0);
}
