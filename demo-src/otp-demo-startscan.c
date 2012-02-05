/* ------------------------------------------------------------------------ *
 *                                                                          *
 * otp-demo-startscan.c                                                     *
 *                                                                          *
 * This program demonstrates the communication with a OpenVAS Scanner       *
 * and starts a new scan against localhost.                                 *
 * OpenSSL libraries provide the required encryption functions. No client   *
 * certs are used, and we use username/password together with the default   *
 * connection method TLSv1.                                                 *
 *                                                                          *
 * The following settings according to OTP 1.0 are used:                    *
 * CLIENT <|> PREFERENCES <|>                                               *
 * plugin_set <|>                                                           *
 * [other prefs data]                                                       *
 * <|> CLIENT                                                               *
 * CLIENT <|> LONG_ATTACK <|>  <|> CLIENT                                   *
 *                                                                          *
 * This program has been written and tested with openvassd version 3.2.5    *
 * 20120110 frank4dd                                                        *
 *                                                                          *
 * compile instructions:                                                    *
 * gcc -lssl -lcrypt otp-demo-startscan.c -o otp-demo-startscan             *
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
#define DEBUG 1

#define CIPHER_LIST "EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC3-SHA:DES-CBC3-MD5:DHE-DSS-RC4-SHA:IDEA-CBC-SHA:RC4-SHA:RC4-MD5:IDEA-CBC-MD5:RC2-CBC-MD5:RC4-MD5"

#define DEST_IP "127.0.0.1"
#define DEST_PORT 9391
#define MAXTRANS 1
/* MAXDATASIZE should be large enough to handle a huge plugin *
 * description so we get a newline. If it is to small, we get *
 * chunks with no newline counted and its just a mess.        */
#define MAXDATASIZE 16384
#define MAXCOMMSIZE 81
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
/* The spec is inconsistent, the next message does not end with a <|> */
/* http://www.openvas.org/compendium/otp-plugin_dependencies.html     */
#define PDEPS_START "SERVER <|> PLUGINS_DEPENDENCIES"
#define SCAN_START  "SERVER <|> TIME <|> SCAN_START <|>"
#define SCAN_END  "SERVER <|> TIME <|> SCAN_END <|>"
#define SERVER_END_MARKER "<|> SERVER"
#define CLIENT_END_MARKER "<|> CLIENT"
#define PLUGS_REQ "CLIENT <|> COMPLETE_LIST <|>" /* request plugins from server */
#define PREFS_REQ "CLIENT <|> GO ON <|> CLIENT"  /* confirms plugs have been received, requests server to continue with prefs */
#define PREFS_SEND "CLIENT <|> PREFERENCES <|>"  /* send prefs to server */
#define RULES_REQ "CLIENT <|> RULES <|>"         /* request rules from server */
#define NSCAN_REQ "CLIENT <|> LONG_ATTACK <|>"   /* start a new scan */
#define SERVER_BYE "SERVER <|> BYE <|> BYE <|> SERVER"

#define TARGET_IP "127.0.0.1"

const char newline[2] = {'\n', '\0'};
char server_ntp_version[255];

int  plugs_counter = 0;
int  prefs_counter = 0;
int  rules_counter = 0;
int  pdeps_counter = 0;
SSL           *ssl;


/* ------------------------------------------------------------------------- *
 * scanner_connect creates a new tcp session to the scan server and returns  *
 * 0 for success, -1 for failure.                                           *
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
  if(DEBUG) printf("SSL_get_cipher = %s\n", SSL_get_cipher(ssl));

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

int scanner_login(char * username, char * password){

  char * buf = NULL;
  buf = (char *) malloc(MAXDATASIZE);
  memset(buf, '\0', MAXDATASIZE);
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

  free(buf);
  return login;
}

/* ------------------------------------------------------------------------- *
 * scanner_getprefs retrieves the list of preferences from the server. It    *
 * returns the number of retrieved preferences for success, 0 for failure.   *
 * ------------------------------------------------------------------------- */

int scanner_getprefs() {

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
 
  free(buf);
  return prefs_counter;
}

/* ------------------------------------------------------------------------- *
 * scanner_getrules retrieves the list of rules from the server. It          *
 * returns the number of retrieved rules for success, 0 for failure.         *
 * ------------------------------------------------------------------------- */

int scanner_getrules(){

  char * buf = NULL;
  int i = 0;
  //int retcode = 0;
  size_t len;

  /* client request to get the server rules, + newline */
  //if(DEBUG) printf("Sending Data: %s%c", RULES_REQ, '\n');
  //retcode = SSL_write(ssl, RULES_REQ, strlen(RULES_REQ));
  //retcode = SSL_write(ssl, newline, 1);

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

    rules_counter++;

    if(DEBUG == 1 ) { i++; if (i == 10) { printf("."); i=0; } }
    if(DEBUG == 2 ) printf("%s\n", buf);
    if(DEBUG == 3) {
      printf("Len %3.0d Counter %3.0d Rules: ", len, rules_counter);
      printf("%s\n", buf);
    }

    /* clear the buffer */
    memset(buf, '\0', MAXDATASIZE);
  }

  free(buf);
  return rules_counter;
}

/* ------------------------------------------------------------------------- *
 * scanner_getpdeps retrieves the list of plugin dependencies. It            *
 * returns the number of retrieved deps for success, 0 for failure.          *
 * Dependencies are always send after the rules message, we don't need       *
 * to initiate the sending with a client command.                            *
 * ------------------------------------------------------------------------- */
int scanner_getpdeps(){

  char * buf = NULL;
  int i = 0;
  //int retcode = 0;
  size_t len;

  buf = (char *) malloc(MAXDATASIZE);
  memset(buf, '\0', MAXDATASIZE);

  /* receive the Dependencies List start marker */
  len=SSL_read(ssl, buf, strlen(PDEPS_START)+1);
  if(DEBUG) printf("Receive Data: %s", buf);

  if(! strstr(buf, PDEPS_START)) exit(1);

  while(1) {
    len=SSL_read(ssl, buf, MAXDATASIZE);

    /* check if the end marker hits */
    if(strstr(buf, SERVER_END_MARKER)) {
      if(DEBUG) printf("Receive Data: %s\n", buf);
      break;
    }

    pdeps_counter++;

    if(DEBUG == 1 ) { i++; if (i == 10) { printf("."); i=0; } }
    if(DEBUG == 2 ) printf("%s\n", buf);
    if(DEBUG == 3) {
      printf("Len %3.0d Counter %3.0d Dependencies: ", len, pdeps_counter);
      printf("%s\n", buf);
    }

    /* clear the buffer */
    memset(buf, '\0', MAXDATASIZE);
  }

  free(buf);
  return pdeps_counter;
}

/* ------------------------------------------------------------------------- *
 * scanner_setprefs sends the preferences, starting with the list of plugins *
 * to the scan server.                                                       *
 * ------------------------------------------------------------------------- */

int scanner_setprefs(){
  char send_buf[MAXCOMMSIZE] = PREFS_SEND;
  static char preference1[] = "Port range <|> 0-1024";
  static char plugstart[] = "plugin_set <|> ";
  static char plugslist[] = "1.3.6.1.4.1.25623.1.0.14259;";
  //static char clientplugs[] = "plugin_set <|> 1.3.6.1.4.1.25623.1.0.10335";
  int retcode = 0;

  /* client request to send the preferences, + newline */
  if(DEBUG) printf("Sending Data: %s\n", send_buf);
  retcode = SSL_write(ssl, send_buf, strlen(send_buf));
  retcode = SSL_write(ssl, newline, 1);
  if(DEBUG) printf("Sending Data: %s\n", preference1);
  retcode = SSL_write(ssl, preference1, strlen(preference1));
  retcode = SSL_write(ssl, newline, 1);
  if(DEBUG) printf("Sending Data: %s%s\n", plugstart, plugslist);
  retcode = SSL_write(ssl, plugstart, strlen(plugstart));
  retcode = SSL_write(ssl, plugslist, strlen(plugslist));
  retcode = SSL_write(ssl, newline, 1);

  /* client send the end marker for preferences, + newline */
  if(DEBUG) printf("Sending Data: %s\n", CLIENT_END_MARKER);
  retcode = SSL_write(ssl, CLIENT_END_MARKER, strlen(CLIENT_END_MARKER));
  retcode = SSL_write(ssl, newline, 1);

  return 0;
}

/* ------------------------------------------------------------------------- *
 * scanner_setrules sends the self-imposed client rules to the scan server.  *
 * ------------------------------------------------------------------------- */

int scanner_setrules(){
  char send_buf[MAXCOMMSIZE] = RULES_REQ;
  int retcode = 0;

  /* client request to send the preferences, + newline */
  if(DEBUG) printf("Sending Data: %s\n", send_buf);
  retcode = SSL_write(ssl, send_buf, strlen(send_buf));
  retcode = SSL_write(ssl, newline, 1);


  /* client send the end marker for preferences, + newline */
  if(DEBUG) printf("Sending Data: %s\n", CLIENT_END_MARKER);
  retcode = SSL_write(ssl, CLIENT_END_MARKER, strlen(CLIENT_END_MARKER));
  retcode = SSL_write(ssl, newline, 1);

  return 0;
}

/* ------------------------------------------------------------------------- *
 * scanner_newscan sends the preferences, starting with the list of plugins  *
 * to the scan server.                                                       *
 * ------------------------------------------------------------------------- */

int scanner_newscan(){

  char recv_buf[MAXCOMMSIZE] = "";
  char send_buf[MAXCOMMSIZE] = NSCAN_REQ;
  int retcode = 0;

  /* client request a new scan, sending target IP + newline */
  if(DEBUG) printf("Sending Data: %s\n", send_buf);
  retcode = SSL_write(ssl, send_buf, strlen(send_buf));
  retcode = SSL_write(ssl, newline, 1);

  snprintf(send_buf, sizeof(send_buf), "9\n127.0.0.1");
  if(DEBUG) printf("Sending Data: %s\n", send_buf);
  retcode = SSL_write(ssl, send_buf, strlen(send_buf));
  retcode = SSL_write(ssl, newline, 1);

  retcode=SSL_read(ssl, recv_buf, MAXDATASIZE);
  if(DEBUG) printf("Receive Data: %s", recv_buf);

  /* SERVER <|> TIME <|> SCAN_START <|> Sat Jan 21 16:39:00 2012 <|> SERVER */
  /* Check if we got the "SCAN_START" info */

  if(strstr(recv_buf, SCAN_START)) return 1;
  return 0;
}

int scanner_results() {
  char * recv_buf = NULL;
  int retcode = 0;

  recv_buf = (char *) malloc(MAXDATASIZE);

  /* Now we take the data out for 10 minutes = 600 secs */
  while(1) {
    memset(recv_buf, '\0', MAXDATASIZE);
    retcode=SSL_read(ssl, recv_buf, MAXDATASIZE);
    if(DEBUG && retcode > 0) printf("Receive Data: %s", recv_buf);
    if(strstr(recv_buf, SCAN_END)) break;
    sleep(10);
  }

  return 0;
}

/* ------------------------------------------------------------------------- *
 * scanner_logout closes the connection to the scan server.                  *
 * ------------------------------------------------------------------------- */

int scanner_logout(){
  int retcode = 0;

  retcode=SSL_shutdown(ssl);
  //sleep(1);
  //retcode=SSL_shutdown(ssl);
  if(DEBUG) printf("Received retcode: %d\n", retcode);
  return retcode;
}


int main() {
  int ret;

  printf("==== start scanner_connect ====\n");
  ret = scanner_connect(DEST_IP, DEST_PORT);
  printf("==== end scanner_connect ====\n\n");

  printf("==== start scanner_login ====\n");
  ret = scanner_login(USERNAME, PASSWORD);

  if(ret == 0) {
    printf("login of %s with %s failed.\n", USERNAME, PASSWORD);
    exit(1);
  }

  printf("sucessful login\n");
  printf("==== end scanner_login ====\n\n");

  /* before we can start the attack, we need to get all prefs and rules */
  printf("==== start scanner_getprefs ====\n");
  prefs_counter = scanner_getprefs();
  printf("==== end scanner_getprefs ====\n\n");

  printf("==== start scanner_getrules ====\n");
  rules_counter = scanner_getrules();
  printf("==== end scanner_getrules ====\n\n");

  printf("==== start scanner_getpdeps ====\n");
  pdeps_counter = scanner_getpdeps();
  printf("==== end scanner_getpdeps ====\n\n");

  /* before we can start the attack, we need to send prefs and rules */
  printf("==== start scanner_setprefs ====\n");
  scanner_setprefs();
  printf("==== end scanner_setpreps ====\n\n");

  printf("==== start scanner_setrules ====\n");
  scanner_setrules();
  printf("==== end scanner_setrules ====\n\n");

  printf("==== start scanner_newscan ====\n");
  ret = scanner_newscan();
  if(ret == 0) {
    printf("Starting a new scan failed.\n");
    exit(1);
  }
  printf("==== end scanner_newscan ====\n\n");

  printf("==== start scanner_results ====\n");
  scanner_results();
  printf("==== end scanner_results ====\n\n");

  printf("==== start scanner_logout ====\n");
  scanner_logout();
  printf("==== end scanner_logout ====\n\n");

  printf("Closed connection to %s.\n", DEST_IP);
  exit(0);
}
