/* ------------------------------------------------------------------------ *
 *                                                                          *
 * otp-demo-dumpprefs.c  username/password authenticated                    *
 *                                                                          *
 * This program demonstrates the communication with a OpenVAS scanner       *
 * and  saves the returned openvas server settings to a dump file           *
 * called otp-demo-dumpprefs.txt                                            *
 *                                                                          *
 * This program has been written and tested with openvassd version 3.2.5    *
 * 20120109 frank4dd                                                        *
 *                                                                          *
 * compile instructions:                                                    *
 * gcc -lssl -lcrypt otp-demo-dumpprefs.c -o otp-demo-dumpprefs.c           *
 *                                                                          *
 * Don't forget to add a user to openvassd, ie. like below:                 *
 *                                                                          *
 * susie:/home/openvas/sbin # ./openvas-adduser                             *
 * Using /var/tmp as a temporary file holder                                *
 *                                                                          *
 * Add a new openvassd user                                                 *
 * ------------------------                                                 *
 *                                                                          *
 * Login : fm2                                                              *
 * Authentication (pass/cert) [pass] :                                      *
 * Login password : test                                                    * 
 * Login password (again) : test                                            *
 *                                                                          *
 * User rules                                                               *
 * ----------                                                               *
 * openvassd has a rules system which allows you to restrict the hosts      *
 * that fm2 has the right to test. For instance, you may want               *
 * him to be able to scan his own host only.                                *
 *                                                                          *
 * Please see the openvas-adduser(8) man page for the rules syntax          *
 *                                                                          *
 * Enter the rules for this user, and hit ctrl-D once you are done :        *
 * (the user can have an empty rules set)                                   *
 *                                                                          *
 * Login             : fm2                                                  *
 * Password          : ***********                                          *
 * DN                :                                                      *
 * Rules             :                                                      *
 *                                                                          *
 * Is that ok ? (y/n) [y]                                                   *
 * user added.                                                              *
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
/* DEBUG = 1: adds the OTP protocol strings received */
/* DEBUG = 2: shows in addition the received data and counters */
#define DEBUG 2

#define CIPHER_LIST "EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC3-SHA:DES-CBC3-MD5:DHE-DSS-RC4-SHA:IDEA-CBC-SHA:RC4-SHA:RC4-MD5:IDEA-CBC-MD5:RC2-CBC-MD5:RC4-MD5"

#define DEST_IP "70.85.16.97"
#define DEST_PORT 9391

/* MAXDATASIZE should be large enough to handle a huge plugin *
 * description so we get a newline. If it is to small, we get *
 * chunks with no newline counted and its just a mess.        */
#define MAXDATASIZE 26384

#define USERPROMPT "User : "
#define PASSPROMPT "Password : "
#define USERNAME "fm2"
#define PASSWORD "test"
#define CLIENT_OTP_VERSION "< OTP/1.0 >"
#define SERVER_OTP_VERSION "< OTP/1.0 >"
#define PLUGS_MD5 "SERVER <|> PLUGINS_MD5 <|>"
#define PLUGS_START "SERVER <|> PLUGIN_LIST <|>"
#define PREFS_START "SERVER <|> PREFERENCES <|>"
#define RULES_START "SERVER <|> RULES <|>"
#define SERVER_END_MARKER "<|> SERVER"
#define PLUGS_REQ "CLIENT <|> COMPLETE_LIST"
#define PREFS_REQ "CLIENT <|> PREFERENCES"
#define RULES_REQ "CLIENT <|> RULES"

const char newline[2] = {'\n', '\0'};
char server_otp_version[255];

int  plugs_counter = 0;
int  prefs_counter = 0;
int  rules_counter = 0;
SSL           *ssl;


/* ------------------------------------------------------------------------- *
 * scanner_connect creates a new session to the openvas server and returns   *
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
  /* for TLSv1, we use TLSv1_client_method() */
  if((ssl_ctx = SSL_CTX_new(TLSv1_client_method())) == NULL) 
    printf("SSL_CTX_new() context creation error\n");

  /* enable all SSL engine bug workaround options (i.e. Netscape, Microsoft) */
  if(SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL) < 0)
    printf("SSL_CTX_set_options error\n");

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

  /* get the received openvas server certificate */
  if(! (servercert = SSL_get_peer_certificate(ssl)))
    printf("SSL_get_peer_certificate() error: cannot get server certificate\n");

  /* print the received openvas server certificate */
  if(DEBUG == 2) {
    BIO                  *outbio;
    outbio = BIO_new_fd(fileno(stdout), BIO_NOCLOSE);
    if (! (X509_print_ex(outbio, servercert, 0, XN_FLAG_SEP_MULTILINE)))
      BIO_printf(outbio, "Error printing certificate text information\n");
  }

  return 1;
}

/* ------------------------------------------------------------------------- *
 * scanner_login tries to log in with the username and password provided. It *
 * returns 1 for success, 0 for failure.                                     *
 * ------------------------------------------------------------------------- */

int scanner_login(char * username, char * password){

  char * buf = NULL;
  int login = 0 , retcode = 0;

  /* send the client protocol version, followed by a newline */
  if(DEBUG) printf("Sending Data: %s%c", CLIENT_OTP_VERSION, '\n');
  retcode = SSL_write(ssl, CLIENT_OTP_VERSION, strlen(CLIENT_OTP_VERSION));
  retcode = SSL_write(ssl, newline, 1);

  /* allocate and clear the buffer */
  buf = (char *) malloc(MAXDATASIZE);
  memset(buf, '\0', MAXDATASIZE);

  /* receive the server protocol version, followed by a newline */

  retcode=SSL_read(ssl, buf, strlen(SERVER_OTP_VERSION)+1);
  if(DEBUG) printf("Receive Data: %s", buf);

  /* set global variable server protocol version, remove the newline */
  strncpy(server_otp_version, buf, retcode-1);

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

  /* Check if we got the "Bad Login" info or the Plugin List start marker */
  /* Receive Data: SERVER <|> PLUGINS_MD5 <|> ba70d1d3f851b90c4eca5ee3c61e8f67 <|> SERVER */
  if(strstr(buf, PLUGS_MD5)) login = 1;

  free(buf);
  return login;
}

/* ------------------------------------------------------------------------- *
 * scanner_getplugs tries to retrieve the list of plugins from the server.   *
 * It returns the number of retrieved plugins for success, 0 for failure.    *
 * ------------------------------------------------------------------------- */

int scanner_getplugs(FILE * plugsfd){

  char * buf = NULL;
  size_t len;
  int i;
  int retcode=0;

  buf = (char *) malloc(MAXDATASIZE);
  memset(buf, '\0', MAXDATASIZE);

  /* send the plugin request followed by a newline */
  if(DEBUG) printf("Sending Data: %s\n", PLUGS_REQ);
  retcode = SSL_write(ssl, PLUGS_REQ, strlen(PLUGS_REQ));
  retcode = SSL_write(ssl, newline, 1);

  /* Now we take the data out */
  retcode=SSL_read(ssl, buf, MAXDATASIZE);
  if(DEBUG) printf("Receive Data: %s", buf);

  /* Check if we got the plugin list start marker */
  if(strstr(buf, PLUGS_START)) printf("Plugin list marker received. All plugins should follow.\n");
  fputs(buf, plugsfd);

  /* cycle through the big chunk of preferences data we */
  /* are receiving.                                     */
 
  while(1) {
    len=SSL_read(ssl, buf, MAXDATASIZE);

    /* check if the end marker hits */
    if(strstr(buf, SERVER_END_MARKER)) { 
      fputs(buf, plugsfd);
      if(DEBUG) printf("Receive Data: %s\n", buf);
      break;
    }

    plugs_counter++;

    fputs(buf, plugsfd);
    //if(DEBUG == 2 ) printf("%s\n", buf);
    if(DEBUG == 2) {
      printf("Len %6.0d Counter %5.0d Plugin ID: ", len, plugs_counter);
      for(i=0;i!=' ';i++) putchar(buf[i]);
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

int scanner_getprefs(FILE * prefsfd) {

  char * buf = NULL;
  size_t len;
  int i = 0;
  int retcode=0;

  buf = (char *) malloc(MAXDATASIZE);
  memset(buf, '\0', MAXDATASIZE);

  /* send the plugin request followed by a newline */
  if(DEBUG) printf("Sending Data: %s\n", PREFS_REQ);
  retcode = SSL_write(ssl, PREFS_REQ, strlen(PREFS_REQ));
  retcode = SSL_write(ssl, newline, 1);

  /* receive the Preferences List start marker */
  len=SSL_read(ssl, buf, strlen(PREFS_START)+1);
  if(DEBUG) printf("Receive Data: %s", buf);

  if(! strstr(buf, PREFS_START)) exit(1);
  fputs(buf, prefsfd);

  /* clear the buffer */
  memset(buf, '\0', MAXDATASIZE);

  while(1) {
    len=SSL_read(ssl, buf, MAXDATASIZE);

    /* check if the end marker hits */
    if(strstr(buf, SERVER_END_MARKER)) {
      fputs(buf, prefsfd);
      if(DEBUG) printf("Receive Data: %s\n", buf);
      break;
    }

    prefs_counter++;

    fputs(buf, prefsfd);
    if(DEBUG == 2) {
      printf("Len %3.0d Counter %3.0d Pref: ", len, prefs_counter);
      if(strlen(buf) < 54) printf("%s", buf);
      else { 
        for(i=0;i<53;i++) putchar(buf[i]);
        putchar('\n');
      }
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

int scanner_getrules(FILE * rulesfd){

  char * buf = NULL;
  size_t len;
  int retcode=0;

  buf = (char *) malloc(MAXDATASIZE);
  memset(buf, '\0', MAXDATASIZE);

  /* send the plugin request followed by a newline */
  if(DEBUG) printf("Sending Data: %s\n", RULES_REQ);
  retcode = SSL_write(ssl, RULES_REQ, strlen(RULES_REQ));
  retcode = SSL_write(ssl, newline, 1);

  /* receive the Rules List start marker */
  len=SSL_read(ssl, buf, strlen(RULES_START)+1);
  if(DEBUG) printf("Receive Data: %s", buf);

  if(! strstr(buf, RULES_START)) exit(1);
  fputs(buf, rulesfd);

  memset(buf, '\0', MAXDATASIZE);

  while(1) {
    len=SSL_read(ssl, buf, MAXDATASIZE);

    /* check if the end marker hits */
    if(strstr(buf, SERVER_END_MARKER)) { 
      fputs(buf, rulesfd);
      if(DEBUG) printf("Receive Data: %s\n", buf);
      break;
    }

    prefs_counter++;

    fputs(buf, rulesfd);
    if(DEBUG == 2) {
      printf("Len %3.0d Counter %3.0d Rules: ", len, rules_counter);
      printf("%s\n", buf);
    }

    /* clear the buffer */
    memset(buf, '\0', MAXDATASIZE);
  }

  free(buf);
  return rules_counter;
}

int main() {

  int fd;
  int ret;
  FILE *plugsfile, *prefsfile, *rulesfile;;

  fd = scanner_connect(DEST_IP, DEST_PORT);

  ret = scanner_login(USERNAME, PASSWORD);

  if(ret == 0) {
    printf("login of %s with %s failed.\n", USERNAME, PASSWORD);
    close(fd);
    exit(1);
  }

  printf("sucessful login\n");

  if(! (plugsfile = fopen("./otp-demo-dumpplugs.txt", "w")))
        printf("Error: Can't create ./otp-demo-dumpplugs.txt file.");

  if(! (prefsfile = fopen("./otp-demo-dumpprefs.txt", "w")))
        printf("Error: Can't create ./otp-demo-dumpprefs.txt file.");

  if(! (rulesfile = fopen("./otp-demo-dumprules.txt", "w")))
        printf("Error: Can't create ./otp-demo-dumprules.txt file.");

  plugs_counter = scanner_getplugs(plugsfile);

  if(plugs_counter) printf("Found %d Plugins.\n", plugs_counter);
  else printf("\nFailed to receive any plugins.\n");

  prefs_counter = scanner_getprefs(prefsfile);

  if(prefs_counter) printf("Found %d Prefs.\n", prefs_counter);
  else printf("\nFailed to receive any preferences.\n");

  rules_counter = scanner_getrules(rulesfile);

  if(rules_counter >= 0) printf("Found %d Rules.\n", rules_counter);
  else printf("\nFailed to receive any Rules.\n");
 
  printf("Closing connection to %s.\n", DEST_IP);
  fclose(plugsfile);
  fclose(prefsfile);
  fclose(rulesfile);
  close(fd);
  exit(0);
}
