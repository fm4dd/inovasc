/* ------------------------------------------------------------------------ *
 *                                                                          *
 * ntp-ssl-demo-cert.c  with client certificate authentication              *
 *                                                                          *
 * This program demonstrates the communication with a Nessus daemon         *
 * and  counts the returned nessus server settings to the screen.           *
 * Unlike ntp-demo.c, it uses SSL for encryption (relies on OpenSSL         *
 * libraries to provide the required en/decryption functions). Here,        *
 * certs are used, and ssl_version=SSLv3 must be set in nessusd.conf.       *
 *                                                                          *
 * The Following settings according to NTP 1.2 are retrieved:               *
 * SERVER <|> PLUGIN_LIST <|> [data] <|> SERVER                             *
 * SERVER <|> PREFERENCES <|> [data] <|> SERVER                             *
 * SERVER <|> RULES <|> [data] <|> SERVER                                   *
 *                                                                          *
 * this program has been written and tested with nessusd version 2.2.0      *
 * 20041208 frank4dd                                                        *
 *                                                                          *
 * compile instructions:                                                    *
 * gcc -lssl -lcrypt ntp-ssl-demo-cert.c -o ntp-ssl-demo-cert               *
 * ------------------------------------------------------------------------ */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>

/* DEBUG = 0: connects and returns number of plugins, preferences, rules */
/* DEBUG = 1: adds the NTP protocol strings received */
/* DEBUG = 2: shows in addition received plugin ID's and counters */
/* DEBUG = 3: shows in addition to 2 All Plugin data */
#define DEBUG 3

#define CIPHER_LIST "EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC3-SHA:DES-CBC3-MD5:DHE-DSS-RC4-SHA:IDEA-CBC-SHA:RC4-SHA:RC4-MD5:IDEA-CBC-MD5:RC2-CBC-MD5:RC4-MD5"

#define DEST_IP "127.0.0.1"
#define DEST_PORT 1241

/* MAXDATASIZE should be large enough to handle a huge plugin *
 * description so we get a newline. If it is to small, we get *
 * chunks with no newline counted and its just a mess.        */
#define MAXDATASIZE 16384

#define USERPROMPT "User : "
#define PASSPROMPT "Password : "
#define USERNAME "guest"
/* Although we authenticate with a client certificate, the NTP protocol  *
 * still requires a password string, but its a dummy string of any value */
#define PASSWORD "*****"
#define CA_DIR "NULL"
#define CA_FILE "../etc/cacert.pem"
#define CLIENT_CERT "../etc/cert_guest.pem"
#define CLIENT_PRIVKEY "../etc/key_guest.pem"
#define CLIENT_NTP_VERSION "< NTP/1.2 >"
#define SERVER_NTP_VERSION "< NTP/1.2 >"
#define PLUGS_START "SERVER <|> PLUGIN_LIST <|>"
#define PREFS_START "SERVER <|> PREFERENCES <|>"
#define RULES_START "SERVER <|> RULES <|>"
#define SERVER_END_MARKER "<|> SERVER"

char server_ntp_version[255];

int  plugs_counter = 0;
int  prefs_counter = 0;
int  rules_counter = 0;
SSL           *ssl;


/* ------------------------------------------------------------------------- *
 * nessus_connect creates a new tcp session to the nessus server and returns *
 * the file descriptor to it.                                                *
 * ------------------------------------------------------------------------- */
int nessus_connect(char * nessus_ip, int nessus_port) {
  int sockfd;
  struct sockaddr_in dest_addr;
  static SSL_CTX        *ssl_ctx = NULL;
  X509			*servercert;

  if(DEBUG) printf("Creating socket file descriptor.\n");
  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  if(DEBUG) printf("Loading content into filedescriptor.\n");
  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(nessus_port);
  dest_addr.sin_addr.s_addr=inet_addr(nessus_ip);

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
  if((ssl_ctx = SSL_CTX_new(SSLv3_client_method())) == NULL) 
    printf("SSL_CTX_new() context creation error\n");

  /* enable all SSL engine bug workaround options (i.e. Netscape, Microsoft) */
  if(SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL) < 0)
    printf("SSL_CTX_set_options error\n");

  /* choose list of available SSL_CIPHERs with a control string */
  if(! SSL_CTX_set_cipher_list(ssl_ctx, CIPHER_LIST))
    printf("SSL_CTX_set_cipher_list error\n");

  /* verify the CA file and path */
  if(SSL_CTX_load_verify_locations(ssl_ctx, CA_FILE, CA_DIR) != 1)
    printf("Error loading CA certificate: %s\n", CA_FILE);

  /* load the client certificate we present to the nessus server */
  if(SSL_CTX_use_certificate_chain_file(ssl_ctx, CLIENT_CERT) != 1)
    printf("Error loading certificate: %s\n", CLIENT_CERT);

  /* load the client certificate private key */
  if(SSL_CTX_use_PrivateKey_file(ssl_ctx, CLIENT_PRIVKEY, SSL_FILETYPE_PEM) != 1)
    printf("Error loading cert private key: %s\n", CLIENT_PRIVKEY);

  /* Here we set the verification mode to SSL_VERIFY_PEER */
  SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_verify_depth(ssl_ctx, 4);

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

  /* get the received nessus server certificate */
  if(! (servercert = SSL_get_peer_certificate(ssl)))
    printf("SSL_get_peer_certificate() error: cannot get server certificate\n");

  /* print the received nessus server certificate */
  if(DEBUG == 2) {
    BIO                  *outbio;
    outbio = BIO_new_fd(fileno(stdout), BIO_NOCLOSE);
    if (! (X509_print_ex(outbio, servercert, 0, XN_FLAG_SEP_MULTILINE)))
      BIO_printf(outbio, "Error printing certificate text informationi\n");
  }

  return 1;
}

/* ------------------------------------------------------------------------- *
 * nessus_login tries to log in with the username and password provided. It  *
 * returns 1 for success, 0 for failure.                                     *
 * ------------------------------------------------------------------------- */

int nessus_login(char * username, char * password){

  char * buf = NULL;
  int login = 0 , retcode = 0;
  const char newline[2] = {'\n', '\0'};

  /* send the client protocol version, followed by a newline */
  if(DEBUG) printf("Sending Data: %s%c", CLIENT_NTP_VERSION, '\n');
  retcode = SSL_write(ssl, CLIENT_NTP_VERSION, strlen(CLIENT_NTP_VERSION));
  retcode = SSL_write(ssl, newline, 1);

  buf = (char *) malloc(MAXDATASIZE);

  /* receive the server protocol version, followed by a newline */

  retcode=SSL_read(ssl, buf, strlen(SERVER_NTP_VERSION)+1);
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

  /* send  five *'s as the password, followed by a newline */
  if(DEBUG) printf("Sending Data: %s\n", PASSWORD);
  retcode = SSL_write(ssl, PASSWORD, strlen(PASSWORD));
  retcode = SSL_write(ssl, newline, 1);

  /* clear the buffer */
  memset(buf, '\0', MAXDATASIZE);

  /* Now we take the data out */
  retcode=SSL_read(ssl, buf, MAXDATASIZE);
  if(DEBUG) printf("Receive Data: %s", buf);

  /* Check if we got the "Bad Login" info or the Plugin List start marker */
  if(strstr(buf, PLUGS_START)) login = 1;

  free(buf);
  return login;
}

/* ------------------------------------------------------------------------- *
 * nessus_getplugs tries to retrieve the list of plugins from the server. It *
 * returns the number of retrieved plugins for success, 0 for failure.       *
 * ------------------------------------------------------------------------- */

int nessus_getplugs(){

  char * buf = NULL;
  size_t len;
  int i;

  buf = (char *) malloc(MAXDATASIZE);

  /* cycle through the big chunk of preferences data we */
  /* are receiving.                                     */
 
  while(1) {
    len=SSL_read(ssl, buf, MAXDATASIZE);

    /* check if the end marker hits */
    if(strstr(buf, SERVER_END_MARKER)) { 
      if(DEBUG) printf("Receive Data: %s\n", buf);
      break;
    }

    plugs_counter++;

    if(DEBUG == 2) {
      printf("Len %4.0d Counter %4.0d Plugin ID: ", len, plugs_counter);
      for(i=0;i<5;i++) putchar(buf[i]);
      putchar('\n');
    }

    if(DEBUG == 3 ) 
      printf("Len %4.0d Counter %4.0d Plugin ID: %s\n",
                                              len, plugs_counter, buf);

    /* clear the buffer */
    memset(buf, '\0', MAXDATASIZE);
  }

  free(buf);
  return plugs_counter;
}

/* ------------------------------------------------------------------------- *
 * nessus_getprefs retrieves the list of preferences from the server. It     *
 * returns the number of retrieved preferences for success, 0 for failure.   *
 * ------------------------------------------------------------------------- */

int nessus_getprefs() {

  char * buf = NULL;
  size_t len;
  int i;

  buf = (char *) malloc(MAXDATASIZE);

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
 * nessus_getrules retrieves the list of rules from the server. It           *
 * returns the number of retrieved rules for success, 0 for failure.         *
 * ------------------------------------------------------------------------- */

int nessus_getrules(){

  char * buf = NULL;
  size_t len;

  buf = (char *) malloc(MAXDATASIZE);

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

  int nessusfd;
  int ret;

  nessusfd = nessus_connect(DEST_IP, DEST_PORT);

  ret = nessus_login(USERNAME, PASSWORD);

  if(ret == 0) {
    printf("login of %s with %s failed.\n", USERNAME, CLIENT_CERT);
    close(nessusfd);
    exit(1);
  }

  printf("sucessful login\n");

  plugs_counter = nessus_getplugs();

  if(plugs_counter) printf("Found %d Plugins of 5440.\n", plugs_counter);
  else printf("\nFailed to receive any plugins.\n");

  prefs_counter = nessus_getprefs();

  if(prefs_counter) printf("Found %d Prefs of 165.\n", prefs_counter);
  else printf("\nFailed to receive any preferences.\n");

  rules_counter = nessus_getrules();

  if(rules_counter >= 0) printf("Found %d Rules of 0.\n", rules_counter);
  else printf("\nFailed to receive any Rules.\n");
 
  printf("Closing connection to %s.\n", DEST_IP);
  close(nessusfd);
  exit(0);
}

/* ------------------------------------------------------------------------ *
 *                        SERVER SIDE CONFIGURATION                         * 
 * ------------------------------------------------------------------------ *
 * root@toshi:/home/nessus/sbin # ./nessus-adduser                          * 
 * Using /var/tmp as a temporary file holder                                * 
 *                                                                          * 
 * Add a new nessusd user                                                   * 
 * ----------------------                                                   * 
 *                                                                          * 
 *                                                                          * 
 * Login : fm3                                                              * 
 * Authentication (pass/cert) [pass] : cert                                 * 
 * Please enter User Distinguished Name:                                    * 
 * Country: US                                                              * 
 * STate: CA                                                                * 
 * Location: Rocklin                                                        * 
 * Organization: Frank4DD                                                   * 
 * Organizational Unit: nessus-client                                       * 
 * Common Name: fm3                                                         * 
 * e-Mail: fm3@192.168.11.8                                                 * 
 *                                                                          * 
 * User rules                                                               * 
 * ----------                                                               * 
 * nessusd has a rules system which allows you to restrict the hosts        * 
 * that fm3 has the right to test. For instance, you may want               * 
 * him to be able to scan his own host only.                                * 
 *                                                                          * 
 * Please see the nessus-adduser(8) man page for the rules syntax           * 
 *                                                                          * 
 * Enter the rules for this user, and hit ctrl-D once you are done :        * 
 * (the user can have an empty rules set)                                   * 
 *                                                                          * 
 *                                                                          * 
 * Login             : fm3                                                  * 
 * ***********                                                              *
 * DN                : /C=US/ST=CA/L=Rocklin/O=Frank4DD/OU=nessus-client    *
 *                     /CN=fm3/Email=fm3@192.168.11.8                       *
 * Rules             :                                                      * 
 *                                                                          * 
 *                                                                          * 
 * Is that ok ? (y/n) [y]                                                   * 
 * user added.                                                              * 
 * ------------------------------------------------------------------------ */ 


/* ------------------------------------------------------------------------ *
 *                        CLIENT SIDE CONFIGURATION                         * 
 * ------------------------------------------------------------------------ *
 *                                                                          * 
 * fm@toshi:~/nessus-client/etc> /usr/share/ssl/misc/CA.pl -newcert         *
 * Generating a 1024 bit RSA private key                                    *
 * .........++++++                                                          *
 * ........................................................++++++           *
 * writing new private key to 'newreq.pem'                                  *
 * Enter PEM pass phrase:                                                   *
 * Verifying - Enter PEM pass phrase:                                       *
 * phrase is too short, needs to be at least 4 chars                        *
 * Enter PEM pass phrase:                                                   *
 * Verifying - Enter PEM pass phrase:                                       *
 * phrase is too short, needs to be at least 4 chars                        *
 * fm@toshi:~/nessus-client/etc> /usr/share/ssl/misc/CA.pl -newcert         *
 * Generating a 1024 bit RSA private key                                    *
 * ........++++++                                                           *
 * ....++++++                                                               *
 * writing new private key to 'newreq.pem'                                  *
 * Enter PEM pass phrase:                                                   *
 * Verifying - Enter PEM pass phrase:                                       *
 * -----                                                                    *
 * You are about to be asked to enter information that will be incorporated *
 * into your certificate request.                                           *
 * What you are about to enter is what is called a Distinguished Name or a  *
 * DN. There are quite a few fields but you can leave some blank            *
 * For some fields there will be a default value,                           *
 * If you enter '.', the field will be left blank.                          *
 * -----                                                                    *
 * Country Name (2 letter code) [US]:                                       *
 * State or Province Name (full name) [CA]:                                 *
 * Locality Name (eg, city) [Rocklin]:                                      *
 * Organization Name (eg, company) [Frank4DDs web CA]:Frank4DD              *
 * Organizational Unit Name (eg, section) []:nessus-client                  *
 * Common Name (eg, YOUR name) []:fm3                                       *
 * Email Address []:fm3@192.168.11.8                                        *
 * Certificate (and private key) is in newreq.pem                           *
 *                                                                          *
 * fm@toshi:~/nessus-client/etc> more newreq.pem                            *
 * -----BEGIN RSA PRIVATE KEY-----                                          *
 * Proc-Type: 4,ENCRYPTED                                                   *
 * DEK-Info: DES-EDE3-CBC,93B8135E246D1866                                  *
 *                                                                          *
 * DjENsb8S/sVV8Jr7W3u9EZTyIA8tPqq5zi0CYIhLmU1rE4A2yTvo+zlTe8m0TNbS         *
 * x9KlZMtE7GeGSrTPsiHh9BwvSRMUxl9fdOl+HqlFmISFQPenz3nIaotPpcJ+WaME         *
 * BozAz14MD6gwSiuRd0sTtyFBiwYAC6E1SGs7ab0OGMWvGbX9tnTN4P5UhZRX2kPy         *
 * 7iKjUMNXPbqJ3tTYmLZ9/adIWtleALyl+DgGtRAbkq4UNZctWwLyjgaB2WYVVIfs         *
 * PG1CacAlWa76bmkfT/NyUBmgzrgu4ceclV2A9J2+jYagQRhuQInpaUMho11uFiN6         *
 * GkdTouYTUIhpIZ5T6wqlb51bEyBYzwpcnowqVgqQgn48WD5gDvPW+W7HRFE5fC3a         *
 * RJhP85B4V/2xDjNsgNLYoJL4UquZ1StdTDTgy1uZ2W+/XlrGPcbJGFo7a6fMZx/K         *
 * b259bQQROJIieBH4UzbtZy+9tS1BRaCXERvK3y5imkKyuUO0CkA4N1FTJ6c+ZiJo         *
 * jCe+SqgdrOYzXR7FjrWHqagt/dvEMy0IlK3aZ7Wyra/JGIJ0MyOp4tx3qNpOlO4c         *
 * V/bqO+VYwrk4xNOU462mC4xnxLIo1i9Jdk07yAEPR9zxmx9UnHQKr3+2pjmCU5GI         *
 * N7hB/Mx+/iPkWvhPZMpMR0o30txCJqG2HwCVzcA+8TqD+3+1zEdyVrK/+gr2M56D         *
 * oKmLdBYAJ8Voz3/uk0LPufNrITWPUw8Q7vXKESConzZBz+SFHpiOV+NPQ9q3C44q         *
 * o48s4OtpUksBlRRmtCJlYJBAHIkhH5oXKRt4mLDzC9+NmdW3Jr4gng==                 *
 * -----END RSA PRIVATE KEY-----                                            *
 * -----BEGIN CERTIFICATE-----                                              *
 * MIIDazCCAtSgAwIBAgIBADANBgkqhkiG9w0BAQQFADCBhjELMAkGA1UEBhMCVVMx         *
 * CzAJBgNVBAgTAkNBMRAwDgYDVQQHEwdSb2NrbGluMREwDwYDVQQKEwhGcmFuazRE         *
 * RDEWMBQGA1UECxMNbmVzc3VzLWNsaWVudDEMMAoGA1UEAxMDZm0zMR8wHQYJKoZI         *
 * hvcNAQkBFhBmbTNAMTkyLjE2OC4xMS44MB4XDTA0MTIwODIxMTAwNloXDTA1MTIw         *
 * ODIxMTAwNlowgYYxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEQMA4GA1UEBxMH         *
 * Um9ja2xpbjERMA8GA1UEChMIRnJhbms0REQxFjAUBgNVBAsTDW5lc3N1cy1jbGll         *
 * bnQxDDAKBgNVBAMTA2ZtMzEfMB0GCSqGSIb3DQEJARYQZm0zQDE5Mi4xNjguMTEu         *
 * ODCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA+IMvRSxnzDKDYMj61noz/Gs/         *
 * h6NBlGrW5hlI/eZ6KTgo98jaea9gdcEk9KjxG376Cgj7HAYw+oCD8jVDtQH02pPW         *
 * hATTo1CY+UrZWLyIxmKDWxvIZozERSNqZRXvs0yUDgQY5YrTWB3D59vWBHZHybww         *
 * jABU0dIXBbviLFaMO+UCAwEAAaOB5jCB4zAdBgNVHQ4EFgQUGSlpcVndw4VHCXFs         *
 * Q9uJuPLAtoQwgbMGA1UdIwSBqzCBqIAUGSlpcVndw4VHCXFsQ9uJuPLAtoShgYyk         *
 * gYkwgYYxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEQMA4GA1UEBxMHUm9ja2xp         *
 * bjERMA8GA1UEChMIRnJhbms0REQxFjAUBgNVBAsTDW5lc3N1cy1jbGllbnQxDDAK         *
 * BgNVBAMTA2ZtMzEfMB0GCSqGSIb3DQEJARYQZm0zQDE5Mi4xNjguMTEuOIIBADAM         *
 * BgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBAUAA4GBAIz78QBKnvQjdRxw00uEw3k/         *
 * SwOXPZamaIH3wBKydOG+aKJPH6c7yn9jlxV7Gapl/nOw2xBAYhHqh/OfeVSCnOSZ         *
 * P3ugEPXOEMD8hOb62B20Z4yBqz8pOvM5cGU9FHgE8KtoCGN1tvcFK2UJRCp6FmDb         *
 * oEle7iVqwnpplNO4XJ6w                                                     *
 * -----END CERTIFICATE-----                                                *
 *                                                                          *
 * fm@toshi:~/nessus-client/etc> cp newreq.pem privkey-w-pass.pem           *
 * fm@toshi:~/nessus-client/etc> mv newreq.pem cert.pem                     *
 * fm@toshi:~/nessus-client/etc> vi privkey-w-pass.pem (del certlines)      *
 * fm@toshi:~/nessus-client/etc> vi cert.pem (del prikey lines)             *
 *                                                                          *
 * REMOVE PASSPHRASE FROM PRIVATE KEY:                                      *
 *                                                                          *
 * fm@toshi:~/nessus-client/etc> openssl rsa -in privkey-w-pass.pem         *
 *                                           -out privkey.pem               *
 * Enter pass phrase for privkey-w-pass.pem:                                *
 * writing RSA key                                                          *
 *                                                                          *
 * fm@toshi:~/nessus-client/etc> cat privkey.pem                            *
 * -----BEGIN RSA PRIVATE KEY----                                           *
 * MIICXgIBAAKBgQD4gy9FLGfMMoNgyPrWejP8az+Ho0GUatbmGUj95nopOCj3yNp5         *
 * r2B1wST0qPEbfvoKCPscBjD6gIPyNUO1AfTak9aEBNOjUJj5StlYvIjGYoNbG8hm         *
 * jMRFI2plFe+zTJQOBBjlitNYHcPn29YEdkfJvDCMAFTR0hcFu+IsVow75QIDAQAB         *
 * AoGBAO0srmmTVsDwmKg/R/54BLNsW+aEresLCGv0R9BiLca3HYpWPASUlzfrDO0f         *
 * a3T1e4cmSRnW4tnA26zGnwbahiZQKja+kc3O6gScmQg8fqQ5iMf3n8VxEj88Jmxx         *
 * z9bIGA97Q9XGiGwryu9S18Hs6r9U1HRA/srfgKoNBcgyBIuhAkEA/fHKIMIxLYps         *
 * LEkIs2LgqLVWSQQKZhJniDi4HWswcfC2SsmN9zKfJaN9YZyfrcC1BlMhJWqPszgI         *
 * fu0uyGEaiQJBAPqGI5qQsXjTIdQ//3bjUaa+drP/XP60QTGOn51Wo6vfe1GU6uIu         *
 * thhalpE67OYbybvg18QVpdwb9IJaaYPiT30CQQDUvVWfAfBe/YLHyttuJJye2WOS         *
 * wb7QagSv+wxLIPwxx/1/Q8EZ4R+wUXl9Z8/hqPo+dS/kf5QpCP0dEChMGAU5AkAi         *
 * TO1hA0CZR2cRVXXXxEXwq5E7EdKcuPdYHqvx8ePU63NJ9za1oymhaf3Fgqje1J0p         *
 * UR6ZpVEhMt6mXlSmDv1NAkEA4y8S43broyerQV3zBAp8MLLtK3vXSR+yWJMkYP9F         *
 * vy7v8eULvHd+v3TZbBpQVt6WHMEoqutqx+7Nh0nCcVJ44A==                         *
 * -----END RSA PRIVATE KEY-----                                            *
 *                                                                          *
 * ------------------------------------------------------------------------ */
