/* ------------------------------------------------------------------------ *
 *                                                                          *
 * ntp-demo-process-prefs.c  with client certificate authentication         *
 *                                                                          *
 * This program demonstrates the communication with a Nessus daemon.        *
 * It uses SSL for encryption (relies on OpenSSL libraries to provide       *
 * the required en/decryption functions).                                   *
 *                                                                          *
 * It loads the preferences in the according array of structs:              *
 * pluginlist, prefslist, ruleslist                                         *
 *                                                                          *
 * ssl_version=SSLv3 must be set in nessusd.conf.                           *
 *                                                                          *
 * The Following settings according to NTP 1.2 are retrieved:               *
 * SERVER <|> PLUGIN_LIST <|> [data] <|> SERVER                             *
 * SERVER <|> PREFERENCES <|> [data] <|> SERVER                             *
 * SERVER <|> RULES <|> [data] <|> SERVER                                   *
 *                                                                          *
 * this program has been written and tested with nessusd version 2.2.0      *
 * 20041209 frank4dd                                                        *
 *                                                                          *
 * compile instructions:                                                    *
 * gcc -lssl -lcrypt ntp-demo-process-prefs.c -o ntp-demo-process-prefs     *
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
/* DEBUG = 2: showsin addition received data and counters */
#define DEBUG 1

#define CIPHER_LIST "EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC3-SHA:DES-CBC3-MD5:DHE-DSS-RC4-SHA:IDEA-CBC-SHA:RC4-SHA:RC4-MD5:IDEA-CBC-MD5:RC2-CBC-MD5:RC4-MD5"

#define DEST_IP "127.0.0.1"
#define DEST_PORT 1241
/* MAXDATASIZE should be large enough to handle a huge plugin *
 * description so we get a newline. If it is to small, we get *
 * chunks with no newline counted and its just a mess.        */
#define MAXDATASIZE 16384

/* MAXPLUGS  should be large enough to handle all plugins   *
 * we could get from the nessus daemon. If it is to small,  *
 * not all plugins can be processed. the current number is  *
 * around 5.5k. Same goes for MAXPREFS and MAXRULES,        *
 * although their numbers are much smaller (165, 0).        */
#define MAXPLUGS 10000
#define MAXPREFS 512
#define MAXRULES 512

#define USERPROMPT "User : "
#define PASSPROMPT "Password : "
#define USERNAME "fm4"
/* Although we authenticate with a client certificate, the NTP protocol  *
 * still requires a password string, but its a dummy string of any value */
#define PASSWORD "*****"
#define CA_DIR "NULL"
#define CA_FILE "../../etc/cacert.pem"
#define CLIENT_CERT "../../etc/cert_fm4.pem"
#define CLIENT_PRIVKEY "../../etc/key_fm4.pem"
#define CLIENT_NTP_VERSION "< NTP/1.2 >"
#define SERVER_NTP_VERSION "< NTP/1.2 >"
#define PLUGS_START "SERVER <|> PLUGIN_LIST <|>"
#define PREFS_START "SERVER <|> PREFERENCES <|>"
#define RULES_START "SERVER <|> RULES <|>"
#define SERVER_END_MARKER "<|> SERVER"
#define PREF_SEP_MARKER " <|> "

char server_ntp_version[255];

int  plugs_counter = 0;
int  prefs_counter = 0;
int  rules_counter = 0;
SSL           *ssl;

typedef struct plugs Plugs;
typedef struct prefs Prefs;
typedef struct rules Rules;

struct plugs {
                char id[6];
                char name[255];
		char category[255];
		char author[255];
		char descr[8192];
		char summary[255];
		char family[255];
              };

struct prefs {
                char name[128];
		char value[1024];
              };

struct rules {
		char command[128];
		char network[128];
              };

/* Here is our array-of-structs */
struct plugs plugslist[MAXPLUGS];
struct prefs prefslist[MAXPREFS];
struct rules ruleslist[MAXRULES];

/* Here is our array-of-pointers to the structs */
struct plugs *plugslist_ptr[MAXPLUGS];
struct prefs *prefslist_ptr[MAXPREFS];
struct rules *ruleslist_ptr[MAXRULES];


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
  char * buf_ptr = NULL;
  char * tmp_loc = NULL;
  size_t len, diff = 0;

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

    /* cut the plugin in 'buf' into its parts and assign it to a member of  *
     * the 'plugslist' struct array. Parts are separated by string pattern  *   
     * " <|> ", the ";" that needs to be changed into newlines is ignored.  */

    //if(DEBUG == 2 ) printf("%s\n", buf);
    {
      buf_ptr = buf;

      /* collect the plugin_id section */
      tmp_loc = strstr(buf_ptr, PREF_SEP_MARKER) + sizeof(PREF_SEP_MARKER);
      diff = tmp_loc - buf_ptr;
      strncpy(plugslist[plugs_counter].id, buf_ptr,
                  diff - sizeof(PREF_SEP_MARKER));

      /* collect the name section */
      buf_ptr = tmp_loc - 1;
      tmp_loc = strstr(buf_ptr, PREF_SEP_MARKER) + sizeof(PREF_SEP_MARKER);
      diff = tmp_loc - buf_ptr;
      strncpy(plugslist[plugs_counter].name, buf_ptr,
                    diff - sizeof(PREF_SEP_MARKER));

      /* collect the category section */
      buf_ptr = tmp_loc - 1;
      tmp_loc = strstr(buf_ptr, PREF_SEP_MARKER) + sizeof(PREF_SEP_MARKER);
      diff = tmp_loc - buf_ptr;
      strncpy(plugslist[plugs_counter].category, buf_ptr,
                    diff - sizeof(PREF_SEP_MARKER));

      /* collect the author/copyright section */
      buf_ptr = tmp_loc - 1;
      tmp_loc = strstr(buf_ptr, PREF_SEP_MARKER) + sizeof(PREF_SEP_MARKER);
      diff = tmp_loc - buf_ptr;
      strncpy(plugslist[plugs_counter].author, buf_ptr,
                    diff - sizeof(PREF_SEP_MARKER));

      /* collect the descriptive section */
      buf_ptr = tmp_loc - 1;
      tmp_loc = strstr(buf_ptr, PREF_SEP_MARKER) + sizeof(PREF_SEP_MARKER);
      diff = tmp_loc - buf_ptr;
      strncpy(plugslist[plugs_counter].descr, buf_ptr,
                    diff - sizeof(PREF_SEP_MARKER));

      /* collect the summary section */
      buf_ptr = tmp_loc - 1;
      tmp_loc = strstr(buf_ptr, PREF_SEP_MARKER) + sizeof(PREF_SEP_MARKER);
      diff = tmp_loc - buf_ptr;
      strncpy(plugslist[plugs_counter].summary, buf_ptr,
                    diff - sizeof(PREF_SEP_MARKER));

      /* collect the family section */
      buf_ptr = tmp_loc - 1;
      diff = (strchr(buf_ptr, '\n') - buf_ptr);
      strncpy(plugslist[plugs_counter].family, buf_ptr, diff);

      /* the last and very important step: save the struct pointer */
      plugslist_ptr[plugs_counter] = &plugslist[plugs_counter];

      if(DEBUG == 2) {
        printf("Len %4.0d Count %4.0d ", len, plugs_counter+1);
        printf("ID: %s ", plugslist[plugs_counter].id);
        printf("Name: %s\n", plugslist[plugs_counter].family);
      }
    }

    plugs_counter++;

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
  char * buf_ptr = NULL;
  char * tmp_loc = NULL;
  size_t len, diff = 0;

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

    /* cut the preferences from 'buf' into their parts and assign them    *
     * to be members of the 'prefslist' struct array. Parts are separated *
     * string patterns " <|> ". We ignore other format markers here.      */
    {
      buf_ptr = buf;

      /* collect the pref name section */
      tmp_loc = strstr(buf_ptr, PREF_SEP_MARKER) + sizeof(PREF_SEP_MARKER);
      diff = tmp_loc - buf_ptr;
      strncpy(prefslist[prefs_counter].name, buf_ptr,
                  diff - sizeof(PREF_SEP_MARKER));

      /* collect the pref value section */
      buf_ptr = tmp_loc - 1;
      diff = (strchr(buf_ptr, '\n') - buf_ptr);
      strncpy(prefslist[prefs_counter].value, buf_ptr, diff);

      /* the last and very important step: save the struct pointer */
      prefslist_ptr[prefs_counter] = &prefslist[prefs_counter];

      if(DEBUG == 2) {
        printf("Len %3.0d Count %3.0d ", len, prefs_counter+1);
        printf("Name %s\n", prefslist[prefs_counter].name);
      }
    }

    prefs_counter++;

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

  printf("Example Plugin: Number 23:\n");
  printf("==========================\n");
  printf("ID: [%s] CATEGORY: [%s] FAMILY: [%s]\n", plugslist_ptr[23]->id,
          plugslist_ptr[23]->category, plugslist_ptr[23]->family);

  printf("Example Plugin Number 2455:\n");
  printf("===========================\n");
  printf("ID: [%s] CATEGORY: [%s] FAMILY: [%s]\n", plugslist_ptr[2455]->id,
          plugslist_ptr[2455]->category, plugslist_ptr[2455]->family);

  printf("Example Preference: Number 46:\n");
  printf("==========================\n");
  printf("NAME: [%s]\n : VALUE [%s]\n", prefslist_ptr[46]->name,
          prefslist_ptr[46]->value);

  printf("Example Preference: Number 131:\n");
  printf("==========================\n");
  printf("NAME: [%s]\n : VALUE [%s]\n", prefslist_ptr[131]->name,
          prefslist_ptr[131]->value);

  printf("Closing connection to %s.\n", DEST_IP);
  close(nessusfd);
  exit(0);
}
