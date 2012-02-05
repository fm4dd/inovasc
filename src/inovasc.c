/* ------------------------------------------------------------------------ *
 *                                                                          *
 * inovasc.c  provides functions and routines for various cgi's             *
 *                                                                          *
 * Here I keep functions providing communication with a scanner daemon.     *
 * TLSv1 or SSL is used for session encryption, therefore we rely on        *
 * OpenSSL libraries to provide the required en&decryption functions.       *
 * For more info see also the demo programs in the demo-src directory.      *
 *                                                                          *
 * Server data (plugins, rules, etc) is loaded in the according array       *
 * of structs: pluginlist, prefslist, ruleslist, prefdepslist               *
 * ------------------------------------------------------------------------ */

/* needed for strptime() function in inovasc.c, used in scanresults.c */
#define _XOPEN_SOURCE
#define __USE_XOPEN
#define __USE_GNU
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <cgic.h>
#include "inovasc.h"

const char newline[2]        = {'\n', '\0'};
const char semicolon[2]      = {';', '\0'};
const char whitespace[2]     = {';', '\0'};
      char session_id[24];
      char error_string[255] = "";
      char *server_otp_version;
      SSL  *ssl;

/* ------------------------------------------------------------------------- *
 * scanner_connect creates a new session to the scan server and returns      *
 * the file descriptor to it.                                                *
 * ------------------------------------------------------------------------- */
SSL * scanner_connect(char *ip, int port, char *encr, char *cert) {
  int sockfd;
  int retcode;
  int cert_auth = 0;
  struct sockaddr_in dest_addr;
  static SSL_CTX        *ssl_ctx = NULL;
  char 			cacertfile[255] = "";
  char 			clientcertfile[255] = "";

  /* if we get cert=none, we use password authentication */
  if (strcmp(cert, "none")) cert_auth = 1;

  /* create the basic TCP socket */
  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(port);
  dest_addr.sin_addr.s_addr=inet_addr(ip);

  /* Zeroing the rest of the struct */
  memset(&(dest_addr.sin_zero), '\0', 8);

  if ( connect(sockfd, (struct sockaddr *) &dest_addr,
                              sizeof(struct sockaddr)) == -1 ) {
    snprintf(error_string, sizeof(error_string),
             "Cannot connect to the scanner server %s on port %d.", ip, port);
    int_error(error_string);
  }

  /* start the SSL initialization */
  ssl = NULL;

  /* initialize SSL library and register algorithms */
  if(SSL_library_init() < 0)
    int_error("Could not initialize the OpenSSL library !");

  /* load  the SSL error messages */
  SSL_load_error_strings();

  /* create a new SSL_CTX object as framework for TLS/SSL enabled functions *
   * use the selected encryption type: TLS1, SSLv2, SSLv3 or auto           *
   * this corresponds to the 'ssl_version' setting in openvassd.conf        */

   if ( strcmp(encr, "TLSv1") == 0 )
      ssl_ctx = SSL_CTX_new(TLSv1_client_method());

   else if ( strcmp(encr, "SSLv2") == 0 )
      ssl_ctx = SSL_CTX_new(SSLv2_client_method());

   else if ( strcmp(encr, "SSLv3") == 0 ) {
      ssl_ctx = SSL_CTX_new(SSLv3_client_method());
      SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL); }

   else if ( strcmp(encr, "Auto") == 0 )
      ssl_ctx = SSL_CTX_new(SSLv23_client_method());

   else {
      snprintf(error_string, sizeof(error_string), "Unknown SSL encryption method %s.\n", encr);
      int_error(error_string);
   }  

   if ( ssl_ctx == NULL ) {
      snprintf(error_string, sizeof(error_string), "Cannot create SSL context for encryption method %s.\n", encr);
      int_error(error_string);
   }  

  /* choose list of available SSL_CIPHERs with a control string */
  if(! SSL_CTX_set_cipher_list(ssl_ctx, CIPHER_LIST))
    int_error("SSL_CTX_set_cipher_listError - cannot set SSL cipher list.");

  /* --- start SSL routines for client cert authentication ----- */
  if (cert_auth) {
    /* verify the CA file and path */
    snprintf(cacertfile, sizeof(cacertfile),
             "%s/%s", CA_CERT_DIR, CA_CERT);
    if(SSL_CTX_load_verify_locations(ssl_ctx, cacertfile, NULL) != 1) {
      snprintf(error_string, sizeof(error_string),
               "Cannot load the CA certificate: %s.", CA_CERT);
      int_error(error_string);
    }

    /* load the client certificate we present to the nessus server */
    snprintf(clientcertfile, sizeof(clientcertfile),
             "%s/%s", CLIENT_CERT_DIR, cert);
    if(SSL_CTX_use_certificate_chain_file(ssl_ctx, clientcertfile) != 1) {
      snprintf(error_string, sizeof(error_string),
               "Cannot load the client certificate: %s.\n%s",
                cert, strerror(errno));
      int_error(error_string);
    }

    /* load the client certificate private key */
    if(SSL_CTX_use_PrivateKey_file(ssl_ctx, CLIENT_PRIVKEY,
                                            SSL_FILETYPE_PEM) != 1) {
      snprintf(error_string, sizeof(error_string),
               "Cannot load the client certificate's private key: %s.", CLIENT_PRIVKEY);
      int_error(error_string);
    }

    /* Here we set the verification mode to SSL_VERIFY_PEER */
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ssl_ctx, 4);

  /* --- end SSL routines for client cert authentication ----- */
  }

  /* create a new SSL structure for a connection */
  if((ssl = SSL_new(ssl_ctx)) == NULL)
     int_error("Cannot creat a new SSL structure with SSL_new().");

  /* connect the SSL object with the socket file descriptor */
  if(! SSL_set_fd(ssl, sockfd))
     int_error("Cannot connect to socket with SSL_set_fd().");

  /* initiate the TLS/SSL handshake with an TLS/SSL server */
  if( (retcode = SSL_connect(ssl)) <= 0) {
    snprintf(error_string, sizeof(error_string),
    "Problem with SSL_connect() during SSL handshake.\n%d %s", retcode, strerror(SSL_get_error(ssl, retcode)));
    int_error(error_string);
  }

  return ssl;
}

/* ------------------------------------------------------------------------- *
 * scanner_login tries to log in with the username and password provided.    *
 * ------------------------------------------------------------------------- */

int scanner_login(SSL *ssl, char *user, char *pass) {

  char * buf = NULL;
  int retcode = 0;

  buf = (char *) malloc(MAXDATASIZE);

  /* send the client protocol version, followed by a newline */
  memset(buf, '\0', MAXDATASIZE);
  snprintf(buf, strlen(CLIENT_OTP_VERSION)+2, "%s\n", CLIENT_OTP_VERSION);
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif
  retcode = SSL_write(ssl, buf, strlen(buf));

  /* receive the server protocol version, followed by a newline */
  memset(buf, '\0', MAXDATASIZE);
  retcode=SSL_read(ssl, buf, strlen(SERVER_OTP_VERSION)+1);
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif

  /* set global variable server protocol version, remove the newline */
  server_otp_version = (char *) malloc(strlen(buf));
  memset(server_otp_version, '\0', strlen(buf));
  strncpy(server_otp_version, buf, strlen(buf)-1);

  /* receive the username prompt */
  memset(buf, '\0', MAXDATASIZE);
  retcode=SSL_read(ssl, buf, MAXDATASIZE);
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif

  /* send the username followed by a newline */
  memset(buf, '\0', MAXDATASIZE);
  snprintf(buf, strlen(user)+2, "%s\n", user);
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif
  retcode = SSL_write(ssl, buf, strlen(buf));

  /* receive the password prompt */
  memset(buf, '\0', MAXDATASIZE);
  retcode=SSL_read(ssl, buf, MAXDATASIZE);
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif

  /* send the password, followed by a newline */
  memset(buf, '\0', MAXDATASIZE);
  snprintf(buf, strlen(pass)+2, "%s\n", pass);
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif
  retcode = SSL_write(ssl, buf, strlen(buf));

  /* Now we take the data out */
  memset(buf, '\0', MAXDATASIZE);
  retcode=SSL_read(ssl, buf, MAXDATASIZE);
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif

  /* Check if we got the "Bad Login" info or the Plugin MD5 hash marker */
  if(strstr(buf, PLIST_HASH)) { free(buf); return 1; }
  else int_error("Scan Server responds with 'Bad Login'. Wrong scan server username or password?");

  free(buf);
  return 0;
}

/* ------------------------------------------------------------------------- *
 * scanner_getplugs tries to retrieve the list of plugins from the server.   *
 * It returns the number of retrieved plugins for success, 0 for failure.    *
 * ------------------------------------------------------------------------- */

int scanner_getplugs(SSL *ssl){

  char * buf = NULL;
  char * buf_ptr = NULL;
  char * tmp_loc = NULL;
  size_t len = 0, diff = 0;
  int retcode = 0, counter = 0;

  buf = (char *) malloc(MAXDATASIZE);

  /* send the plugin request followed by a newline */
  memset(buf, '\0', MAXDATASIZE);
  snprintf(buf, strlen(PLIST_GET)+2, "%s\n", PLIST_GET);
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif
  retcode = SSL_write(ssl, buf, strlen(buf));

  /* Now we should receive the list start marker */
  memset(buf, '\0', MAXDATASIZE);
  retcode=SSL_read(ssl, buf, MAXDATASIZE);
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif

  /* Check if we got the Plugin List start marker */
  if(! strstr(buf, PLIST_START)) int_error("Can't get the list of plugins from server.");

  /* Now we cycle through the big chunk of plugins */
  /* sent to us by the server.                     */
  while(1) {
    memset(buf, '\0', MAXDATASIZE);
    len=SSL_read(ssl, buf, MAXDATASIZE);

    /* check if the end marker hits */
    if(strstr(buf, SERVER_END)) break;

    /* check if the space for plugins is exhausted */
    if(counter >= MAXPLUGS) {
      snprintf(error_string, sizeof(error_string),
               "Maximum number of plugins exhausted (%d).",
                MAXPLUGS);
      int_error(error_string);
      break;
    }

    /* cut the plugin in 'buf' into its parts and assign it to a member of  *
     * the 'plugslist' struct array. Parts are separated by string pattern  *   
     * " <|> ", the ";" that needs to be changed into newlines is ignored.  */

    {

      /* collect the plugin_id section */
      buf_ptr = buf;
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      diff = tmp_loc - buf_ptr;
      strncpy(plugslist[counter].id, buf_ptr, diff);
      plugslist[counter].id[diff]= '\0';

      /* collect the name section */
      buf_ptr = tmp_loc + sizeof(SEPARATOR) - 1;
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      diff = tmp_loc - buf_ptr;
      strncpy(plugslist[counter].name, buf_ptr, diff+1);
      plugslist[counter].name[diff]= '\0';

      /* collect the category section */
      buf_ptr = tmp_loc + sizeof(SEPARATOR) - 1;
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      diff = tmp_loc - buf_ptr;
      strncpy(plugslist[counter].category, buf_ptr, diff+1);
      plugslist[counter].category[diff]= '\0';

      /* collect the author/copyright section */
      buf_ptr = tmp_loc + sizeof(SEPARATOR) - 1;
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      diff = tmp_loc - buf_ptr;
      strncpy(plugslist[counter].author, buf_ptr, diff+1);
      plugslist[counter].author[diff]= '\0';

      /* collect the descriptive section */
      buf_ptr = tmp_loc + sizeof(SEPARATOR) - 1;
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      diff = tmp_loc - buf_ptr;
      strncpy(plugslist[counter].descr, buf_ptr, diff+1);
      plugslist[counter].descr[diff]= '\0';

      /* collect the summary section */
      buf_ptr = tmp_loc + sizeof(SEPARATOR) - 1;
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      diff = tmp_loc - buf_ptr;
      strncpy(plugslist[counter].summary, buf_ptr, diff+1);
      plugslist[counter].summary[diff]= '\0';

      /* collect the family section */
      buf_ptr = tmp_loc + sizeof(SEPARATOR) - 1;
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      diff = tmp_loc - buf_ptr;
      strncpy(plugslist[counter].family, buf_ptr, diff+1);
      plugslist[counter].family[diff]= '\0';

      /* collect the revision */
      buf_ptr = tmp_loc + sizeof(SEPARATOR) - 1;
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      diff = tmp_loc - buf_ptr;
      strncpy(plugslist[counter].revision, buf_ptr, diff+1);
      plugslist[counter].revision[diff]= '\0';

      /* collect the cve list */
      buf_ptr = tmp_loc + sizeof(SEPARATOR) - 1;
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      diff = tmp_loc - buf_ptr;
      strncpy(plugslist[counter].cve, buf_ptr, diff+1);
      plugslist[counter].cve[diff]= '\0';

      /* collect the bid */
      buf_ptr = tmp_loc + sizeof(SEPARATOR) - 1;
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      diff = tmp_loc - buf_ptr;
      strncpy(plugslist[counter].bid, buf_ptr, diff+1);
      plugslist[counter].bid[diff]= '\0';

      /* collect the mdvsa section */
      buf_ptr = tmp_loc + sizeof(SEPARATOR) - 1;
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      diff = tmp_loc - buf_ptr;
      strncpy(plugslist[counter].mdvsa, buf_ptr, diff+1);
      plugslist[counter].mdvsa[diff]= '\0';

      /* collect the hash section */
      buf_ptr = tmp_loc + sizeof(SEPARATOR) - 1;
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      diff = tmp_loc - buf_ptr;
      strncpy(plugslist[counter].hash, buf_ptr, diff+1);
      plugslist[counter].hash[diff]= '\0';

      /* collect the info section */
      buf_ptr = tmp_loc + sizeof(SEPARATOR) - 1;
      diff = (strchr(buf_ptr, '\n') - buf_ptr);
      strncpy(plugslist[counter].infos, buf_ptr, diff+1);
      plugslist[counter].infos[diff]= '\0';

      /* the last and very important step: save the struct pointer */
      plugslist_ptr[counter] = &plugslist[counter];
    }

    counter++;
  }
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif

  free(buf);
  return counter;
}

/* ------------------------------------------------------------------------- *
 * scanner_getprefs retrieves the list of preferences from the server. It    *
 * returns the number of retrieved preferences for success, 0 for failure.   *
 * ------------------------------------------------------------------------- */

int scanner_getprefs(SSL *ssl) {

  char * buf = NULL;
  char * buf_ptr = NULL;
  char * tmp_loc = NULL;
  size_t len, diff = 0;
  int	 counter = 0;
  int    retcode = 0;

  buf = (char *) malloc(MAXDATASIZE);

  /* send the preferences request followed by a newline */
  memset(buf, '\0', MAXDATASIZE);
  snprintf(buf, strlen(PREFS_REQ)+2, "%s\n", PREFS_REQ);
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif

  retcode = SSL_write(ssl, buf, strlen(buf));

  /* receive the preferences list start marker */
  memset(buf, '\0', MAXDATASIZE);
  len=SSL_read(ssl, buf, strlen(PREFS_START)+1);
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif

  if(! strstr(buf, PREFS_START)) {
    snprintf(error_string, sizeof(error_string),
      "Expected to receive the preferences start message from the scan server.<p>%s", buf);
    int_error(error_string);
  }

  while(1) {
    memset(buf, '\0', MAXDATASIZE);
    len=SSL_read(ssl, buf, MAXDATASIZE);

    /* check if the end marker hits */
    if(strstr(buf, SERVER_END)) break;

    /* cut the preferences from 'buf' into their parts and assign them    *
     * to be members of the 'prefslist' struct array. Parts are separated *
     * string patterns " <|> ". We ignore other format markers here.      */
    {
      buf_ptr = buf;

      /* collect the pref name section */
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      diff = tmp_loc - buf_ptr;
      strncpy(prefslist[counter].name, buf_ptr, diff+1);
      prefslist[counter].name[diff]= '\0';

      /* collect the pref value section */
      buf_ptr = tmp_loc + sizeof(SEPARATOR) - 1;
      diff = (strchr(buf_ptr, '\n') - buf_ptr);
      strncpy(prefslist[counter].value, buf_ptr, diff+1);
      prefslist[counter].value[diff]= '\0';

      /* the last and very important step: save the struct pointer */
      prefslist_ptr[counter] = &prefslist[counter];
    }
    counter++;
  }
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif
 
  free(buf);
  return counter;
}

/* ------------------------------------------------------------------------- *
 * scanner_getrules retrieves the list of rules from the server. It          *
 * returns the number of retrieved rules for success, 0 for failure.         *
 * ------------------------------------------------------------------------- */

int scanner_getrules(SSL *ssl){

  char  *buf = NULL;
  size_t len;
  int	 counter = 0;

  buf = (char *) malloc(MAXDATASIZE);

  /* Currently, Rules come automatic after Prefs, we dont need to request */
  /* receive the Rules List start marker */
  memset(buf, '\0', MAXDATASIZE);
  len=SSL_read(ssl, buf, strlen(RULES_START)+1);
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif

  if(! strstr(buf, RULES_START)) {
    snprintf(error_string, sizeof(error_string),
      "Expected to receive the rules start message from the scan server.<p>%s", buf);
    int_error(error_string);
  }

  while(1) {
    memset(buf, '\0', MAXDATASIZE);
    len=SSL_read(ssl, buf, MAXDATASIZE);

    /* check if the end marker hits */
    if(strstr(buf, SERVER_END)) break;

    counter++;
  }

#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif

  free(buf);
  return counter;
}

/* ------------------------------------------------------------------------- *
 * scanner_getgroups creates list of categories and families.                *
 * It also sets the counters for both groups.                                *
 * ------------------------------------------------------------------------- */

void scanner_getgroups() {

  int found_catgy;
  int found_famly;
  int i;
  int j;
  int k;
  
  catgy_counter = 0;
  famly_counter = 0;

  /* cycle through all plugins */
  for(i=0; i<plugs_counter; i++) {

    j = 0;
    found_catgy = 0;

    /* cycle through all categories */
    while(j<=catgy_counter) {

      /* check if we already got this category in our list */
      if(strcmp(plugslist_ptr[i]->category, catgylist[j].name) == 0) {

        /* the category exists, add the plugin id to the list ... */
        catgylist[j].plugs_ptr[catgylist[j].plugscount] = plugslist_ptr[i];

        /* ... increase the plugin counter */
        catgylist[j].plugscount++;

        /* ... and set the "category exists" flag */
        found_catgy = 1;
        break;
      }
      j++;
    }
    if(found_catgy == 0) {

      /* the category is a new one, save the category name */
      strcpy(catgylist[catgy_counter].name, plugslist_ptr[i]->category);

      /* .. add the plugin id */
      catgylist[catgy_counter].plugs_ptr[0] = plugslist_ptr[i];

      /* .. set the plugin counter to one for the first plugin found */
      catgylist[catgy_counter].plugscount = 1;

      /* .. set the category "enabled" flag by default to zero */
      catgylist[catgy_counter].enabled = 0;

      /* ... and increase the category counter */
      catgy_counter++;
    }

    k = 0;
    found_famly = 0;

    /* cycle through all families */
    while(k<=famly_counter) {

      if(strcmp(plugslist_ptr[i]->family, famlylist[k].name) == 0) {

        /* the family exists, add the plugin id to the list ... */
        famlylist[k].plugs_ptr[famlylist[k].plugscount] = plugslist_ptr[i];

        /* ... increase the plugin counter */
        famlylist[k].plugscount++;

        /* ... and set the "family exists" flag */
        found_famly = 1;
        break;
      }
      k++;
    }
    if(found_famly == 0) {

      /* the family is a new one, save the family name */
      strcpy(famlylist[famly_counter].name, plugslist_ptr[i]->family);

      /* .. add the plugin id */
      famlylist[famly_counter].plugs_ptr[0] = plugslist_ptr[i];

      /* .. set the plugin counter to one for the first plugin found */
      famlylist[famly_counter].plugscount = 1;

      /* .. set the family "enabled" flag by default to zero */
      famlylist[famly_counter].enabled = 0;

      /* ... and increase the family counter */
      famly_counter++;
    }
  }
}

/* ------------------------------------------------------------------------- *
 * scanner_getpdeps retrieves the list of plugin dependencies. It            *
 * returns the number of retrieved deps for success, 0 for failure.          *
 * Dependencies are always send after the rules message, we don't need       *
 * to initiate the sending with a client command.                            *
 * ------------------------------------------------------------------------- */
int scanner_getpdeps(SSL *ssl){

  char * buf = NULL;
  size_t len;
  int counter = 0;

  buf = (char *) malloc(MAXDATASIZE);

  /* receive the Dependencies List start marker */
  memset(buf, '\0', MAXDATASIZE);
  len=SSL_read(ssl, buf, strlen(PDEPS_START)+1);
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif

  if(! strstr(buf, PDEPS_START)) {
    snprintf(error_string, sizeof(error_string),
      "Expected to receive the dependencies start message from the scan server.<p>%s", buf);
    int_error(error_string);
  }

  while(! strstr(buf, SERVER_END)) {
    /* clear the buffer */
    memset(buf, '\0', MAXDATASIZE);
    len=SSL_read(ssl, buf, MAXDATASIZE);
    counter++;
  }

#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif
  free(buf);
  return counter;
}

/* ------------------------------------------------------------------------- *
 * scanner_setprefs sends the list of preferences to the scanner server.     *
 * ------------------------------------------------------------------------- */

void scanner_setprefs(SSL *ssl, int prefs_counter) {

  char * buf = NULL;
  int retcode = 0;
  int scanplug_counter = 0;
  int i = 0, j = 0;

  buf = (char *) malloc(MAXDATASIZE);

  /* send the client preferences start marker, followed by a newline */
  memset(buf, '\0', MAXDATASIZE);
  snprintf(buf, strlen(PREFS_SET)+2, "%s\n", PREFS_SET);
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif

  retcode = SSL_write(ssl, buf, strlen(buf));

  /* send the whole list of server preferences stored in prefslist */
  for (i=0; i<prefs_counter; i++) {
    memset(buf, '\0', MAXDATASIZE);
    snprintf(buf, MAXDATASIZE, "%s%s%s\n", prefslist_ptr[i]->name,
          SEPARATOR, prefslist_ptr[i]->value);
    retcode = SSL_write(ssl, buf, strlen(buf));
  }

  /* send the client plugin list start marker, followed by a newline */
  memset(buf, '\0', MAXDATASIZE);
  snprintf(buf, strlen(PLUGS_SET)+2, "%s ", PLUGS_SET);
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif
  retcode = SSL_write(ssl, buf, strlen(buf));

  /*  send out these plugin id's where the family name has the 'enabled'  *
   *  flag set in 'familylist', separated by a semicolon.                 */
  for(i=0; i<famly_counter; i++) {

    if(famlylist[i].enabled == 1) {
      for(j=0; j<famlylist[i].plugscount; j++) {

#ifdef PORTSCAN_WORKAROUND
       /* ----------------------------------------------------------- *
        * If the "Port Scanners" family has been enabled, the         *
        * portscan workaround disables "unsafe" and external plugins. *
        * ----------------------------------------------------------- *
        * 1.3.6.1.4.1.25623.1.0.80009 = strobe (NASL wrapper)         *
        * 1.3.6.1.4.1.25623.1.0.80001 = pnscan (NASL wrapper)         *
        * 1.3.6.1.4.1.25623.1.0.10796 = scan for LaBrea tarpitted hosts
        * 1.3.6.1.4.1.25623.1.0.14272 = Netstat 'scanner'   OK        *
        * 1.3.6.1.4.1.25623.1.0.14259 = Nmap (NASL wrapper) OK        *
        * 1.3.6.1.4.1.25623.1.0.80112 = Simple TCP portscan in NASL   *
        * 1.3.6.1.4.1.25623.1.0.80002 = portbunny (NASL wrapper)      *
        * 1.3.6.1.4.1.25623.1.0.80000 <|> ike-scan (NASL wrapper)     *
        * 1.3.6.1.4.1.25623.1.0.14663 <|> amap (NASL wrapper)         *
        * 1.3.6.1.4.1.25623.1.0.11840 = Excl toplevel domain wildcard host
        * ----------------------------------------------------------- */
        if(strcmp(famlylist[i].name, "Port scanners") == 0) {
          if(strcmp(famlylist[i].plugs_ptr[j]->id, "1.3.6.1.4.1.25623.1.0.80009") == 0) continue;
          if(strcmp(famlylist[i].plugs_ptr[j]->id, "1.3.6.1.4.1.25623.1.0.80001") == 0) continue;
          if(strcmp(famlylist[i].plugs_ptr[j]->id, "1.3.6.1.4.1.25623.1.0.10796") == 0) continue;
          if(strcmp(famlylist[i].plugs_ptr[j]->id, "1.3.6.1.4.1.25623.1.0.80112") == 0) continue;
          if(strcmp(famlylist[i].plugs_ptr[j]->id, "1.3.6.1.4.1.25623.1.0.80002") == 0) continue;
          if(strcmp(famlylist[i].plugs_ptr[j]->id, "1.3.6.1.4.1.25623.1.0.80000") == 0) continue;
          if(strcmp(famlylist[i].plugs_ptr[j]->id, "1.3.6.1.4.1.25623.1.0.14663") == 0) continue;
          if(strcmp(famlylist[i].plugs_ptr[j]->id, "1.3.6.1.4.1.25623.1.0.11840") == 0) continue;
        }
#endif
#ifdef EXTERNAL_PLUGINS_WORKAROUND
       /* ----------------------------------------------------------- *
        * The following plugins will be ignored because they need ext *
        * software and they usually take long to complete (10+ mins). *
        * ----------------------------------------------------------- *
        * 1.3.6.1.4.1.25623.1.0.80109 <|> w3af (NASL wrapper)         *
        * 1.3.6.1.4.1.25623.1.0.110001 <|> arachni (NASL wrapper)     *
        * 1.3.6.1.4.1.25623.1.0.103079 <|> DIRB (NASL wrapper)        *
        * 1.3.6.1.4.1.25623.1.0.80110 <|> wapiti (NASL wrapper)       *
        * 1.3.6.1.4.1.25623.1.0.14260 <|> Nikto (NASL wrapper)        *
        * ----------------------------------------------------------- */
        if(strcmp(famlylist[i].name, "Web application abuses") == 0) {
          if(strcmp(famlylist[i].plugs_ptr[j]->id, "1.3.6.1.4.1.25623.1.0.80109") == 0) continue;
          if(strcmp(famlylist[i].plugs_ptr[j]->id, "1.3.6.1.4.1.25623.1.0.110001") == 0) continue;
          if(strcmp(famlylist[i].plugs_ptr[j]->id, "1.3.6.1.4.1.25623.1.0.103079") == 0) continue;
          if(strcmp(famlylist[i].plugs_ptr[j]->id, "1.3.6.1.4.1.25623.1.0.80110") == 0) continue;
          if(strcmp(famlylist[i].plugs_ptr[j]->id, "1.3.6.1.4.1.25623.1.0.14260") == 0) continue;
        }
#endif

        memset(buf, '\0', MAXDATASIZE);

        /* If this is the first ID, we dont need to send the semicolon */
        if (scanplug_counter == 0)
          snprintf(buf, strlen(famlylist[i].plugs_ptr[j]->id)+1, "%s", famlylist[i].plugs_ptr[j]->id);
        else
          snprintf(buf, strlen(famlylist[i].plugs_ptr[j]->id)+2, ";%s", famlylist[i].plugs_ptr[j]->id);

#ifdef DEBUG
        if(debugfile != NULL) fputs(buf, debugfile);
#endif
        retcode = SSL_write(ssl, buf, strlen(buf));
        scanplug_counter++;
      }
    }
  }

  if(scanplug_counter == 0) int_error("Sent no plugin ID's to the server.");

  /* write the closing CLIENT marker */
  memset(buf, '\0', MAXDATASIZE);
  snprintf(buf, strlen(CLIENT_END)+3, "\n%s\n", CLIENT_END);
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif
  retcode = SSL_write(ssl, buf, strlen(buf));
} 

/* ------------------------------------------------------------------------- *
 * scanner_target sends the target ip to the scanner server.                 *
 * ------------------------------------------------------------------------- */

int scanner_target(SSL *ssl, char *target_ip) {

  char * buf = NULL;
  int retcode = 0, len = 0;
  char target_len[255] = "";

  buf = (char *) malloc(MAXDATASIZE);
  snprintf(target_len, sizeof(target_len), "%d", strlen(target_ip));

  memset(buf, '\0', MAXDATASIZE);
  snprintf(buf, strlen(NSCAN_REQ)+2, "%s\n", NSCAN_REQ);
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif
  retcode = SSL_write(ssl, buf, strlen(buf));

  memset(buf, '\0', MAXDATASIZE);
  snprintf(buf, strlen(target_len)+2, "%s\n", target_len);
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif
  retcode = SSL_write(ssl, buf, strlen(buf));

  memset(buf, '\0', MAXDATASIZE);
  snprintf(buf, strlen(target_ip)+2, "%s\n", target_ip);
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif
  retcode = SSL_write(ssl, buf, strlen(buf));

  memset(buf, '\0', MAXDATASIZE);
  snprintf(buf, strlen(CLIENT_END)+2, "%s\n", CLIENT_END);
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif
  retcode = SSL_write(ssl, buf, strlen(buf));

  /* Now we should receive the scan start marker, see an example below:     */
  /* SERVER <|> TIME <|> SCAN_START <|> Sun Jan 22 15:45:21 2012 <|> SERVER */
  memset(buf, '\0', MAXDATASIZE);
  len=SSL_read(ssl, buf, MAXDATASIZE);
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif

  if(! strstr(buf, SCAN_START)) {
    snprintf(error_string, sizeof(error_string),
             "Expected to receive the scan start message from the scan server.<p>%s", buf);
    int_error(error_string);
    return 0;
  }
return 1;
}

/* ------------------------------------------------------------------------- *
 * write_hostupdates creates the update-<session>.htm popup window html doc  *
 * type is either start, attack or finished                                  *
 * ------------------------------------------------------------------------- */

void write_hostupdates(char *session, char *t_ip, char *type, char *progress) {
  FILE *UPDATES;
  char res_path[PATH_MAX] = "";
  char title[72] = "Scan Updates for Session: ";
  int current_plug = 0;
  int maxconf_plug = 0;
  char *slash_ptr;
  div_t calc_percent;
  div_t calc_display;
  int prog_percent = 0;
  int disp_percent = 0;
  int disp_remain  = 20;

/* ---------------------------------------------------------------------------
   if we get type finished, we don't need to calculate the progress percentage,
   and just set it to 100%. We also wan't to stop the page refresh and we even
   could close the window.
   -------------------------------------------------------------------------- */

  if(strcmp(type, "attack") == 0) {
    slash_ptr = index(progress, '/');
    maxconf_plug = atoi(slash_ptr+1);
    *slash_ptr = '\0';
    current_plug = atoi(progress);

    /* calculate plugin progress in percent. maxconf_plug = 100%, current_plug = x */
    calc_percent = div((current_plug * 100), maxconf_plug);
    if(calc_percent.quot > 100) prog_percent = 100;
    else prog_percent = calc_percent.quot;
    calc_display = div((prog_percent * 20), 100);
    disp_percent = calc_display.quot;
    disp_remain = 20 - disp_percent;
  }

  strcat(title, session);
  /* create the file path and try to open it for writing */
  sprintf(res_path, "%s/updates-%s.htm", RESULTS_DIR, session);
  UPDATES = fopen(res_path, "w");
  if(UPDATES == NULL) {
    snprintf(error_string, sizeof(error_string),
             "Could not write the updates file %s/updates-%s.htm.", RESULTS_DIR, session);
    int_error(error_string);
  }

  /* start the html output */
  fprintf(UPDATES, "<html>\n<head>\n");
  fprintf(UPDATES, "<meta http-equiv=\"Cache-Control\" Content=\"no-cache\">\n");
  fprintf(UPDATES, "<meta http-equiv=\"Pragma\" Content=\"no-cache\">\n");
  fprintf(UPDATES, "<meta http-equiv=\"Expires\" Content=\"0\">\n");

  /* refresh window only until finished */
  if(strcmp(type, "finished") != 0)
    fprintf(UPDATES, "<meta http-equiv=\"refresh\" content=\"%d\">\n", UPDWIN_REFRESH);
  fprintf(UPDATES, "<link rel=stylesheet type=text/css href=../style/style.css>\n");
  fprintf(UPDATES, "<title>INOVASC - %s</title>\n</head>\n", title);

  /* done with the header, start the body */
  fprintf(UPDATES, "<div id=\"update\">\n");
  fprintf(UPDATES, "<body>\n");
  fprintf(UPDATES, "<script type=\"text/javascript\">\n");
  fprintf(UPDATES, "<!--\n window.focus();\n //-->\n");
  fprintf(UPDATES, "</script>\n");
  fprintf(UPDATES, "<table>\n");
  fprintf(UPDATES, "<tr>\n");
  fprintf(UPDATES, "<th colspan=21>Scan Progress Details</th>\n");
  fprintf(UPDATES, "</tr>\n");
  fprintf(UPDATES, "<tr>\n");
  fprintf(UPDATES, "<td class=txt bgcolor=CFCFCF width=172>Percent:</td>\n");
  fprintf(UPDATES, "<td class=pct>05</td><td class=pct>10</td><td class=pct>15</td>\n");
  fprintf(UPDATES, "<td class=pct>20</td><td class=pct>25</td><td class=pct>30</td>\n");
  fprintf(UPDATES, "<td class=pct>35</td><td class=pct>40</td><td class=pct>45</td>\n");
  fprintf(UPDATES, "<td class=pct>50</td><td class=pct>55</td><td class=pct>60</td>\n");
  fprintf(UPDATES, "<td class=pct>65</td><td class=pct>70</td><td class=pct>75</td>\n");
  fprintf(UPDATES, "<td class=pct>80</td><td class=pct>85</td><td class=pct>90</td>\n");
  fprintf(UPDATES, "<td class=pct>95</td><td class=pct>100</td>\n");
  fprintf(UPDATES, "</tr>\n");

  fprintf(UPDATES, "<tr>\n");
  fprintf(UPDATES, "<td class=txt bgcolor=CFCFCF>Progress Bar:</td>\n");
  fprintf(UPDATES, "<td class=pct colspan=%d>&nbsp;</td>", disp_percent);
  if(disp_percent <20)
    fprintf(UPDATES, "<td class=txt colspan=%d>&nbsp;</td>", disp_remain);
  fprintf(UPDATES, "</tr>\n");

  fprintf(UPDATES, "<tr>");
  fprintf(UPDATES, "<td class=txt bgcolor=CFCFCF>Progress Status:</td>\n");
  fprintf(UPDATES, "<td class=txt colspan=20>");
  if(strcmp(type, "start") == 0) 
    fprintf(UPDATES, "Scan of %s started.", t_ip);
  if(strcmp(type, "attack") == 0) 
    fprintf(UPDATES, "Scan of %s completed to %d%%.", t_ip, prog_percent);
  if(strcmp(type, "finished") == 0) fprintf(UPDATES, "Finished scanning.");
  fprintf(UPDATES, "</td>");
  fprintf(UPDATES, "</tr>\n");

  fprintf(UPDATES, "<tr>\n");
  fprintf(UPDATES, "<td class=txt bgcolor=CFCFCF>Status Details:</td>\n");
  fprintf(UPDATES, "<td class=txt colspan=20>");
  if(strcmp(type, "start") == 0) 
    fprintf(UPDATES, "Please wait for updates.");
  if(strcmp(type, "attack") == 0)  {
    if(current_plug <= maxconf_plug)
      fprintf(UPDATES, "Plugin (%d of %d): %s", current_plug,
                                 maxconf_plug, plugslist[current_plug].name);
    else
      fprintf(UPDATES, "All Plugins launched, waiting for results...");
  }
  if(strcmp(type, "finished") == 0) fprintf(UPDATES, "Scan 100%% complete.");
  fprintf(UPDATES, "</td>");
  fprintf(UPDATES, "</tr>\n");
  fprintf(UPDATES, "<tr>\n");
  fprintf(UPDATES, "<th colspan=21>");
  fprintf(UPDATES, "<input type=button OnClick=\"return ");
  fprintf(UPDATES, "self.close();\" value=\"Close Window\">");
  fprintf(UPDATES, "</th>");
  fprintf(UPDATES, "</tr>\n");
  fprintf(UPDATES, "</table>\n");
  fprintf(UPDATES, "</body>\n");
  fprintf(UPDATES, "</div>\n");
  fprintf(UPDATES, "</html>");
  fclose(UPDATES);

  /* delete the update file after we finished the scan */
  if(strcmp(type, "finished") == 0) { sleep(2); unlink(res_path); }
}

/* ------------------------------------------------------------------------- *
 * scanner_getstats gets the scan process updates from the scan server.      *
 * ------------------------------------------------------------------------- */

void scanner_getstats(SSL *ssl, char *session) {

  char * buf = NULL;
  char * buf_ptr = NULL;
  char * tmp_loc = NULL;
  int    i=0, retcode = 0;
  size_t len, diff = 0;
  int stats_counter = 0;
  char status_type[81] = "";
  char status_ip[18] = "";
  char status_progress[81] = "";
  short dup_flag = 0;

  result_counter = 0;
  ports_counter = 0;

  buf = (char *) malloc(MAXDATASIZE);

  while(1) {
    memset(buf, '\0', MAXDATASIZE);
    buf_ptr = NULL;
    tmp_loc = NULL;
    len=SSL_read(ssl, buf, MAXDATASIZE);
#ifdef DEBUG
    if(debugfile != NULL) fputs(buf, debugfile);
#endif

    /* check if the scanner wants to end the connection: */
    /* SERVER <|> BYE <|> BYE <|> SERVER                 */
    if(strstr(buf, SERVER_BYE)) {
      /* respond with the clients BYE message */
      memset(buf, '\0', MAXDATASIZE);
      snprintf(buf, strlen(CLIENT_BYE)+2, "%s\n", CLIENT_BYE);
#ifdef DEBUG
      if(debugfile != NULL) fputs(buf, debugfile);
#endif
      retcode = SSL_write(ssl, buf, strlen(buf));
      /* stop waiting for further messages from the server */
      break;
    }

    /* check if the scan for the host is completed: */
    /* SERVER <|> FINISHED <|> 127.0.0.1 <|> SERVER */
    if(strstr(buf, HOST_END)) {
      /* buf_ptr points to the beginning of the IP address string */
      buf_ptr = buf + sizeof(HOST_END);
      /* tmp_loc will be set to the end of the IP address string */
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      /* diff will specify the length of the IP address string */
      diff = tmp_loc - buf_ptr;
      /* copy the IP address string in the variable status_ip */
      strncpy(status_ip, buf_ptr, diff+1);
      status_ip[diff]= '\0';
      /* stop writing the updates file */
      write_hostupdates(session_id, status_ip, "finished", "100");
    }

    /* Check if we got a "SERVER ERROR" start marker */
    if(strstr(buf, ERROR_START)) {
      /* buf_ptr contains the start pointer of the IP address string */
      buf_ptr = buf + sizeof(ERROR_START);
      /* tmp_loc will be set to the end of the IP address string */
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      /* diff will specify the length */
      diff = tmp_loc - buf_ptr;

      if(strstr(buf, LOGS_START)) strncpy(reslist[result_counter].type, "Error", 6);
      strncpy(reslist[result_counter].data, buf_ptr, diff);
      strcpy(reslist[result_counter].service, "n/a");
      strcpy(reslist[result_counter].plugin_id, "n/a");
      result_counter++;
    }

    /* Check if we got a PORT start marker */
    /* SERVER <|> PORT <|> 127.0.0.1 <|> ldaps (636/tcp) <|> SERVER */
    if(strstr(buf, PORTS_START)) {

      /* buf_ptr points to the beginning of the IP address string */
      buf_ptr = buf + sizeof(PORTS_START);
      /* tmp_loc will be set to the end of the IP address string */
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      /* diff will specify the length of the IP address string */
      diff = tmp_loc - buf_ptr;
      /* copy the IP address string in the variable status_ip */
      strncpy(status_ip, buf_ptr, diff+1);
      status_ip[diff]= '\0';

      /* buf_ptr will be set to the beginning of the port info */
      buf_ptr = tmp_loc + sizeof(SEPARATOR) -1;
      /* tmp_loc will be set to the end of the port info */
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      diff = tmp_loc - buf_ptr;
      /* we need to terminate buf_ptr for strcmp to work */
      buf_ptr[diff] = '\0';
      /* check if this port has been already reported */
      dup_flag = 0;
      for(i=0; i<ports_counter; i++) {
        if(strcmp(portlist[i].name, buf_ptr) == 0) {
#ifdef DEBUG
          if(debugfile != NULL) fputs(" Portscan duplicate - skipping...\n", debugfile);
#endif
          dup_flag = 1;
          break;
        }
      }

      if(dup_flag == 0) {
        /* copy the port information into the array */
        strncpy(portlist[ports_counter].name, buf_ptr, diff);
        portlist[ports_counter].name[diff]= '\0';
        ports_counter++;
      }
    }

    /* Check if we got a LOG, INFO, NOTE, or HOLE start marker */
    /* SERVER <|> NOTE <|> 127.0.0.1 <|> ldaps (636/tcp) <|> nmap thinks ssl... <|> 1.3.6.1.4.1.25623.1.0.66286 <|> SERVER */
    if(strstr(buf, LOGS_START) || strstr(buf, INFOS_START) ||
       strstr(buf, NOTES_START) || strstr(buf, HOLES_START)) {
      if(strstr(buf, LOGS_START)) strncpy(reslist[result_counter].type, "Log", 4);
      if(strstr(buf, INFOS_START)) strncpy(reslist[result_counter].type, "Info", 5);
      if(strstr(buf, NOTES_START)) strncpy(reslist[result_counter].type, "Note", 5);
      if(strstr(buf, HOLES_START)) strncpy(reslist[result_counter].type, "Hole", 5);
      /* buf_ptr will be set to the beginning of the IP address */
      if(strstr(buf, LOGS_START))
        buf_ptr = buf + sizeof(LOGS_START);
      else
        buf_ptr = buf + sizeof(INFOS_START);
      /* tmp_loc will be set to the end of the IP address string */
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      /* diff will specify the length */
      diff = tmp_loc - buf_ptr;
      /* copy the IP into the variable status_ip */
      strncpy(status_ip, buf_ptr, diff);
      status_ip[diff]= '\0';
  
      /* buf_ptr will be set to the beginning of the port info */
      buf_ptr = tmp_loc + sizeof(SEPARATOR) -1;
      /* tmp_loc will be set to the end of the port info */
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      diff = tmp_loc - buf_ptr;
      /* copy the port information into the array */
      strncpy(reslist[result_counter].service, buf_ptr, diff);
      reslist[result_counter].service[diff]= '\0';

      /* buf_ptr will be set to the beginning of the text info */
      buf_ptr = tmp_loc + sizeof(SEPARATOR) -1;
      /* tmp_loc will be set to the end of the text info */
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      diff = tmp_loc - buf_ptr;
      strncpy(reslist[result_counter].data, buf_ptr, diff);
      reslist[result_counter].data[diff]= '\0';

      /* buf_ptr will be set to the beginning of the id info */
      buf_ptr = tmp_loc + sizeof(SEPARATOR) -1;
      /* tmp_loc will be set to the end of the id info */
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      diff = tmp_loc - buf_ptr;
      strncpy(reslist[result_counter].plugin_id, buf_ptr, diff);
      reslist[result_counter].plugin_id[diff]= '\0';
      result_counter++;
    }

    /* Check if we got a STATUS start marker, example: */
    /* SERVER <|> STATUS <|> 127.0.0.1 <|> attack <|> 2/24069 <|> SERVER */
    if(strstr(buf, STATS_START)) {

      buf_ptr = buf + sizeof(STATS_START);
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      diff = tmp_loc - buf_ptr;
      // this is the ip address, i.e. "127.0.0.1 <|> attack <|> 2/24069 <|> SERVER"
      strncpy(status_ip, buf_ptr, diff);
      status_ip[diff] = '\0';
  
      /* tmp_loc now points at the end of the ip address */
      buf_ptr = tmp_loc + sizeof(SEPARATOR) - 1;
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      diff = tmp_loc - buf_ptr;
      // this is the type string, i.e. "attack <|> 182/183 <|> SERVER"
      strncpy(status_type, buf_ptr, diff);
      status_type[diff] = '\0';
  
      /* tmp_loc now points at the end of the attack string */
      buf_ptr = tmp_loc + sizeof(SEPARATOR) - 1;
      tmp_loc = strstr(buf_ptr, SEPARATOR);
      diff = tmp_loc - buf_ptr;
      // the string is now i.e. "182/183" */
      strncpy(status_progress, buf_ptr, diff);
      status_progress[diff] = '\0';

      /* We only check progress for attack, not for portscan */
      if(strcmp(status_type, "attack") == 0)
        write_hostupdates(session_id, status_ip, status_type, status_progress);

      stats_counter++;
    }
  }
}

void write_hostresults(char *t_ip, char *s_ip, char *session) {

  FILE *RESULTS;
  char res_path[127] = "";
  char scantimestr[127] = "";
  double scanduration = 0;
  char scandurationstr[10] = "";
  char title[72] = "Scan Results for ";
  char table_title[1024] = "";
  char table_title_buf[256] = "";
  struct tm scantime_start;
  struct tm *scantime_end;
  time_t end_tstamp;
  int i,j =0;
  long hours = 0; /* can't help it :) */
  long mins = 0;
  long secs = 0;
  ldiv_t timediff;
  char outbuf[16192];
  char *startptr, *newline;
  int  len;
  int log_counter = 0;
  int hole_counter = 0;
  int info_counter = 0;
  int note_counter = 0;
  int error_counter = 0;
  
  strcat(title, t_ip);

  /* get the scan end time, calculate the difference from scan start */
  end_tstamp = time(NULL);
  scantime_end = localtime(&end_tstamp);

  /* convert the scan session start timestamp into a human readable string */
  strptime(session, "%s", &scantime_start);
  strftime(scantimestr, sizeof(scantimestr), "%B, %d. %Y at %T", &scantime_start);

  /* calculate the difference from scan start and write it to scanduration */
  scanduration = difftime(end_tstamp, mktime(&scantime_start));

  /* Create a scan duration string */
  secs = (long) (scanduration+0.5);

  if (secs>=3600) { 
    timediff = ldiv(secs, 3600);
    hours = timediff.quot;
    secs = timediff.rem;
  }

  if (secs>=60) { 
    timediff = ldiv(secs, 60);
    mins = timediff.quot;
    secs = timediff.rem;
  }

  snprintf(scandurationstr, sizeof(scandurationstr), "%02ld:%02ld:%02ld",
                                                     hours, mins, secs);

  /* calculate the scan results summary */
  for(i=0; i<result_counter; i++) {
    if(strcmp(reslist[i].type, "Log") == 0)   log_counter++;
    if(strcmp(reslist[i].type, "Hole") == 0)  hole_counter++;
    if(strcmp(reslist[i].type, "Info") == 0)  info_counter++;
    if(strcmp(reslist[i].type, "Note") == 0)  note_counter++;
    if(strcmp(reslist[i].type, "Error") == 0) error_counter++;
  }

  /* start the html output */
  sprintf(res_path, "%s/session-%s.htm", RESULTS_DIR, session);
  RESULTS = fopen(res_path, "w");
  if(RESULTS == NULL) int_error("Could not start writing the results file.");

  get_dns(t_ip);
  sprintf(table_title_buf, "Scan results for Host %s [%s]", t_ip, dns_name);
  strcat(table_title, table_title_buf);
  get_dns(cgiRemoteAddr);
  sprintf(table_title_buf, " requested by %s [%s]", cgiRemoteAddr, dns_name);
  strcat(table_title, table_title_buf);
  get_dns(s_ip);
  sprintf(table_title_buf, " and executed from the scan server %s [%s]", s_ip, dns_name);
  strcat(table_title, table_title_buf);
  
  sprintf(table_title_buf, " on %s", scantimestr);
  strcat(table_title, table_title_buf);

  sprintf(table_title_buf, " using template '%s'.", template_name);
  strcat(table_title, table_title_buf);

  pagehead(title, session, RESULTS);
  fprintf(RESULTS, "<table width=\"100%%\">\n");
  fprintf(RESULTS, "<tr>");
  fprintf(RESULTS, "<th colspan=3>INOVASC Scan Results Summary</th>");
  fprintf(RESULTS, "</tr>\n");

  fprintf(RESULTS, "<tr>");
  fprintf(RESULTS, "<td colspan=3>%s<p>", table_title);
  fprintf(RESULTS, "<table class=\"Summary\"><tr>");
  fprintf(RESULTS, "<td class=\"Port\">Port</td>");
  fprintf(RESULTS, "<td class=\"count\">%d</td>", ports_counter);
  fprintf(RESULTS, "<td class=\"empty\">&nbsp;</td>");
  fprintf(RESULTS, "<td class=\"Hole\">Hole</td>");
  fprintf(RESULTS, "<td class=\"count\">%d</td>", hole_counter);
  fprintf(RESULTS, "<td class=\"empty\">&nbsp;</td>");
  fprintf(RESULTS, "<td class=\"Info\">Info</td>");
  fprintf(RESULTS, "<td class=\"count\">%d</td>", info_counter);
  fprintf(RESULTS, "<td class=\"empty\">&nbsp;</td>");
  fprintf(RESULTS, "<td class=\"Note\">Note</td>");
  fprintf(RESULTS, "<td class=\"count\">%d</td>", note_counter);
  fprintf(RESULTS, "<td class=\"empty\">&nbsp;</td>");
  fprintf(RESULTS, "<td class=\"Log\">Log</td>");
  fprintf(RESULTS, "<td class=\"count\">%d</td>",  log_counter);
  fprintf(RESULTS, "<td class=\"empty\">&nbsp;</td>");
  fprintf(RESULTS, "<td class=\"Error\">Error</td>");
  fprintf(RESULTS, "<td class=\"count\">%d</td>", error_counter);
  fprintf(RESULTS, "</tr></table></td>");
  fprintf(RESULTS, "</tr>\n");

  fprintf(RESULTS, "<tr>");
  fprintf(RESULTS, "<th colspan=3>INOVASC Scan Results Listing</th>");
  fprintf(RESULTS, "</tr>\n");

  fprintf(RESULTS, "<tr>");
  fprintf(RESULTS, "<td class=\"Port\" width=20>Port</td>");
  fprintf(RESULTS, "<td class=\"result\" width=160>Service: List of Ports</td>");
  fprintf(RESULTS, "<td class=\"result\" width=330>Name: Port Scanners</td>");
  fprintf(RESULTS, "</tr>");
  fprintf(RESULTS, "<tr>");
  fprintf(RESULTS, "<td colspan=3>");
  for(i=0; i<ports_counter; i++) {
    fprintf(RESULTS, "%s<br>", portlist[i].name);
  }
  if(ports_counter == 0) {
    fprintf(RESULTS, "The port scan did not return any results.<br>");
    fprintf(RESULTS, "If port scanners had been enabled, then the target system may be firewalled.<br>");
  }
  fprintf(RESULTS, "<br></td>");
  fprintf(RESULTS, "</tr>\n");

  for(i=0; i<result_counter; i++) {

    fprintf(RESULTS, "<tr>");
    fprintf(RESULTS, "<td class=\"%s\" width=20>%s</td>", reslist[i].type, reslist[i].type);
    fprintf(RESULTS, "<td class=\"result\" width=160>Service: %s</td>", reslist[i].service);
    fprintf(RESULTS, "<td class=\"result\" width=330>");
    for(j=0; j<plugs_counter; j++) {
      if(strcmp(reslist[i].plugin_id, plugslist[j].id) == 0)
        fprintf(RESULTS, "Name: %s", plugslist[j].name);
    }
    if(strcmp(reslist[i].plugin_id, "n/a") == 0)
      fprintf(RESULTS, "Scanner Error: Can't scan %s", t_ip);
    fprintf(RESULTS, "</td>");
    fprintf(RESULTS, "</tr>\n");
	
    fprintf(RESULTS, "<tr>");
    if( i == 1 || (i % 2) != 0 ) fprintf(RESULTS, "<td class=\"even\" colspan=3>");
    else fprintf(RESULTS, "<td class=\"odd\" colspan=3>");

    /* The plugin description uses \n separators to format the output. */
    /* For HTML display, we convert them to <br>.                      */
    startptr = reslist[i].data;
    outbuf[0] = '\0';
    len = 0;
    while((newline = strstr(startptr, "\\n"))) {
      len = newline - startptr;
      if(len > 0) {
        strncat(outbuf, startptr, len);
        strncat(outbuf, "<br>", 5);
      }
      //fprintf(RESULTS, "%d %d %d %s<br>", newline, startptr, len, outbuf);
      startptr = newline+2;
    }
    fprintf(RESULTS, "%s<br>", outbuf);
    fprintf(RESULTS, "</td>");
    fprintf(RESULTS, "</tr>\n");
  }
  fprintf(RESULTS, "%s<br>", reslist[i].data);
  fprintf(RESULTS, "<tr>");
  fprintf(RESULTS, "<th colspan=3>");
  fprintf(RESULTS, "Scan duration [HH:MM:SS]: %s", scandurationstr);
  fprintf(RESULTS, "</th>");
  fprintf(RESULTS, "</tr>\n");
  fprintf(RESULTS, "</table>\n");

  pagefoot(RESULTS);
  fclose(RESULTS);
}

/* create_session_id takes the host string from the host start message sent bey the *
 * scan server. It returns the session string calculated from the scan start time   *
 * and the target host IP. An example session id looks like 1327134667_16777343     */
char * create_session_id(SSL *ssl) {

  int len = 0;
  int timestamp = 0;
  int decimal_ip = 0;
  char * buf = NULL;
  char * buf_ptr = NULL;
  char * tmp_loc = NULL;
  char target_ip[16] = "";
  size_t diff = 0;

  buf = (char *) malloc(MAXDATASIZE);

  /* Now we should receive the host scan start marker, see an example below:              */
  /* SERVER <|> TIME <|> HOST_START <|> 127.0.0.1 <|> Sat Jan 21 17:07:22 2012 <|> SERVER */
  memset(buf, '\0', MAXDATASIZE);
  len=SSL_read(ssl, buf, MAXDATASIZE);
#ifdef DEBUG
  if(debugfile != NULL) fputs(buf, debugfile);
#endif

  if(! strstr(buf, HOST_START)) {
    snprintf(error_string, sizeof(error_string),
             "Expected to receive the host start message from the scan server.<p>%s", buf);
    int_error(error_string);
  }

  /* buf_ptr contains the start pointer of the IP address string */
  buf_ptr = buf + sizeof(HOST_START);
  /* tmp_loc will be set to the end of the IP address string */
  tmp_loc = strstr(buf_ptr, SEPARATOR);
  /* diff will specify the length */
  diff = tmp_loc - buf_ptr;
  strncpy(target_ip, buf_ptr, diff);

  timestamp = time(NULL);
  decimal_ip = inet_addr(target_ip);
  snprintf(session_id, sizeof(session_id), "%d_%d", timestamp, decimal_ip);

  /* The code below is for debugging the session id */
  //snprintf(error_string, sizeof(error_string), "create_session_id():%s", session_id); 
  //int_error(error_string);

  return session_id;
}

void get_dns(char *ip) {

  struct hostent *host;
  struct in_addr *my_addr;

  strcpy(dns_name, "");
  my_addr=(struct in_addr*)malloc(sizeof(struct in_addr));
  my_addr->s_addr=inet_addr(ip);
  host = gethostbyaddr((char *) my_addr, 4, AF_INET);
  if(host != NULL) strncpy(dns_name, host->h_name, sizeof(dns_name));
  else strncpy(dns_name, "unknown", sizeof(dns_name));
}

/* -------------------------------------------------------------------------- *
 * result_select: helper function used in scandir() to select files in a dir. *
 * -------------------------------------------------------------------------- */

int result_select(const struct dirent *entry) {

  /* check for "." and ".." directory entries */
  if(entry->d_name[0]=='.') return 0;

  /* Check for session-<id>.rc file name extensions */
  if( (strstr(entry->d_name, "session-") != NULL) &&
      (strstr(entry->d_name, ".htm") != NULL) ) return 1;
  else return 0;
}

/* ------------------------------------------------------------------------- *
 * templ_select: helper function used in scandir() to select files in a dir. *
 * ------------------------------------------------------------------------- */

int templ_select(const struct dirent *entry) {

  /* check for "." and ".." directory entries */
  if(entry->d_name[0]=='.') return 0;

  /* Check for session-<id>.rc file name extensions */
  if( (strstr(entry->d_name, "template-") != NULL) &&
      (strstr(entry->d_name, ".rc") != NULL) ) return 1;
  else return 0;
}

int template_setplugs(SSL *ssl) {
  int retcode = 0;
  int scanplug_counter = 0;
  int i = 0;

  /* send the client plugin list start marker, !NOT! followed by a newline */
  retcode = SSL_write(ssl, PLUGS_SET, strlen(PLUGS_SET));

  for(i=0; i<template_plugs_all; i++) {
    if(template_plug_list[i].enabled == 1) {

      /* send the semicolon, unless we got the first id, in which case we  *
       * don't need to.                                                    */
       if (scanplug_counter != 0)
         retcode = SSL_write(ssl, semicolon, strlen(semicolon));

       retcode = SSL_write(ssl, template_plug_list[i].id,
                              strlen(template_plug_list[i].id));
       scanplug_counter++;
    }
  }

  retcode = SSL_write(ssl, newline, 1);
  retcode = SSL_write(ssl, CLIENT_END, strlen(CLIENT_END));
  retcode = SSL_write(ssl, newline, 1);

  return scanplug_counter;
}

void set_credentials(char *type, char * user, char *pass, int prefs_counter) {
  int i;

  for (i=0; i<prefs_counter; i++) {
    if(strcmp(type, "ssh-pass") == 0) {
      if(strstr(prefslist_ptr[i]->name, "SSH login name:") != NULL)
        strncpy(prefslist_ptr[i]->value, user, sizeof(prefslist_ptr[i]->value));
      if(strstr(prefslist_ptr[i]->name, "SSH password (unsafe!):") != 0)
        strncpy(prefslist_ptr[i]->value, pass, sizeof(prefslist_ptr[i]->value));
    }
    if(strcmp(type, "smb-pass") == 0) {
      if(strstr(prefslist_ptr[i]->name, "SMB login:") != NULL)
        strncpy(prefslist_ptr[i]->value, user, sizeof(prefslist_ptr[i]->value));
      if(strstr(prefslist_ptr[i]->name, "SMB password:") != 0)
        strncpy(prefslist_ptr[i]->value, pass, sizeof(prefslist_ptr[i]->value));
    }
  }
  return;
}
