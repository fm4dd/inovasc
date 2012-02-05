/* ------------------------------------------------------------------------ *
 *                                                                          *
 * ntp-clear-demo.c                                                         *
 *                                                                          *
 * This program demonstrates  a cleartext communication with a Nessus       *
 * daemon and counts the initial nessus server settings to the screen.      *
 * In order to work, ssl_version=none must be set in nessusd.conf.          *
 *                                                                          *
 * The Following settings according to NTP 1.2 are retrieved:               *
 * SERVER <|> PLUGIN_LIST <|> [data] <|> SERVER                             *
 * SERVER <|> PREFERENCES <|> [data] <|> SERVER                             *
 * SERVER <|> RULES <|> [data] <|> SERVER                                   *
 *                                                                          *
 * this program has been written and tested with nessusd version 2.2.0      *
 * 20041119 frank4dd                                                        *
 *                                                                          *
 * compile instructions:                                                    *
 * gcc -lssl -lcrypt ntp-clear-demo.c -o ntp-clear-demo                     *
 * ------------------------------------------------------------------------ */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DEBUG 1
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
#define CLIENT_NTP_VERSION "< OTP/1.0 >"
#define SERVER_NTP_VERSION "< OTP/1.0 >"
#define PLUGS_START "SERVER <|> PLUGIN_LIST <|>"
#define PREFS_START "SERVER <|> PREFERENCES <|>"
#define RULES_START "SERVER <|> RULES <|>"
#define SERVER_END_MARKER "<|> SERVER"

char server_ntp_version[255];

int  plugs_counter = 0;
int  prefs_counter = 0;
int  rules_counter = 0;


/* ------------------------------------------------------------------------- *
 * nessus_connect creates a new tcp session to the nessus server and returns *
 * the file descriptor to it.                                                *
 * ------------------------------------------------------------------------- */
int nessus_connect(char * nessus_ip, int nessus_port) {
  int sockfd;
  struct sockaddr_in dest_addr;

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
    return sockfd;
  }
}

/* ------------------------------------------------------------------------- *
 * nessus_login tries to log in with the username and password provided. It  *
 * returns 1 for success, 0 for failure.                                     *
 * ------------------------------------------------------------------------- */

int nessus_login(int fd, char * username, char * password){

  char * buf = NULL;
  size_t len;
  int login = 0 , retcode = 0;
  const char newline[2] = {'\n', '\0'};

  /* send the client protocol version, followed by a newline */
  if(DEBUG) printf("Sending Data: %s%c", CLIENT_NTP_VERSION, '\n');
  retcode = send(fd, CLIENT_NTP_VERSION, strlen(CLIENT_NTP_VERSION), 0);
  retcode = send(fd, newline, 1, 0);

  buf = (char *) malloc(MAXDATASIZE);

  /* receive the server protocol version, followed by a newline */
  retcode=recv(fd, buf, strlen(SERVER_NTP_VERSION)+1, 0);
  if(DEBUG) printf("Receive Data: %s", buf);

  /* set global variable server protocol version, remove the newline */
  strncpy(server_ntp_version, buf, retcode-1);

  /* clear the buffer */
  memset(buf, '\0', MAXDATASIZE);

  /* receive the username prompt */
  retcode=recv(fd, buf, MAXDATASIZE, 0);
  if(DEBUG) printf("Receive Data: %s\n", buf);

  /* clear the buffer */
  memset(buf, '\0', MAXDATASIZE);

  /* send the username followed by a newline */
  if(DEBUG) printf("Sending Data: %s%c", USERNAME, '\n');
  retcode = send(fd, USERNAME, strlen(USERNAME), 0);
  retcode = send(fd, newline, 1, 0);

  /* receive the password prompt */
  retcode=recv(fd, buf, MAXDATASIZE, 0);
  if(DEBUG) printf("Receive Data: %s\n", buf);

  /* clear the buffer */
  memset(buf, '\0', MAXDATASIZE);

  /* send the password followed by a newline */
  if(DEBUG) printf("Sending Data: %s%c", PASSWORD, '\n');
  retcode = send(fd, PASSWORD, strlen(PASSWORD), 0);
  retcode = send(fd, newline, 1, 0);


  /* look into the login response but don't take data out yet */
  retcode=recv(fd, buf, MAXDATASIZE, MSG_PEEK);

  /* check for the first newline */
  len = strcspn(buf, "\n");

  /* clear the buffer */
  memset(buf, '\0', MAXDATASIZE);

  /* Now we take the data out */
  retcode=recv(fd, buf, len, 0);

  if(DEBUG) printf("Receive Data: %s\n", buf);

  /* Check if we got the "Bad Login" info or the Plugin List start marker */
  if(strstr(buf, PLUGS_START)) login = 1;

  /* Take the last newline out */
  retcode=recv(fd, buf, 1, 0);

  free(buf);
  return login;
}

/* ------------------------------------------------------------------------- *
 * nessus_getplugs tries to retrieve the list of plugins from the server. It *
 * returns the number of retrieved plugins for success, 0 for failure.       *
 * ------------------------------------------------------------------------- */

int nessus_getplugs(int fd){

  char * buf = NULL;
  int retcode = 0;
  size_t len;
  int i;

  buf = (char *) malloc(MAXDATASIZE);

  /* cycle through the big chunk of preferences data we */
  /* are receiving.                                     */
 
  while(1) {
    /* look into the input stream but don't take data out yet */
    retcode=recv(fd, buf, MAXDATASIZE, MSG_PEEK);

    /* check for the first newline */
    len = strcspn(buf, "\n");

    /* clear the buffer */
    memset(buf, '\0', MAXDATASIZE);

    /* Now we take the data out */
    retcode=recv(fd, buf, len, 0);

    /* check if the end marker hits */
    if(strstr(buf, SERVER_END_MARKER)) { 
      if(DEBUG) printf("Receive Data: %s\n", buf);
      break;
    }

    plugs_counter++;

    //if(DEBUG == 2 ) printf("%s\n", buf);
    if(DEBUG == 2) {
      printf("Len %4.0d Counter %4.0d Plugin ID: ", len, plugs_counter);
      for(i=0;i<5;i++) putchar(buf[i]);
      putchar('\n');
    }

    /* Now we take the newline out */
    retcode=recv(fd, buf, 1, 0);

    /* clear the buffer */
    memset(buf, '\0', MAXDATASIZE);
  }

  /* Take the last newline out */
  retcode=recv(fd, buf, 1, 0);

  free(buf);
  return plugs_counter;
}

/* ------------------------------------------------------------------------- *
 * nessus_getprefs retrieves the list of preferences from the server. It     *
 * returns the number of retrieved preferences for success, 0 for failure.   *
 * ------------------------------------------------------------------------- */

int nessus_getprefs(int fd) {

  char * buf = NULL;
  int retcode = 0;
  size_t len;

  buf = (char *) malloc(MAXDATASIZE);

  /* receive the Preferences List start marker */
  retcode=recv(fd, buf, strlen(PREFS_START)+1, 0);
  if(DEBUG) printf("Receive Data: %s", buf);

  if(! strstr(buf, PREFS_START)) exit(1);

  while(1) {
    /* look into the input stream but don't take data out yet */
    retcode=recv(fd, buf, MAXDATASIZE, MSG_PEEK);

    /* check for the first newline */
    len = strcspn(buf, "\n");

    /* clear the buffer */
    memset(buf, '\0', MAXDATASIZE);

    /* Now we take the data out */
    retcode=recv(fd, buf, len, 0);

    /* check if the end marker hits */
    if(strstr(buf, SERVER_END_MARKER)) {
      if(DEBUG) printf("Receive Data: %s\n", buf);
      break;
    }

    prefs_counter++;

    if(DEBUG == 2) {
      printf("Len %3.0d Counter %3.0d Pref: ", len, prefs_counter);
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
  return prefs_counter;
}

/* ------------------------------------------------------------------------- *
 * nessus_getrules retrieves the list of rules from the server. It           *
 * returns the number of retrieved rules for success, 0 for failure.         *
 * ------------------------------------------------------------------------- */

int nessus_getrules(int fd){

  char * buf = NULL;
  int retcode = 0;
  size_t len;

  buf = (char *) malloc(MAXDATASIZE);

  /* receive the Rules List start marker */
  retcode=recv(fd, buf, strlen(RULES_START)+1, 0);
  if(DEBUG) printf("Receive Data: %s", buf);

  if(! strstr(buf, RULES_START)) exit(1);

  while(1) {
    /* look into the input stream but don't take data out yet */
    retcode=recv(fd, buf, MAXDATASIZE, MSG_PEEK);

    /* check for the first newline */
    len = strcspn(buf, "\n");

    /* clear the buffer */
    memset(buf, '\0', MAXDATASIZE);

    /* Now we take the data out */
    retcode=recv(fd, buf, len, 0);

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

  int nessusfd;
  int ret;

  nessusfd = nessus_connect(DEST_IP, DEST_PORT);

  ret = nessus_login(nessusfd, USERNAME, PASSWORD);

  if(ret == 0) {
    printf("login of %s with %s failed.\n", USERNAME, PASSWORD);
    close(nessusfd);
    exit(1);
  }

  printf("sucessful login\n");

  plugs_counter = nessus_getplugs(nessusfd);

  if(plugs_counter) printf("Found %d Plugins of 5440.\n", plugs_counter);
  else printf("\nFailed to receive any plugins.\n");

  prefs_counter = nessus_getprefs(nessusfd);

  if(prefs_counter) printf("Found %d Prefs of 165.\n", prefs_counter);
  else printf("\nFailed to receive any preferences.\n");

  rules_counter = nessus_getrules(nessusfd);

  if(rules_counter >= 0) printf("Found %d Rules of 0.\n", rules_counter);
  else printf("\nFailed to receive any Rules.\n");
 
  printf("Closing connection to %s.\n", DEST_IP);
  close(nessusfd);
  exit(0);
}
