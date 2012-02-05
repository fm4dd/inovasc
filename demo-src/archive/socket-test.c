/* ------------------------------------------------------------------------ *
 *                                                                          *
 * socket-test.c                                                            *
 *                                                                          *
 * This program demonstrates the communication with a web server            *
 * and dumps the server root page (index.htm) to the screen.                *
 *                                                                          *
 * this program has been written and tested with apache 1.3.28              *
 * and implements the functions from Beej's Guide to Network Programming.   *
 * http://www.ecst.csuchico.edu/~beej/guide/net/                            *
 *                                                                          *
 * 20041117 frank4dd                                                        *
 * ------------------------------------------------------------------------ */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DEST_IP "192.168.11.8"
#define DEST_PORT 80
#define MAXDATASIZE 1024

int main() {

  int i, sum;
  int sockfd;
  int buflen;
  int retcode;
  struct sockaddr_in dest_addr;
  char buf[MAXDATASIZE];

  printf("Creating socket file descriptor.\n");

  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  printf("Loading content into filedescriptor.\n");

  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(DEST_PORT);
  dest_addr.sin_addr.s_addr=inet_addr(DEST_IP);
  printf("Zeroing the rest of the struct.\n");
  memset(&(dest_addr.sin_zero), '\0', 8); // zero the rest of the struct

  printf("Try connecting to %s.\n", DEST_IP);

  if ( connect(sockfd, (struct sockaddr *) &dest_addr,
                              sizeof(struct sockaddr)) == -1 ) {
    perror("Error connecting");
    exit(1);
  } else {
    printf("Connected to %s.\n", DEST_IP);
  }
  
  printf("Sending data request to %s.\n", DEST_IP);

  sprintf(buf, "GET / HTTP/1.1\r\nHost: DEST_IP\r\nConnection: close\r\n\r\n");
  buflen=strlen(buf);
  retcode = write(sockfd, buf, buflen);

  printf("Receiving data from %s.\n", DEST_IP);

  sum=0;

  do {

    retcode=read(sockfd, buf, MAXDATASIZE);
    sum=sum+retcode;
    if(retcode > 0) {
      for(i=0;i<retcode;i++) {
        putchar(buf[i]);
      }
    } else break;
  }
  while (1);

  printf("Received %d bytes of data from %s.\n", sum, DEST_IP);

  printf("Closing connection to %s.\n", DEST_IP);
  close(sockfd);
  exit(0);
}
