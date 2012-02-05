/* -------------------------------------------------------------------------- *
 * file:         about.c                                                      *
 * purpose:      display the about message in the about.txt file              *
 * ---------------------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include <cgic.h>
#include "inovasc.h"

int cgiMain() {

  int ret;
  FILE *fp;
  static char title[] = "About ";
  strcat(title, CLIENT_SW_VERSION);

  if (! (fp = fopen(ABOUT_TEMPL, "r")))
     int_error("Error cant open about file");

/* -------------------------------------------------------------------------- *
 * start the html output                                                      *
 * ---------------------------------------------------------------------------*/

   pagehead(title, NULL, cgiOut);

/* -------------------------------------------------------------------------- *
 * start the form output                                                      *
 * ---------------------------------------------------------------------------*/

   for(;;) {
      ret = getc(fp);
      if(ret == EOF) break;
      fprintf(cgiOut, "%c", ret);
   }
   pagefoot(NULL);
   fclose(fp);
   return(0);
}
