/* -------------------------------------------------------------------------- *
 * file:         pagefoot.c                                                   *
 * purpose:      provides a standard page footer across all cgi's             *
 * ---------------------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include <cgic.h>
#include "inovasc.h"

void pagefoot(FILE *out) {

  int ret;
  FILE *fp;
  char hostport[72] = "[unknown] port [none]";

  /* check were our output should go to: null means to cgiOut */
  if(out == NULL) out = cgiOut;
 
  if(strlen(cgiServerName) != 0) {
     strcpy(hostport, cgiServerName);
     strcat(hostport, " port ");
     strcat(hostport, cgiServerPort);
  }

  fprintf(out, "</div>\n");

  fprintf(out, "<div id=\"sidecontent\">\n");

  if ((fp = fopen(SIDEBAR_TEMPL, "r"))) {
    for(;;) {
       ret = getc(fp);
       if(ret == EOF) break;
       fprintf(out, "%c", ret);
     }
  }

  fprintf(out, "</div>\n");

  fprintf(out, "<div id=\"footer\">\n");
  fprintf(out, "<span class=\"left\">&copy; %s by <a href=\"http://www.frank4dd.com/\">Frank4DD</a> - licensed under GPL.</span>\n", CLIENT_SW_VERSION);
  fprintf(out, "<span class=\"right\">");
  fprintf(out, "Generated on: %s", hostport);
  fprintf(out, " for: ");
  if (strlen(cgiRemoteUser) != 0) fprintf(out, "%s", cgiRemoteUser);
  if (strlen(cgiRemoteAddr) != 0) fprintf(out, "%s", cgiRemoteAddr);
  else fprintf(out, "%s", "[unknown]");
  fprintf(out, "</span>\n");
  fprintf(out, "</div>\n");
  fprintf(out, "</div>\n");

  /* the html footer template typically contains web analytics tracking code. */
  /* we do not want to add this code to the scan results, only cgi output */
  if ((fp = fopen(FOOTER_TEMPL, "r")) && (out == cgiOut)) {
    for(;;) {
       ret = getc(fp);
       if(ret == EOF) break;
       fprintf(out, "%c", ret);
     }
  }

  fprintf(out, "</body>\n");
  fprintf(out, "</html>\n");
}
