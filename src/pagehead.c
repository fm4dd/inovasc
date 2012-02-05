/* -------------------------------------------------------------------------- *
 * file:         pagehead.c                                                   *
 * purpose:      provides the standard page header across all cgi's           *
 *                                                                            *
 *               If the session parameter is not NULL (scanprogress.cgi),     *
 *               we set the http redirect to scan results and add the         *
 *               progress update popup code to the scanprogress html header.  *
 * ---------------------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include <cgic.h>
#include "inovasc.h"

void pagehead(char* title, char *session, FILE *out) {

  char res_page[81] = "";
  if(out == NULL) out = cgiOut;

/* -------------------------------------------------------------------------- *
 * start the head output                                                      *
 * ---------------------------------------------------------------------------*/

  if(out == cgiOut) cgiHeaderContentType("text/html; charset=UTF-8");
  fprintf(out, "<html>\n");
  fprintf(out, "<head>\n");
  fprintf(out, "<link rel=\"stylesheet\" type=\"text/css\" href=\"../style/style.css\" media=\"screen\" />\n");

  if(session != NULL && out == cgiOut) {
    /* here goes the html redirect code to point to the results file */
    snprintf(res_page, sizeof(res_page), "session-%s.htm", session);
    fprintf(out, "<meta http-equiv=\"refresh\"");
    fprintf(out, "content=\"1; url=%s/%s\">\n", RESULTS_DIR, res_page);
  }

  fprintf(out, "<meta name=\"Title\" content=\"INOVASC - %s\" />\n", title);
  fprintf(out, "<meta name=\"Description\" content=\"INOVASC - OpenVAS security scanner web client\" />\n");
  fprintf(out, "<meta name=\"Keywords\" content=\"OpenVAS, vulnerability assessment, scanner, audit, compliance\" />\n");
  fprintf(out, "<title>INOVASC - %s</title>\n", title);
  fprintf(out, "</head>\n");

  fprintf(out, "<body>\n");
  fprintf(out, "<div id=\"wrapper\">\n");
  fprintf(out, "<div id=\"banner\">\n");
  fprintf(out, "<h1>INOVASC - %s</h1>\n", title);
  fprintf(out, "<h2>Web-based System Vulnerability Assessment with OpenVAS</h2>\n");
  fprintf(out, "</div>\n");

  fprintf(out, "<div id=\"vmenu\">\n");
  fprintf(out, "<ul>\n");
  fprintf(out, "<li><a href=\"%s\" class=\"selected\"><span>Home</span></a></li>\n", HOMELINK);
  fprintf(out, "<li><a href=\"%s/cgi-bin/scantemplates.cgi\"><span>Scan Templates</span></a></li>\n", HOMELINK);
  fprintf(out, "<li><a href=\"%s/cgi-bin/scanlogin.cgi\"><span>Direct Scan</span></a></li>\n", HOMELINK);
  fprintf(out, "<li><a href=\"%s/cgi-bin/scanresults.cgi\"><span>List existing Results</span></a></li>\n", HOMELINK);
  fprintf(out, "<li><a href=\"%s/cgi-bin/help.cgi\"><span>Help</span></a></li>\n", HOMELINK);
  fprintf(out, "<li><a href=\"%s/cgi-bin/about.cgi\"><span>About</span></a></li>\n", HOMELINK);
  fprintf(out, "</ul>\n");
  fprintf(out, "</div>\n");

  fprintf(out, "<div id=\"content\">\n");
}
