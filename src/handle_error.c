/* -------------------------------------------------------------------------- *
 * file:	 handle_error.c                                               *
 * purpose:      provides a standard error page for all cgi's                 *
 * ---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cgic.h>
#include "inovasc.h"

void handle_error(const char *file, int lineno, const char *msg)
{
   static char title[] = "System Error Information";

/* -------------------------------------------------------------------------- *
 * start the html output                                                      *
 * ---------------------------------------------------------------------------*/

   pagehead(title, NULL, cgiOut);

   fprintf(cgiOut, "<h3>%s Error</h3>\n", CLIENT_SW_VERSION);
   fprintf(cgiOut, "<hr>");
   fprintf(cgiOut, "<ul><li>File: %s Line: %d</li></ul>\n", file, lineno);
   fprintf(cgiOut, "<p>Error: %s</p>\n", msg);

   fprintf(cgiOut, "<h3>Additional Information</h3>\n");
   fprintf(cgiOut, "<hr>");
   fprintf(cgiOut, "<p>");
   ERR_print_errors_fp(cgiOut);
   fprintf(cgiOut, "</p>");

   fprintf(cgiOut, "<p>");
   fprintf(cgiOut, "For most common errors, please see section 5 under <a href=\"help.cgi\">Help</a>.\n");
   fprintf(cgiOut, "If the problem persists, please contact me at <a href=\"mailto:%s\">%s</a>\n", CONTACT_EMAIL, CONTACT_EMAIL);
   fprintf(cgiOut, "with the info above and include a description what triggered the error.");
   fprintf(cgiOut, "</p>");
   pagefoot(NULL);
   exit(-1);
}
