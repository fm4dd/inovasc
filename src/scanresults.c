/* -------------------------------------------------------------------------- *
 * file:         scanresults.c                                                *
 * purpose:      builds a list of session html files in the results directory *
 * ---------------------------------------------------------------------------*/

/* needed for strptime() function in nessuswc.c, used in scanresults.c */
#define _XOPEN_SOURCE
#define __USE_XOPEN
#define __USE_GNU
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <cgic.h>

#include "inovasc.h"

int result_select(const struct dirent *entry);

int cgiMain() {

  static char 	title[] = "List of Scan Results";
  char		targetdec_ip[16] = "";
  char		targetdot_ip[16] = "";
  char		timestamp[16] = "";
  char		sorting[16] = "desc";
  char		scantimestr[33] = "";
  char		*buf_ptr = NULL;
  struct	dirent **resultsdir_list;
  struct	in_addr target_ip;
  struct	tm scantime;
  char		resultsfilestr[225];
  char          altcolor[16] = "class=\"odd\"";
  int pagenumber = 1;
  int rescounter = 0;
  int tempcounter = 0;
  int pagecounter = 0;
  int dispcounter = 0;
  int dispmaxlines = 0;
  div_t disp_calc;

/* -------------------------------------------------------------------------- *
 * Get the list of .htm files from the result directory                       *
 * ---------------------------------------------------------------------------*/
  rescounter = scandir(RESULTS_DIR, &resultsdir_list, result_select, alphasort);
  if(rescounter<=0) int_error("Error: No result files found.");

/* -------------------------------------------------------------------------- *
 * calculate how many pages we get with MAXRESDISPLAY                         *
 * ---------------------------------------------------------------------------*/

  if(rescounter<=MAXRESDISPLAY) pagecounter = 1;
  else {
    disp_calc = div(rescounter, MAXRESDISPLAY);
    /* if the count of certs divided by MAXCERTDISPLAY has no remainder */
    if(disp_calc.rem == 0) pagecounter = disp_calc.quot;
    /* with a remainder, we must prepare an extra page for the rest */
    else pagecounter = disp_calc.quot +1;
  }

/* -------------------------------------------------------------------------- *
 * Check if we have been subsequently called with a pagenumber & sort request *
 * ---------------------------------------------------------------------------*/

  if(cgiFormInteger("page", &pagenumber, 1) == cgiFormSuccess)
    if(pagenumber > pagecounter || pagenumber <=0)
      int_error("Error: Page does not exist.");

  if(cgiFormString("sort", sorting, sizeof(sorting)) != cgiFormSuccess)
      strncpy(sorting, "desc", sizeof(sorting));

/* -------------------------------------------------------------------------- *
 * now we know how many results we have in total and we can build the page(s).*
 * For every MAXDISPLAY results we start a new page and cycle through by      *
 * calling ourself with the requested results range.                          *
 * ---------------------------------------------------------------------------*/

  if(strcmp(sorting, "asc") == 0) {

    if(rescounter <= MAXRESDISPLAY) {
       dispmaxlines = rescounter;
       tempcounter = 0;
    }
    else 
      if(pagenumber == pagecounter &&
             ( pagecounter * MAXRESDISPLAY) - rescounter != 0) {
  
        tempcounter = (pagecounter * MAXRESDISPLAY) - MAXRESDISPLAY;
        dispmaxlines = rescounter - ((pagecounter-1) * MAXRESDISPLAY);
      }
      else {
  
        tempcounter = (pagenumber * MAXRESDISPLAY) - MAXRESDISPLAY;
        dispmaxlines = MAXRESDISPLAY;
      }
  } 

  if(strcmp(sorting, "desc") == 0) {

    if(rescounter <= MAXRESDISPLAY) {
       dispmaxlines = rescounter;
       tempcounter = rescounter;
    }
    else 
      if(pagenumber == pagecounter &&
             ( pagecounter * MAXRESDISPLAY) - rescounter != 0) {
  
        tempcounter = rescounter - ((pagecounter-1) * MAXRESDISPLAY);
        dispmaxlines = rescounter - ((pagecounter-1) * MAXRESDISPLAY);
      }
      else {
  
        tempcounter = rescounter - (pagenumber * MAXRESDISPLAY) + MAXRESDISPLAY;
        dispmaxlines = MAXRESDISPLAY;
      }
  }

/* -------------------------------------------------------------------------- *
 * start the html output                                                      *
 * ---------------------------------------------------------------------------*/

   pagehead(title, NULL, cgiOut);

/* -------------------------------------------------------------------------- *
 * start the form output                                                      *
 * ---------------------------------------------------------------------------*/

  fprintf(cgiOut, "<table width=\"100%%\">");
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th width=\"5\">");
  fprintf(cgiOut, "#");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<th width=\"270\">");
  fprintf(cgiOut, "Scan Session");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<th width=\"185\">");
  fprintf(cgiOut, "Scan Date");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<th width=\"100\" nowrap>");
  fprintf(cgiOut, "Scan Target");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<th width=\"35\">");
  fprintf(cgiOut, "View");
  fprintf(cgiOut, "</th>\n");

  for(dispcounter=0; dispcounter < dispmaxlines; dispcounter++) {

    if(strcmp(sorting, "desc") == 0) tempcounter--;

    /* dis-assemble the session id into its time and ip values */
    strncpy(resultsfilestr, resultsdir_list[tempcounter]->d_name,
                                              sizeof(resultsfilestr));

    /* split the filename */
    buf_ptr = strchr(resultsfilestr, '-') + 1;
    strncpy(timestamp, buf_ptr, strcspn(buf_ptr, "_"));
    buf_ptr = strchr(resultsfilestr, '_') + 1;
    strncpy(targetdec_ip, buf_ptr, sizeof(targetdec_ip));
    /* here we blend out the .htm extension in targetdec_ip */
    *strchr(targetdec_ip, '.') = '\0';

    /* convert the decimal IP back into dotted format */
    target_ip.s_addr=atoi(targetdec_ip);
    strncpy(targetdot_ip, inet_ntoa(target_ip), sizeof(targetdot_ip));

    /* convert the timestamp into a human readable string */
    strptime(timestamp, "%s", &scantime);
    strftime(scantimestr, sizeof(scantimestr), "%B, %d. %Y %T",
                                                           &scantime);
    free(resultsdir_list[tempcounter]);

    fprintf(cgiOut, "<tr>");
    fprintf(cgiOut, "<th>");
    fprintf(cgiOut, "%d", tempcounter+1);
    fprintf(cgiOut, "</th>\n");

    if( tempcounter == 1 || (tempcounter % 2) != 0 )
       strncpy(altcolor, "class=\"even\"", sizeof(altcolor));
    else
       strncpy(altcolor, "class=\"odd\"", sizeof(altcolor));

    fprintf(cgiOut, "<td %s>", altcolor);
    fprintf(cgiOut, "%s\n", resultsfilestr);
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<td %s>", altcolor);
    fprintf(cgiOut, "%s\n", scantimestr);
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<td %s>", altcolor);
    fprintf(cgiOut, "%s\n", targetdot_ip);
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<form><th>");
    fprintf(cgiOut, "<input type=\"button\" value=\"View\" ");
    fprintf(cgiOut, "onClick=\"parent.location='%s/%s'\">", RESULTS_DIR, resultsfilestr);
    fprintf(cgiOut, "</th></form>\n");
    fprintf(cgiOut, "</tr>");

    if(strcmp(sorting, "asc") == 0) tempcounter++;
  } 

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th colspan=\"6\">");
  fprintf(cgiOut, "Total # of results: %d - ", rescounter);
  fprintf(cgiOut, "Page %d of %d", pagenumber, pagecounter);
  fprintf(cgiOut, "</th>");
  fprintf(cgiOut, "</tr>");
  fprintf(cgiOut, "</table>\n");

  fprintf(cgiOut, "<p>");
  fprintf(cgiOut, "<table width=\"100%%\">");
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<form action=\"scanresults.cgi\" method=\"post\">");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"sort\" ");
  fprintf(cgiOut, "value=\"desc\">\n");
  fprintf(cgiOut, "<th>");
  fprintf(cgiOut, "<input type=\"submit\" name=\"sort\"");
  fprintf(cgiOut, " value=\"Latest Results first\">");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "</form>");
  fprintf(cgiOut, "<form action=\"scanresults.cgi\" method=\"post\">");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"sort\" ");
  fprintf(cgiOut, "value=\"asc\">\n");
  fprintf(cgiOut, "<th>");
  fprintf(cgiOut, "<input type=\"submit\" name=\"sort\"");
  fprintf(cgiOut, " value=\"Oldest Results first\">");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "</form>");
  fprintf(cgiOut, "<th width=40>");
  fprintf(cgiOut, "&nbsp;");
  fprintf(cgiOut, "</th>\n");
  // goto page 1
  fprintf(cgiOut, "<form action=\"scanresults.cgi\" method=\"post\">");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"sort\" ");
  fprintf(cgiOut, "value=\"");
  fprintf(cgiOut, "%s", sorting);
  fprintf(cgiOut, "\">\n");
  fprintf(cgiOut, "<th width=10>");
  fprintf(cgiOut, "<input type=\"submit\" value=\"<<\">");
  fprintf(cgiOut, "</th>");
  fprintf(cgiOut, "</form>");
  // goto page before
  fprintf(cgiOut, "<form action=\"scanresults.cgi\" method=\"post\">");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"sort\" ");
  fprintf(cgiOut, "value=\"");
  fprintf(cgiOut, "%s", sorting);
  fprintf(cgiOut, "\">\n");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"page\" ");
  fprintf(cgiOut, "value=\"");
  tempcounter = 0;
  if(pagenumber > 1) tempcounter = pagenumber - 1;
  else tempcounter = 1;
  fprintf(cgiOut, "%d", tempcounter);
  fprintf(cgiOut, "\">\n");
  fprintf(cgiOut, "<th width=10>");
  fprintf(cgiOut, "<input type=\"submit\" value=\"<\">");
  fprintf(cgiOut, "</th>");
  fprintf(cgiOut, "</form>");
  // goto page after
  fprintf(cgiOut, "<form action=\"scanresults.cgi\" method=\"post\">");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"sort\" ");
  fprintf(cgiOut, "value=\"");
  fprintf(cgiOut, "%s", sorting);
  fprintf(cgiOut, "\">\n");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"page\" ");
  fprintf(cgiOut, "value=\"");
  tempcounter = 0;
  if(pagecounter > pagenumber) tempcounter = pagenumber + 1;
  else tempcounter = pagecounter;
  fprintf(cgiOut, "%d", tempcounter);
  fprintf(cgiOut, "\">\n");
  fprintf(cgiOut, "<th width=10>");
  fprintf(cgiOut, "<input type=\"submit\" value=\">\">");
  fprintf(cgiOut, "</th>");
  fprintf(cgiOut, "</form>");
  // goto last page
  fprintf(cgiOut, "<form action=\"scanresults.cgi\" method=\"post\">");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"sort\" ");
  fprintf(cgiOut, "value=\"");
  fprintf(cgiOut, "%s", sorting);
  fprintf(cgiOut, "\">\n");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"page\" ");
  fprintf(cgiOut, "value=\"");
  fprintf(cgiOut, "%d", pagecounter);
  fprintf(cgiOut, "\">\n");
  fprintf(cgiOut, "<th width=10>");
  fprintf(cgiOut, "<input type=\"submit\" value=\">>\">");
  fprintf(cgiOut, "</th>");
  fprintf(cgiOut, "</form>");
  fprintf(cgiOut, "<form action=\"scanresults.cgi\" method=\"post\">");
  fprintf(cgiOut, "<th width=10 nowrap>");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"sort\" ");
  fprintf(cgiOut, "value=\"");
  fprintf(cgiOut, "%s", sorting);
  fprintf(cgiOut, "\">\n");
  fprintf(cgiOut, "<input type=\"submit\" value=\"Goto\">");
  fprintf(cgiOut, "</th>");
  fprintf(cgiOut, "<th width=10 nowrap>");
  fprintf(cgiOut, "<input type=\"text\" name=\"page\" size=4 value=");
  fprintf(cgiOut, "%d>\n", pagecounter);
  fprintf(cgiOut, "</th>");
  fprintf(cgiOut, "</form>");
  fprintf(cgiOut, "</tr>\n");
  fprintf(cgiOut, "</table>\n");

/* -------------------------------------------------------------------------- *
 * end the html output                                                        *
 * ---------------------------------------------------------------------------*/

   pagefoot(NULL);
   return(0);
}
