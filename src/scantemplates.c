/* -------------------------------------------------------------------------- *
 * file:         scantemplates.c                                              *
 * purpose:      builds a list of scan template files in the template         *
 *               directory                                                    *
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

int templ_select(const struct dirent *entry);

int cgiMain() {

  static char 	title[] = "Scan Configuration Templates";
  char		sorting[16] = "desc";
  char          altcolor[16] = "class=\"odd\"";
  struct	dirent **templatedir_list;

  int pagenumber = 1;
  int rescounter = 0;
  int tempcounter = 0;
  int pagecounter = 0;
  int dispcounter = 0;
  int dispmaxlines = 0;
  div_t disp_calc;

/* -------------------------------------------------------------------------- *
 * Get the list of .rc files from the result directory                       *
 * ---------------------------------------------------------------------------*/
  rescounter = scandir(TEMPLATE_DIR, &templatedir_list,
                                                   templ_select, alphasort);

/* -------------------------------------------------------------------------- *
 * calculate how many pages we get with MAXRESDISPLAY                         *
 * ---------------------------------------------------------------------------*/

  if(rescounter<=MAXRESDISPLAY) pagecounter = 1;
  else {
    disp_calc = div(rescounter, MAXRESDISPLAY);
    pagecounter = disp_calc.quot +1;
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
 * now we know how many files we have in total and we can build the page(s).  *
 * For every MAXDISPLAY files we start a new page and cycle through by        *
 * calling ourself with the requested files range.                            *
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
  fprintf(cgiOut, "<th width=\"320\">");
  fprintf(cgiOut, "Name & Plugins [total/enabled]");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<th width=\"130\">");
  fprintf(cgiOut, "Template File");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<th width=\"170\" nowrap>");
  fprintf(cgiOut, "Creation Date");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "<th>");
  fprintf(cgiOut, "Select");
  fprintf(cgiOut, "</th>\n");

  for(dispcounter=0; dispcounter < dispmaxlines; dispcounter++) {

    if(strcmp(sorting, "desc") == 0) tempcounter--;

    fprintf(cgiOut, "<tr>");
    fprintf(cgiOut, "<th>");
    fprintf(cgiOut, "%d", tempcounter+1);
    fprintf(cgiOut, "</td>\n");

    if( tempcounter == 1 || (tempcounter % 2) != 0 )
       strncpy(altcolor, "class=\"even\"", sizeof(altcolor));
    else
       strncpy(altcolor, "class=\"odd\"", sizeof(altcolor));

    /* get the template file name here */
    strncpy(templatefilestr, templatedir_list[tempcounter]->d_name,
                                              sizeof(templatefilestr));
    free(templatedir_list[tempcounter]);

    get_template_name(templatefilestr);
    get_template_date(templatefilestr);
    get_template_plugs(templatefilestr);

    fprintf(cgiOut, "<td %s>", altcolor);
    fprintf(cgiOut, "<b>%s</b> [%d/%d]\n", template_name, template_plugs_all,
                          template_plugs_enabled);
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<td %s>", altcolor);
    fprintf(cgiOut, "%s\n", templatefilestr);
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<td %s>", altcolor);
    fprintf(cgiOut, "%s\n", template_date);
    fprintf(cgiOut, "</td>\n");
    fprintf(cgiOut, "<form method=post action=scanlogin.cgi>");
    fprintf(cgiOut, "<input type=\"hidden\" name=\"template\" ");
    fprintf(cgiOut, "value=\"%s\">\n", templatefilestr);
    fprintf(cgiOut, "<th>");
    fprintf(cgiOut, "<input type=\"submit\" value=\"Select\">");
    fprintf(cgiOut, "</th>\n");
    fprintf(cgiOut, "</form>");
    fprintf(cgiOut, "</tr>");

    if(strcmp(sorting, "asc") == 0) tempcounter++;
  } 

  if(rescounter == 0) {
    fprintf(cgiOut, "<tr><td colspan=\"6\"><p>No template files found.<p></td></tr>");
  }

  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th colspan=\"6\">");
  fprintf(cgiOut, "Total # of templates: %d - ", rescounter);
  fprintf(cgiOut, "Page %d of %d", pagenumber, pagecounter);
  fprintf(cgiOut, "</td>");
  fprintf(cgiOut, "</tr>");
  fprintf(cgiOut, "</table>\n");

  fprintf(cgiOut, "<p>");
  fprintf(cgiOut, "<table width=\"100%%\">");
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<form action=\"scanlogin.cgi\" method=\"post\">");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"template\" ");
  fprintf(cgiOut, "value=\"create\">\n");
  fprintf(cgiOut, "<th>");
  fprintf(cgiOut, "<input type=\"submit\" value=\"New Template\">");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "</form>");
  fprintf(cgiOut, "<form action=\"scantemplates.cgi\" method=\"post\">");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"sort\" ");
  fprintf(cgiOut, "value=\"desc\">\n");
  fprintf(cgiOut, "<th>");
  fprintf(cgiOut, "<input type=\"submit\" value=\"Show Latest\">");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "</form>");
  fprintf(cgiOut, "<form action=\"scantemplates.cgi\" method=\"post\">");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"sort\" ");
  fprintf(cgiOut, "value=\"asc\">\n");
  fprintf(cgiOut, "<th>");
  fprintf(cgiOut, "<input type=\"submit\" value=\"Show Oldest\">");
  fprintf(cgiOut, "</th>\n");
  fprintf(cgiOut, "</form>");
  // goto page 1
  fprintf(cgiOut, "<form action=\"scantemplates.cgi\" method=\"post\">");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"sort\" ");
  fprintf(cgiOut, "value=\"");
  fprintf(cgiOut, "%s", sorting);
  fprintf(cgiOut, "\">\n");
  fprintf(cgiOut, "<th width=10>");
  fprintf(cgiOut, "<input type=\"submit\" value=\"<<\">");
  fprintf(cgiOut, "</th>");
  fprintf(cgiOut, "</form>");
  // goto page before
  fprintf(cgiOut, "<form action=\"scantemplates.cgi\" method=\"post\">");
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
  fprintf(cgiOut, "<form action=\"scantemplates.cgi\" method=\"post\">");
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
  fprintf(cgiOut, "<form action=\"scantemplates.cgi\" method=\"post\">");
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
  fprintf(cgiOut, "<form action=\"scantemplates.cgi\" method=\"post\">");
  fprintf(cgiOut, "<th width=10 nowrap>");
  fprintf(cgiOut, "<input type=\"hidden\" name=\"sort\" ");
  fprintf(cgiOut, "value=\"");
  fprintf(cgiOut, "%s", sorting);
  fprintf(cgiOut, "\">\n");
  fprintf(cgiOut, "<input type=\"submit\" value=\"Goto\">");
  fprintf(cgiOut, "</th>");
  fprintf(cgiOut, "<th width=10 nowrap>");
  fprintf(cgiOut, "<input type=\"text\" name=\"page\" size=2 value=");
  fprintf(cgiOut, "%d>\n", pagecounter);
  fprintf(cgiOut, "</th>");
  fprintf(cgiOut, "</form>");
  fprintf(cgiOut, "</tr>\n");
  fprintf(cgiOut, "</table>\n");

/* -------------------------------------------------------------------------- *
 * end the html output                                                        *
 * ---------------------------------------------------------------------------*/

   pagefoot(NULL);
   fclose(cgiOut);
   return(0);
}
