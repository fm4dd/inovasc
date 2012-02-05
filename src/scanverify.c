/* -------------------------------------------------------------------------- *
 * file:         scanverify.c                                                 *
 * purpose:      scanner server login and plugin retrieval, display of the    *
 *               scan configuration loaded from the scan template.            *
 * ---------------------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <cgic.h>

#include "inovasc.h"

int cgiMain() {

   char 	title[256] = "";
   char		ip[16];
   int		port;
   char         formbuf[2];
   char		user[81] = "";
   char		pass[81] = "";
   char		cert[81] = "";
   char		encr[81] = "";
   char		session_name[81] = "";
   int		prefs_counter = 0;
   int		rules_counter = 0;
   int		pdeps_counter = 0;
   int		famly_enabled = 0;
   int		enabled_counter = 0;
   SSL		*ssl;
   int 		i = 0, j = 0, k = 0;

/* -------------------------------------------------------------------------- *
 * check if we got a template filename or a session name for a new template   *
 * ---------------------------------------------------------------------------*/

  if ( cgiFormString("template", templatefilestr, sizeof(templatefilestr))
                                                        == cgiFormSuccess ) {
     get_template_name(templatefilestr);
     snprintf(title, sizeof(title),
              "Scanner Configuration for<br> Template \"%s\"", template_name);
     get_template_prefs(templatefilestr);
     get_template_plugs(templatefilestr);
  } else {
    if ( cgiFormString("s-name", session_name, sizeof(session_name))
                                                        == cgiFormNotFound )
       int_error("Template filename or session name must be set."); 
    if ( strcmp(session_name, "") == 0 )
       int_error("Session name empty, must be set in scanconfig.cgi."); 
  }

/* -------------------------------------------------------------------------- *
 * check if we got all information to make a scanner server connection        *
 * ---------------------------------------------------------------------------*/

  if ( cgiFormString("ip", ip, sizeof(ip)) != cgiFormSuccess )
    int_error("Cannot retrieve the scanner server IP address.");

  if ( cgiFormInteger("port", &port, SCANNER_PORT) != cgiFormSuccess )
    int_error("Cannot retrieve the scanner server port number.");

  if ( port <= 0 || port > 65535 )
    int_error("The scan server port number is not in a valid port range.");

  if ( cgiFormString("encr", encr, sizeof(encr)) != cgiFormSuccess )
    int_error("Cannot retrieve the scanner server protocol encryption type.");

  if ( cgiFormString("user", user, sizeof(user)) != cgiFormSuccess )
    int_error("Cannot retrieve the scanner server remote user name.");

  if ( cgiFormString("pass", pass, sizeof(pass)) != cgiFormSuccess )
    int_error("Cannot retrieve the scanner server remote user password.");

  if ( cgiFormString("cert", cert, sizeof(cert)) != cgiFormSuccess )
    int_error("Cannot retrieve the client certificate name.");
  
/* -------------------------------------------------------------------------- *
 * make a SSL connection to the scanner server.                               *
 * ---------------------------------------------------------------------------*/

  ssl = scanner_connect(ip, port, encr, cert);

/* -------------------------------------------------------------------------- *
 * Handle the login to the scanner server.                                    *
 * ---------------------------------------------------------------------------*/

  scanner_login(ssl, user, pass);

/* -------------------------------------------------------------------------- *
 * Get the list of plugins from the scanner server and                        *
 * create the list of categories.                                             *
 * ---------------------------------------------------------------------------*/

  plugs_counter = 0;
  plugs_counter = scanner_getplugs(ssl);
  if (plugs_counter == 0)
     int_error("Could not receive plugins from the scanner server.");

  scanner_getgroups();

/* -------------------------------------------------------------------------- *
 * Get the preferences list from the scanner server.                          *
 * ---------------------------------------------------------------------------*/

  prefs_counter = scanner_getprefs(ssl);
  if (prefs_counter == 0)
     int_error("Could not receive preferences from the scanner server.");

/* -------------------------------------------------------------------------- *
 * Get the rules list from the scanner server.                                *
 * ---------------------------------------------------------------------------*/

  rules_counter = scanner_getrules(ssl);
  /* it isn't unusual to have no rules so the count can be zero. */

/* -------------------------------------------------------------------------- *
 * Get the preferences dependency list from the OpenVAS Server.               *
 * ---------------------------------------------------------------------------*/

  pdeps_counter = scanner_getpdeps(ssl);

/* -------------------------------------------------------------------------- *
 * If session_name is set, create a new template file                         *
 * ---------------------------------------------------------------------------*/

  if(strcmp(session_name, "") != 0) {

    /* collect the enabled family info from scanconfig.cgi */
    for(i=0; i<famly_counter; i++) {
      if (cgiFormString(famlylist[i].name, formbuf, sizeof(formbuf))
                                                         != cgiFormNotFound) {
        famlylist[i].enabled = 1;
        famly_enabled++;
      }
    }
    if (famly_enabled == 0)
      int_error("No plugin family had been selected. Choose at least one.");

    write_template_file(new_template_file(), session_name, prefs_counter, famly_counter);

    get_template_name(templatefilestr);
    snprintf(title, sizeof(title),
         "Created Scanner Configuration<br>for Template \"%s\"", template_name);
    get_template_prefs(templatefilestr);
    get_template_plugs(templatefilestr);
  }

/* -------------------------------------------------------------------------- *
 * start the html output                                                      *
 * ---------------------------------------------------------------------------*/

   pagehead(title, NULL, cgiOut);

/* -------------------------------------------------------------------------- *
 * start the form output                                                      *
 * ---------------------------------------------------------------------------*/

 /* debug code: show all template plugin ids and their enabled status */
 //  fprintf(cgiOut, "Session Name: %s <br>", session_name);
 //  fprintf(cgiOut, "Template Name: %s <br>", templatefilestr);
 // { int i =0;
 //   for(i=0; i<template_plugs_all; i++)
 //    fprintf(cgiOut,"#: %d, id: [%s] en: [%d]<br>",i,template_plug_list[i].id,
 //      template_plug_list[i].enabled);
 // }

   fprintf(cgiOut, "<form action=\"scanprocess.cgi\" method=\"post\">");
   /* forward the login information to the next cgi */
   fprintf(cgiOut, "<input type=hidden name=ip value=%s>", ip);
   fprintf(cgiOut, "<input type=hidden name=port value=%d>", port);
   fprintf(cgiOut, "<input type=hidden name=encr value=%s>", encr);
   fprintf(cgiOut, "<input type=hidden name=user value=%s>", user);
   fprintf(cgiOut, "<input type=hidden name=pass value=%s>", pass);
   fprintf(cgiOut, "<input type=hidden name=cert value=%s>", cert);

   fprintf(cgiOut, "<table width=\"100%%\">");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th colspan=4>");
   fprintf(cgiOut, "Scan Target IP Address and optional Login Credentials");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<td bgcolor=CFCFCF align=\"center\">");
   fprintf(cgiOut, "IP Address:");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td align=\"center\">");
   fprintf(cgiOut, "<input type=text name=t-ip size=15 maxlength=15 value=%s>",
           DEFAULT_TARGET_IP);
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td bgcolor=CFCFCF align=\"center\">");
   fprintf(cgiOut, "Credentials:");
   fprintf(cgiOut, "</td>");

   fprintf(cgiOut, "<td align=\"center\">");
   fprintf(cgiOut, "<select name=\"c-type\">");
   fprintf(cgiOut, "<option value=\"none\" selected>No Credentials</option>");
   fprintf(cgiOut, "<option value=\"ssh-pass\">SSH Passphrase</option>");
   fprintf(cgiOut, "<option value=\"smb-pass\">SMB User Login</option></select>");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "</tr>\n");

   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<td bgcolor=CFCFCF align=\"center\">");
   fprintf(cgiOut, "User Name:");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td align=\"center\">");
   fprintf(cgiOut, "<input type=text name=c-user size=15 maxlength=15>");
   fprintf(cgiOut, "</td>");

   fprintf(cgiOut, "<td bgcolor=CFCFCF align=\"center\">");
   fprintf(cgiOut, "Passphrase:");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td align=\"center\">");
   fprintf(cgiOut, "<input type=password name=c-pass size=18 maxlength=30>");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th colspan=4>");
   fprintf(cgiOut, "<input type=\"submit\" value=\"Start Scan\">");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>");
   fprintf(cgiOut, "</table>");
   fprintf(cgiOut, "<input type=hidden name=template value=%s>", templatefilestr);
   fprintf(cgiOut, "</form><p>");

   fprintf(cgiOut, "<table width=\"100%%\">");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th colspan=4>");
   fprintf(cgiOut, "Scanner Plugin Family List");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>");
   fprintf(cgiOut, "<tr>");

   for(i=0; i<famly_counter; i++) {

    /* check for each family, how many of the enabled template    *
     * plugins match the plugin list for this family and increase *
     * the enabled_counter with each hit.                         */

     enabled_counter = 0;
     for(j=0; j<famlylist[i].plugscount; j++) {
       for(k=0; k<template_plugs_all; k++) {
         if( strcmp(famlylist[i].plugs_ptr[j]->id,
             template_plug_list[k].id) == 0
             &&
             template_plug_list[k].enabled == 1 )
           enabled_counter++;
       }
     }

     if(enabled_counter > 0) {
       famly_enabled++;
       fprintf(cgiOut, "<td bgcolor=FFFFFF>");
     }
     else
       fprintf(cgiOut, "<td bgcolor=CFCFCF>");

     fprintf(cgiOut, "%s", famlylist[i].name);
     fprintf(cgiOut, "</td>");
     if(enabled_counter > 0) fprintf(cgiOut, "<td style=\"text-align: right;\">");
     else fprintf(cgiOut, "<td bgcolor=CFCFCF style=\"text-align: right;\">");
     fprintf(cgiOut, "%d/%d", enabled_counter, famlylist[i].plugscount);
     fprintf(cgiOut, "</td>");

    /* we want to display 2 columns of 2 cells (Family Name | Plugin Count) *
     * to shorten the length of the overall Family list.                    */
     if( i == 1 || (i % 2) != 0 ) fprintf(cgiOut, "</tr><tr>\n");

   }

   /* if famly_counter is a uneven number we miss a cell at the last row *
    * so we better insert a "dummy".                                     */
   if( (famly_counter % 2) != 0 ) {
      fprintf(cgiOut, "<td bgcolor=CFCFCF colspan=2>&nbsp;</td>\n");
   }
   fprintf(cgiOut, "</tr>");
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th colspan=4>");
   fprintf(cgiOut, "Total: %d Plugins", plugs_counter );
   fprintf(cgiOut, " in %d Families.", famly_counter );
   fprintf(cgiOut, " Enabled: %d Plugins", template_plugs_enabled );
   fprintf(cgiOut, " in %d Families.", famly_enabled );
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>");
   fprintf(cgiOut, "</table>\n");

   fprintf(cgiOut, "<p>");
   fprintf(cgiOut, "<table width=\"100%%\">\n");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th colspan=2>INOVASC Client</th>");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<td bgcolor=\"#CFCFCF\" width=180>");
   fprintf(cgiOut, "Version:");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td>%s</td>\n", CLIENT_SW_VERSION);
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<td bgcolor=CFCFCF>Copyright:</td>");
   fprintf(cgiOut, "<td>%s</td>\n", CLIENT_COPYRIGHTS);
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<td bgcolor=CFCFCF>Status:</td>");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<b>%s</b> login to server <b>%s</b> successful.",
                    user, ip);
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th colspan=2>&nbsp;</th>");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "</table>\n");

/* -------------------------------------------------------------------------- *
 * end the html output                                                        *
 * ---------------------------------------------------------------------------*/

   pagefoot(NULL);
   fclose(cgiOut);
   return(0);
}
