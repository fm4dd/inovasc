/* -------------------------------------------------------------------------- *
 * file:         scanconfig.c                                                 *
 * purpose:      scan server login and plugin retrieval                       *
 * ---------------------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <cgic.h>

#include "inovasc.h"

int cgiMain() {

  static char 	title[] = "Create a new Scan Configuration";
  char		ip[16];
  int		port;
  char		user[81];
  char		pass[81];
  char		cert[81];
  char		encr[81];
  int		prefs_counter = 0;
  int		rules_counter = 0;
  int		pdeps_counter = 0;
  int		even_counter = 0;
  int		odd_counter = 0;
  SSL		*ssl;
  int 		i = 0;
  char          altcolor[16] = "class=\"odd\"";

#ifdef DEBUG
  char          error_string[255] = "";

  if(! (debugfile = fopen(DEBUGFILE, "w"))) {
    snprintf(error_string, sizeof(error_string),
           "Cannot open debug file %s for writing.", DEBUGFILE);
    int_error(error_string);
  }
#endif

/* -------------------------------------------------------------------------- *
 * check if we got called from scantemplates to create a  new template file   *
 * ---------------------------------------------------------------------------*/

 cgiFormString("template", templatefilestr, sizeof(templatefilestr));

/* -------------------------------------------------------------------------- *
 * check if we got all information to make a scan server connection           *
 * ---------------------------------------------------------------------------*/

  if ( cgiFormString("ip", ip, sizeof(ip)) != cgiFormSuccess )
    int_error("Error retrieving OpenVAS server IP address.");

  if ( cgiFormInteger("port", &port, SCANNER_PORT) != cgiFormSuccess )
    int_error("Error retrieving OpenVAS server port number.");

  if ( port <= 0 || port > 65535 )
    int_error("Error OpenVAS server port number not in a valid port range.");

  if ( cgiFormString("encr", encr, sizeof(encr)) != cgiFormSuccess )
    int_error("Error retrieving OpenVAS server protocol encryption type.");

  if ( cgiFormString("user", user, sizeof(user)) != cgiFormSuccess )
    int_error("Error retrieving OpenVAS remote user name.");

  if ( cgiFormString("pass", pass, sizeof(pass)) != cgiFormSuccess )
    int_error("Error retrieving OpenVAS remote user password.");

  if ( cgiFormString("cert", cert, sizeof(cert)) != cgiFormSuccess )
    int_error("Error retrieving OpenVAS client certificate name.");
  
/* -------------------------------------------------------------------------- *
 * make a SSL connection to the OpenVAS Server.                               *
 * ---------------------------------------------------------------------------*/

  ssl = scanner_connect(ip, port, encr, cert);

/* -------------------------------------------------------------------------- *
 * Handle the login to the OpenVAS Server.                                    *
 * ---------------------------------------------------------------------------*/

  scanner_login(ssl, user, pass);

/* -------------------------------------------------------------------------- *
 * Get the list of plugins from the OpenVAS Server and                        *
 * create the list of categories.                                             *
 * ---------------------------------------------------------------------------*/

  plugs_counter = 0;
  plugs_counter = scanner_getplugs(ssl);
  if (plugs_counter == 0)
     int_error("Error: Could not receive plugins from OpenVAS server.");

  scanner_getgroups();

/* -------------------------------------------------------------------------- *
 * Get the preferences list from the OpenVAS Server.                          *
 * ---------------------------------------------------------------------------*/

  prefs_counter = scanner_getprefs(ssl);
  if (prefs_counter == 0)
     int_error("Could not receive preferences from OpenVAS server.");

/* -------------------------------------------------------------------------- *
 * Get the rules list from the OpenVAS Server.                                *
 * ---------------------------------------------------------------------------*/

  rules_counter = scanner_getrules(ssl);
  /* it isn't unusual to have no rules so the count can be zero. */

/* -------------------------------------------------------------------------- *
 * Get the preferences dependency list from the OpenVAS Server.               *
 * ---------------------------------------------------------------------------*/

  pdeps_counter = scanner_getpdeps(ssl);

/* -------------------------------------------------------------------------- *
 * start the html output                                                      *
 * ---------------------------------------------------------------------------*/

  pagehead(title, NULL, cgiOut);

/* -------------------------------------------------------------------------- *
 * start the form output                                                      *
 * ---------------------------------------------------------------------------*/

  if(strcmp(templatefilestr, "create") == 0)
    fprintf(cgiOut, "<form action=\"scanverify.cgi\" method=\"post\">");
  else
    fprintf(cgiOut, "<form action=\"scanprocess.cgi\" method=\"post\">");

  fprintf(cgiOut, "<table width=\"100%%\">");
  fprintf(cgiOut, "<tr>\n");


  if(strcmp(templatefilestr, "create") == 0) {
    fprintf(cgiOut, "<th colspan=2>");
    fprintf(cgiOut, "New OpenVAS Scan Template");
    fprintf(cgiOut, "</th>");
    fprintf(cgiOut, "</tr>");
    fprintf(cgiOut, "<td bgcolor=CFCFCF align=\"center\" bordercolor=CFCFCF");
    fprintf(cgiOut, " width=270>");
    fprintf(cgiOut, "Configuration Name:");
    fprintf(cgiOut, "</td>");
    fprintf(cgiOut, "<td align=\"center\">");
    fprintf(cgiOut, "<input type=text name=s-name size=35 maxlength=35>");
    fprintf(cgiOut, "</td>");
    fprintf(cgiOut, "</tr>");
    fprintf(cgiOut, "<tr>\n");
    fprintf(cgiOut, "<th colspan=2>");
    fprintf(cgiOut, "<input type=\"submit\" value=\"Save Template\">");
    fprintf(cgiOut, "</th>");
  }
  else {
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
  }
  fprintf(cgiOut, "</tr>");
  fprintf(cgiOut, "</table>");

  /* forward login information to either scanprocess.cgi or scanverify.cgi */
  fprintf(cgiOut,"<input type=hidden name=ip value=%s>",ip);
  fprintf(cgiOut,"<input type=hidden name=port value=%d>",port);
  fprintf(cgiOut,"<input type=hidden name=encr value=%s>",encr);
  fprintf(cgiOut,"<input type=hidden name=user value=%s>",user);

  /* Escape the password string, it can contain HTML reserved chars like '>' */
  fprintf(cgiOut,"<input type=hidden name=pass value=");
  cgiHtmlEscape(pass);
  fprintf(cgiOut,">");

  fprintf(cgiOut,"<input type=hidden name=cert value=%s>",cert);

  fprintf(cgiOut, "<p>");
  fprintf(cgiOut, "<table width=\"100%%\">");
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th colspan=6>");
  fprintf(cgiOut, "OpenVAS Scanner Plugin Family List");
  fprintf(cgiOut, "</th>");
  fprintf(cgiOut, "</tr>");
  fprintf(cgiOut, "<tr>");

  for(i=0; i<famly_counter; i++) {

    fprintf(cgiOut, "<td bgcolor=CFCFCF align=\"center\" bordercolor=CFCFCF>");
    fprintf(cgiOut, "<input type=checkbox name=\"%s\">", famlylist[i].name);
    fprintf(cgiOut, "</td>");

    if( i == 1 || (i % 2) != 0 ) {
      if ( odd_counter == 1 || (odd_counter % 2) != 0 )
        strncpy(altcolor, "class=\"odd\"", sizeof(altcolor));
      else
        strncpy(altcolor, "class=\"even\"", sizeof(altcolor));
      odd_counter++;
    } else {
      if ( even_counter == 1 || (even_counter % 2) != 0 )
        strncpy(altcolor, "class=\"odd\"", sizeof(altcolor));
      else
        strncpy(altcolor, "class=\"even\"", sizeof(altcolor));
      even_counter++;
    }

    fprintf(cgiOut, "<td %s>", altcolor);
    fprintf(cgiOut, "%s", famlylist[i].name);
    fprintf(cgiOut, "</td>");

    fprintf(cgiOut, "<td %s style=\"text-align: right;\">", altcolor);
    fprintf(cgiOut, "%d", famlylist[i].plugscount);
    fprintf(cgiOut, "</td>");

   /* we want to display 2 columns of 3 cells (checkbox | Family Name | *
    * Plugin Count) to shorten the length of the overall Family list.   */
    if( i == 1 || (i % 2) != 0 ) fprintf(cgiOut, "</tr><tr>\n");

  }

  /* if famly_counter is a uneven number we miss a cell at the last row *
   * so we better insert a "dummy".                                     */
  if( (famly_counter % 2) != 0 ) {
     fprintf(cgiOut, "<td bgcolor=CFCFCF bordercolor=CFCFCF>&nbsp;</td>\n");
     fprintf(cgiOut, "<td bgcolor=FFFFFF colspan=2>&nbsp;</td>\n");
  }
  fprintf(cgiOut, "</tr>");
  fprintf(cgiOut, "<tr>");
  fprintf(cgiOut, "<th colspan=6>");
  fprintf(cgiOut, "Total: %d Plugins", plugs_counter );
  fprintf(cgiOut, " in %d Families.", famly_counter );
  fprintf(cgiOut, "</th>");
  fprintf(cgiOut, "</tr>");
  fprintf(cgiOut, "</table>\n");
  fprintf(cgiOut, "</form>");

  fprintf(cgiOut, "<p>");
  fprintf(cgiOut, "<table width=\"100%%\">");
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th colspan=2>");
  fprintf(cgiOut, "INOVASC Client");
  fprintf(cgiOut, "</th>");
  fprintf(cgiOut, "</tr>");
  fprintf(cgiOut, "<tr>");
  fprintf(cgiOut, "<td align=\"center\" bgcolor=\"#CFCFCF\"");
  fprintf(cgiOut, "bordercolor=\"#CFCFCF\" width=180>");
  fprintf(cgiOut, "Version:");
  fprintf(cgiOut, "</td>");
  fprintf(cgiOut, "<td align=\"center\"bgcolor=\"#FFFFFF\">");
  fprintf(cgiOut, "%s\n", CLIENT_SW_VERSION);
  fprintf(cgiOut, "</td>");
  fprintf(cgiOut, "</tr>\n");
  fprintf(cgiOut, "<tr>");
  fprintf(cgiOut, "<td align=\"center\" bgcolor=CFCFCF bordercolor=CFCFCF>");
  fprintf(cgiOut, "Copyright:");
  fprintf(cgiOut, "</td>");
  fprintf(cgiOut, "<td align=\"center\"bgcolor=\"#FFFFFF\">");
  fprintf(cgiOut, "%s\n", CLIENT_COPYRIGHTS);
  fprintf(cgiOut, "</td>");
  fprintf(cgiOut, "</tr>");
  fprintf(cgiOut, "<tr>");
  fprintf(cgiOut, "<td align=\"center\" bgcolor=CFCFCF bordercolor=CFCFCF>");
  fprintf(cgiOut, "Status:");
  fprintf(cgiOut, "</td>");
  fprintf(cgiOut, "<td align=\"center\"bgcolor=\"#FFFFFF\">");
  fprintf(cgiOut, "<b>%s</b> login to server <b>%s</b> successful.",
                   user, ip);
  fprintf(cgiOut, "</td>");
  fprintf(cgiOut, "</tr>");
  fprintf(cgiOut, "<tr>\n");
  fprintf(cgiOut, "<th colspan=2>");
  fprintf(cgiOut, "&nbsp;");
  fprintf(cgiOut, "</th>");
  fprintf(cgiOut, "</tr>");
  fprintf(cgiOut, "</table>\n");

/* -------------------------------------------------------------------------- *
 * end the html output                                                        *
 * ---------------------------------------------------------------------------*/

  pagefoot(NULL);
#ifdef DEBUG
  if(debugfile != NULL) fclose(debugfile);
#endif
  fclose(cgiOut);
  return(0);
}
