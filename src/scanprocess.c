/* -------------------------------------------------------------------------- *
 * file:         scanprocess.c                                                *
 * purpose:      start the scan and retrieve the scanner output               *
 * ---------------------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <cgic.h>

#include "inovasc.h"

int cgiMain() {
  char		ip[16];
  int		port;
  char		user[81];
  char		pass[81];
  char		cert[81];
  char		encr[81];
  char		target_ip[16];
  char		cred_type[16];
  char		cred_user[16];
  char		cred_pass[31];
  char		*session_id;
  SSL		*ssl;
  static char 	title[] = "Scanning Progress";
  char		formbuf[3];
  int		prefs_counter = 0;
  int		rules_counter = 0;
  int		pdeps_counter = 0;
  int		famly_enabled = 0;
  int		plugs_enabled = 0;
  int 		i = 0, j = 0, k = 0;

#ifdef DEBUG
  char         error_string[255] = "";

  if(! (debugfile = fopen(DEBUGFILE, "w"))) {
    snprintf(error_string, sizeof(error_string),
           "Cannot open debug file %s for writing.", DEBUGFILE);
    int_error(error_string);
  }
#endif

/* -------------------------------------------------------------------------- *
 * check if we got all information to make a scanner server connection        *
 * ---------------------------------------------------------------------------*/

  if ( cgiFormString("ip", ip, sizeof(ip)) != cgiFormSuccess )
    int_error("Error retrieving scan server IP address.");

  if ( cgiFormInteger("port", &port, SCANNER_PORT) != cgiFormSuccess )
    int_error("Error retrieving scan server port number.");

  if ( port <= 0 || port > 65535 )
    int_error("Error scan server port number not in a valid port range.");

  if ( cgiFormString("encr", encr, sizeof(encr)) != cgiFormSuccess )
    int_error("Error retrieving scan server protocol encryption type.");

  if ( cgiFormString("user", user, sizeof(user)) != cgiFormSuccess )
    int_error("Error retrieving scan server remote user name.");

  if ( cgiFormString("pass", pass, sizeof(pass)) != cgiFormSuccess )
    int_error("Error retrieving scan server remote user password.");

  if ( cgiFormString("cert", cert, sizeof(cert)) != cgiFormSuccess )
    int_error("Error retrieving the clients certificate name.");
  
  if ( cgiFormString("t-ip", target_ip, sizeof(target_ip)) != cgiFormSuccess )
    int_error("Error retrieving the clients scan target IP address.");
  
  if ( cgiFormString("c-type", cred_type, sizeof(cred_type)) != cgiFormSuccess )
    int_error("Error retrieving the choice of a credentials scan.");

  if(strcmp(cred_type, "ssh-pass") == 0 || strcmp(cred_type, "smb-pass") == 0) {
    if ( cgiFormString("c-user", cred_user, sizeof(cred_user)) != cgiFormSuccess )
      int_error("Error retrieving the username for a credentials scan.");
    if ( cgiFormString("c-pass", cred_pass, sizeof(cred_pass)) != cgiFormSuccess )
      int_error("Error retrieving the passphrase for a credentials scan.");
  }
  
#ifdef DEBUG
  if(debugfile != NULL) fputs("\nscanprocess.cgi start:", debugfile);
  if(debugfile != NULL) fputs("\n Scanner Addr: ", debugfile);
  if(debugfile != NULL) fputs(ip, debugfile);
  if(debugfile != NULL) fputs("\n Scanner Port: ", debugfile);
  snprintf(error_string, sizeof(error_string), "%d", port);
  if(debugfile != NULL) fputs(error_string, debugfile);
  if(debugfile != NULL) fputs("\n Scanner Encr: ", debugfile);
  if(debugfile != NULL) fputs(encr, debugfile);
  if(debugfile != NULL) fputs("\n Scanner User: ", debugfile);
  if(debugfile != NULL) fputs(user, debugfile);
  if(debugfile != NULL) fputs("\n Scanner Pass: ", debugfile);
  if(debugfile != NULL) fputs(pass, debugfile);
  if(debugfile != NULL) fputs("\n Scanner Cert: ", debugfile);
  if(debugfile != NULL) fputs(cert, debugfile);
  if(debugfile != NULL) fputs("\n  Target Addr: ", debugfile);
  if(debugfile != NULL) fputs(target_ip, debugfile);
  if(debugfile != NULL) fputs("\n   Creds Type: ", debugfile);
  if(debugfile != NULL) fputs(cred_type, debugfile);
  if(debugfile != NULL) fputs("\n   Creds User: ", debugfile);
  if(debugfile != NULL) fputs(cred_user, debugfile);
  if(debugfile != NULL) fputs("\n   Creds Pass: ", debugfile);
  if(debugfile != NULL) fputs(cred_pass, debugfile);
  if(debugfile != NULL) fputs("\nscanprocess parameters complete.\n\n", debugfile);
#endif

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
     int_error("Could not receive plugins from the scan server.");

  scanner_getgroups();

/* -------------------------------------------------------------------------- *
 * Get the preferences list from the scanner server.                          *
 * ---------------------------------------------------------------------------*/

  prefs_counter = scanner_getprefs(ssl);
  if (prefs_counter == 0)
     int_error("Could not receive preferences from the scan server.");

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
 * Here we process the prefs and plugins before we can return the list        *
 * ---------------------------------------------------------------------------*/
#ifdef DEBUG
  if(debugfile != NULL) fputs("\nscanprocess.cgi start", debugfile);
#endif

  if (cgiFormString("template", templatefilestr, sizeof(templatefilestr))
                                                         == cgiFormNotFound) {
    /* If no template was given, collect all plugin groups from CGI form */
    for(i=0; i<famly_counter; i++) {
      if (cgiFormString(famlylist[i].name, formbuf, sizeof(formbuf))
                                                         != cgiFormNotFound) {

#ifdef DEBUG
        if(debugfile != NULL) fputs("\n Family selected: ", debugfile);
        if(debugfile != NULL) fputs(famlylist[i].name, debugfile);
        snprintf(error_string, sizeof(error_string), " [%d plugins]", famlylist[i].plugscount);
        if(debugfile != NULL) fputs(error_string, debugfile);
#endif
        famlylist[i].enabled = 1;
        plugs_enabled = plugs_enabled + famlylist[i].plugscount;
        famly_enabled++;
      }
    }
    if (famly_enabled == 0)
      int_error("No plugin family had been selected. Choose at least one.");

  } else {
    /* load the template information */
    get_template_name(templatefilestr);
    get_template_prefs(templatefilestr);
    get_template_plugs(templatefilestr);

    if(template_plugs_enabled == 0)
      int_error("No plugin has been enabled. Enable at least one in template.");

    /* update the preference list */
    for (i=0; i<prefs_counter; i++) {
      for (j=0; j<template_prefs_all; j++) {
        if(strcmp(prefslist_ptr[i]->name, template_pref_list[j].name) == 0)
          if(strcmp(prefslist_ptr[i]->value, template_pref_list[j].value) != 0)
            strncpy(prefslist_ptr[i]->value, template_pref_list[j].value,
                    sizeof(prefslist_ptr[i]->value));
      }
    }

    /* count the enabled families */
    for(i=0; i<famly_counter; i++) {

    /* check for each family, how many of the enabled template    *
     * plugins match the plugin list for this family and increase *
     * the enabled_counter with each hit.                         */
       plugs_enabled = 0;
       for(j=0; j<famlylist[i].plugscount; j++) {
         for(k=0; k<template_plugs_all; k++) {
           if( strcmp(famlylist[i].plugs_ptr[j]->id,
               template_plug_list[k].id) == 0
               &&
               template_plug_list[k].enabled == 1 )
             plugs_enabled++;
         }
       }
       if(plugs_enabled > 0) famly_enabled++;
     } 
  } 
#ifdef DEBUG
  if(debugfile != NULL) fputs("\nscanprocess.cgi end\n\n", debugfile);
#endif
/* ------------------------------------------------------------------------ *
 * Send the preferences back to the scanner server.                         *
 * -------------------------------------------------------------------------*/

  if(strcmp(cred_type, "ssh-pass") == 0 || strcmp(cred_type, "smb-pass") == 0)
    set_credentials(cred_type, cred_user, cred_pass, prefs_counter);

  scanner_setprefs(ssl, prefs_counter);

/* ------------------------------------------------------------------------ *
 * Send the target IP list to the scanner server - this starts the scan.    *
 * -------------------------------------------------------------------------*/

  scanner_target(ssl, target_ip);

  /* session_id is created when the scan start for the host has been received */
  session_id = create_session_id(ssl);

/* -------------------------------------------------------------------------- *
 * start the initial cgi and update output                                    *
 * ---------------------------------------------------------------------------*/
   
   /* start writing the update popup window data so we are ready to display */
   write_hostupdates(session_id, target_ip, "start", "0");

/* -------------------------------------------------------------------------- *
 * start the html output                                                      *
 * ---------------------------------------------------------------------------*/

   pagehead(title, session_id, cgiOut);

   fprintf(cgiOut, "<table width=\"100%%\">\n");
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th colspan=2>Initiating new Scan</th>");

   fprintf(cgiOut, "</tr>\n<tr>");
   fprintf(cgiOut, "<td bgcolor=CFCFCF width=180>Selected Template:</th>");
   if(strlen(template_name) == 0) strncpy(template_name, "none", sizeof(template_name));
   fprintf(cgiOut, "<td>%s</td>", template_name);

   fprintf(cgiOut, "</tr>\n<tr>");
   fprintf(cgiOut, "<td bgcolor=CFCFCF>Using Credentials:</td>");
   fprintf(cgiOut, "<td>%s</td>", cred_type);

   fprintf(cgiOut, "</tr>\n<tr>");
   fprintf(cgiOut, "<td bgcolor=CFCFCF>Selected Families:</td>");
   fprintf(cgiOut, "<td>%d</td>", famly_enabled);

   fprintf(cgiOut, "</tr>\n<tr>");
   fprintf(cgiOut, "<td bgcolor=CFCFCF>Enabled Plugins:</td>");
   fprintf(cgiOut, "<td>%d</td>", plugs_enabled);

   fprintf(cgiOut, "</tr>\n<tr>");
   fprintf(cgiOut, "<td bgcolor=CFCFCF>Selected Target:</td>");
   fprintf(cgiOut, "<td>%s</td>", target_ip);

   fprintf(cgiOut, "</tr>\n<tr>");
   fprintf(cgiOut, "<td bgcolor=CFCFCF>Scanner Progress:</td>");
   fprintf(cgiOut, "<td><img src=../images/progressbar.gif></td>");

   fprintf(cgiOut, "</tr>\n<tr>");
   fprintf(cgiOut, "<td bgcolor=CFCFCF>Detailed Updates:</td>");
   fprintf(cgiOut, "<td>");
   fprintf(cgiOut, "<input type=button OnClick=\"return ");
   fprintf(cgiOut, "window.open(\'%s/updates-%s.htm\',",RESULTS_DIR,session_id);
   fprintf(cgiOut, " \'progress_update\',");
   fprintf(cgiOut, " 'width=690,height=150,status=no,scrollbars=no');\"\n");
   fprintf(cgiOut, " value=\"Show Scan Progress Details\">");
   fprintf(cgiOut, "</td>");

   fprintf(cgiOut, "</tr>\n<tr>");
   fprintf(cgiOut, "<th colspan=2>Total: %d Plugins in %d Families.",
                    plugs_counter, famly_counter );
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>");
   fprintf(cgiOut, "</table>\n");

   fprintf(cgiOut, "<p>");
   fprintf(cgiOut, "<table width=\"100%%\">");
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<th colspan=2>INOVASC Client</th>");

   fprintf(cgiOut, "</tr>\n<tr>");
   fprintf(cgiOut, "<td bgcolor=CFCFCF width=180>");
   fprintf(cgiOut, "Version:");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td>%s</td>", CLIENT_SW_VERSION);

   fprintf(cgiOut, "</tr>\n<tr>");
   fprintf(cgiOut, "<td bgcolor=CFCFCF>Copyright:</td>");
   fprintf(cgiOut, "<td>%s</td>", CLIENT_COPYRIGHTS);

   fprintf(cgiOut, "</tr>\n<tr>");
   fprintf(cgiOut, "<td bgcolor=CFCFCF>Status:</td>");
   fprintf(cgiOut, "<td><b>%s</b> login to server <b>%s</b> successful.</td>",
                    user, ip);

   fprintf(cgiOut, "</tr>\n<tr>");
   fprintf(cgiOut, "<th colspan=2>&nbsp;</th>");
   fprintf(cgiOut, "</tr>");
   fprintf(cgiOut, "</table>\n");

/* -------------------------------------------------------------------------- *
 * end the html output                                                        *
 * ---------------------------------------------------------------------------*/

  pagefoot(NULL);
  fflush(cgiOut);

/* -------------------------------------------------------------------------- *
 * Receive the server status updates and results.                             *
 * ---------------------------------------------------------------------------*/

  scanner_getstats(ssl, session_id);
  write_hostresults(target_ip, ip, session_id);

#ifdef DEBUG
  if(debugfile != NULL) fclose(debugfile);
#endif
  fclose(cgiOut);
  return(0);
}
