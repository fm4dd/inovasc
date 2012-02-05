/* -------------------------------------------------------------------------- *
 * file:         scanlogin.c                                                  *
 * purpose:      provides the openvas scan server login settings              *
 * ---------------------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <cgic.h>
/* ip conversion routines and ping require the following header files */
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include "inovasc.h"

char * get_dns_name(char *remote_ip) {

   struct in_addr	addr;
   struct hostent	*host;

   addr.s_addr = inet_addr(remote_ip);
   host = gethostbyaddr((char *)&addr, sizeof(addr), AF_INET);

   if (h_errno == 0) return (host->h_name);
   else if (h_errno == 1) return ("DNS: Authoritative Answer Host not found");
   else if (h_errno == 2) return ("DNS: Non-Authoritative Host not found");
   else if (h_errno == 3) return ("DNS: Non recoverable errors");
   else if (h_errno == 4) return ("DNS: Valid name, no data record");
   else return ("DNS: Unknown error occured");
}


int cgiMain() {

   static char 	title[] = "Scanner Login";
   char		ip[16] = SCANNER_IP;
   int		port = SCANNER_PORT;
   char		user[81] = USERNAME;
   char		pass[81] = PASSWORD;
   char		cert[81] = CLIENT_CERT;

/* -------------------------------------------------------------------------- *
 * check if we got called from scantemplates with a template file to process  *
 * valid entries are: a template filename  or "none"                          *
 * ---------------------------------------------------------------------------*/

  if(! (cgiFormString("template", templatefilestr, sizeof(templatefilestr))
                                                         == cgiFormSuccess))
     strncpy(templatefilestr, "none", sizeof(templatefilestr));

/* -------------------------------------------------------------------------- *
 * start the html output                                                      *
 * ---------------------------------------------------------------------------*/

   pagehead(title, NULL, cgiOut);

/* -------------------------------------------------------------------------- *
 * start the form output                                                      *
 * ---------------------------------------------------------------------------*/

   fprintf(cgiOut, "<table width=\"100%%\">");

/* -------------------------------------------------------------------------- *
 * check if we got a template file to process                                 *
 * ---------------------------------------------------------------------------*/

    if(strcmp(templatefilestr, "none") == 0)
      fprintf(cgiOut, "<form action=\"scanconfig.cgi\" method=\"post\">");
    else if(strcmp(templatefilestr, "create") == 0) {
      fprintf(cgiOut, "<form action=\"scanconfig.cgi\" method=\"post\">");
      fprintf(cgiOut, "<input type=hidden name=template value=%s>",
                                                         templatefilestr);
    }
    else {
      /* forward the template file information to the scanverify.cgi */
      fprintf(cgiOut, "<form action=\"scanverify.cgi\" method=\"post\">");
      fprintf(cgiOut, "<input type=hidden name=template value=%s>",
                                                         templatefilestr);
   }

   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th colspan=2>");
   fprintf(cgiOut, "OpenVAS Scanner Daemon");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<td align=\"center\" bgcolor=\"#CFCFCF\"");
   fprintf(cgiOut, " bordercolor=CFCFCF width=180>");
   fprintf(cgiOut, "IP Address:");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td align=\"right\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<input type=text name=ip size=24 maxlength=24");
   fprintf(cgiOut, " value=%s>\n", ip);
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "</tr>");
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<td align=\"center\" bgcolor=CFCFCF bordercolor=CFCFCF>");
   fprintf(cgiOut, "Service Port:");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td align=\"right\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<input type=text name=port size=4 maxlength=5");
   fprintf(cgiOut, " value=%d>\n", port);
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<td align=\"center\" bgcolor=CFCFCF bordercolor=CFCFCF>");
   fprintf(cgiOut, "Encryption:");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td align=\"right\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<select name=\"encr\">");
   fprintf(cgiOut, "<option value=\"TLSv1\" selected>TLSv1</option>");
   fprintf(cgiOut, "<option value=\"SSLv2\">SSLv2</option>");
   fprintf(cgiOut, "<option value=\"SSLv3\">SSLv3</option>");
   fprintf(cgiOut, "<option value=\"Auto\">Auto</option></select>");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<td align=\"center\" bgcolor=CFCFCF bordercolor=CFCFCF>");
   fprintf(cgiOut, "User Name:");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td align=\"right\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<input type=text name=user size=24 maxlength=24");
   fprintf(cgiOut, " value=%s>\n", user);
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<td align=\"center\" bgcolor=CFCFCF bordercolor=CFCFCF>");
   fprintf(cgiOut, "Password: ");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td align=\"right\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<input type=password name=pass size=24 maxlength=24");

   /* Escape the password string, it can contain HTL reserved chars like '>' */
   fprintf(cgiOut, " value=");
   cgiHtmlEscape(pass);
   fprintf(cgiOut, ">\n");

   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "<tr>");
   fprintf(cgiOut, "<td align=\"center\" bgcolor=CFCFCF bordercolor=CFCFCF>");
   fprintf(cgiOut, "Certificate: ");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "<td align=\"right\" bgcolor=\"#FFFFFF\">");
   fprintf(cgiOut, "<select name=\"cert\">");
   fprintf(cgiOut, "<option value=\"%s\">", cert);
   fprintf(cgiOut, "%s</option><option value=\"none\">None (use pass)",
                                                                 cert);
   fprintf(cgiOut, " </option></select>");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "</tr>\n");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th colspan=2>");
   fprintf(cgiOut, "<input type=\"submit\" value=\"Continue\">");
   fprintf(cgiOut, "</th>");
   fprintf(cgiOut, "</tr>");
   fprintf(cgiOut, "</form></table>\n");

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
   fprintf(cgiOut, "%s\n", "Not logged in");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "</tr>");
   fprintf(cgiOut, "<tr>\n");
   fprintf(cgiOut, "<th colspan=2>");
   fprintf(cgiOut, "&nbsp;");
   fprintf(cgiOut, "</td>");
   fprintf(cgiOut, "</tr>");
   fprintf(cgiOut, "</table>\n");

/* -------------------------------------------------------------------------- *
 * end the html output                                                        *
 * ---------------------------------------------------------------------------*/

   pagefoot(NULL);
   return(0);
}
