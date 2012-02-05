/* ---------------------------------------------------------------------------*
 * file:        inovasc.h                                                     *
 * purpose:     provide standard definitions accross cgi's                    *
 * author:      12/23/2004 Frank4DD                                           *
 * ---------------------------------------------------------------------------*/

#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

/*********** adjust the URL and path to your cert directory below *************/
#define HOMELINK	"/sw/inovasc"
#define STARTLINK	"/sw/inovasc/cgi-bin/scanlogin.cgi"

/* DEBUG enables code to write a debug log with CGI and OTP protocol info */
#define DEBUG
#define DEBUGFILE       "/tmp/inovasc.log"

/* This number defines how many results are displayed in one page when    *
 * scanresults.cgi is called. A number between 10 and 25 is a good choice */
#define MAXRESDISPLAY	15

#define SCANNER_IP	"127.0.0.1"
#define SCANNER_PORT	9391
#define USERNAME	"guest"
/* Although we authenticate with a client certificate, the OTP protocol  *
 * still requires a password string, but its a dummy string of any value */
#define PASSWORD	"*****"

#define RESULTS_DIR	"../results"
#define TEMPLATE_DIR	"../templates"
#define CA_CERT_DIR	"../etc"
#define CA_CERT		"cacert.pem"
#define CLIENT_CERT_DIR	"../etc"
#define CLIENT_CERT	"cert_guest.pem"
#define CLIENT_PRIVKEY	"../etc/key_guest.pem"

/* default scan target ip will be displayed in scanconfig.cgi */
#define DEFAULT_TARGET_IP	"127.0.0.1"

/* enabling the whole portscan family is dangerous unless all particular
   plugins are configured right. Until the implementation of single plugin
   configuration, there is a workaround enabling only safe plugins.
   This workaround can be disabled by commenting it out, at your own risk.   */
#define PORTSCAN_WORKAROUND     1

/* external plugins re used for checkking web application security. 
   However nikto, arachni and co take extremly long and are not always avail */
#define EXTERNAL_PLUGINS_WORKAROUND 1

/* refresh time of scan progress update popup window in sec, 2-3s works fine */
#define UPDWIN_REFRESH		3

/***************** this is safe to be left alone here. ************************/

#define CLIENT_SW_VERSION	"INOVASC 1.2.4 (01/09/2012)"
#define CLIENT_COPYRIGHTS	"GNU GPL, @2004-2012 Frank4DD"
#define CONTACT_EMAIL		"support@frank4dd.com"

#define CLIENT_OTP_VERSION "< OTP/1.0 >"
#define SERVER_OTP_VERSION "< OTP/1.0 >"

/*********** html code template for populating the sidebar  *******************/
#define SIDEBAR_TEMPL   "../sidebar-template.htm" /* optional */
/*********** html code template for populating the help data  *****************/
#define HELP_TEMPL      "../help-template.htm" /* mandatory */
/*********** html code template for populating the about text  ***************/
#define ABOUT_TEMPL    "../about-template.htm" /* mandatory */
/****** html code template for adding code or scripts into the footer *********/
#define FOOTER_TEMPL    "../footer-template.htm" /* optional */

/* MAXDATASIZE should be large enough to handle a huge plugin *
 * description so we get a newline. If it is to small, we get *
 * chunks with no newline counted and its just a mess.        */
// #define MAXDATASIZE 16384
#define MAXDATASIZE 26384

/* MAXPLUGS  should be large enough to handle all plugins   *
 * we could get from the scanner daemon. If it is to small, *
 * not all plugins can be processed. the current number is  *
 * over 20,000. Same goes for MAXPREFS and MAXRULES,        *
 * although their numbers are much smaller (165, 0).        */
#define MAXPLUGS 30000
/* on some systems, maxplugs=40000 works fine. On others,   *
 * once complied, any start of a cgi ends with 'Killed'.    *
 * Reduce MAXPLUGS fixes it, i.e. choose 30-35k instead.    */
#define MAXCATGY 500
#define MAXFAMLY 500
#define MAXPREFS 512
#define MAXRULES 512

/* MAXTEMPL is the max number of templates for which INOVASC *
 * will generate a template file and id for.                 */
#define MAXTEMPL 999

/* we assume that theoretically each plugin could report a hole */
#define MAXRESULTS MAXPLUGS

#define USERPROMPT "User : "
#define PASSPROMPT "Password : "

/* The first line in a INOVASC generated template file identifies the origin */
#define TEMPLATE_HEAD "# This file was created automatically by INOVASC v1.2\n"

/***************** no changes required below this line ************************/

#define CIPHER_LIST "EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC3-SHA:DES-CBC3-MD5:DHE-DSS-RC4-SHA:IDEA-CBC-SHA:RC4-SHA:RC4-MD5:IDEA-CBC-MD5:RC2-CBC-MD5:RC4-MD5"
/* The OTP protocol definitions start here */
/* Next are three base definitions for OTP */
#define SEPARATOR  " <|> "
#define CLIENT_END "<|> CLIENT"
#define SERVER_END "<|> SERVER"

/* OTP server messages when data is sent to the client */
#define PLIST_HASH  "SERVER <|> PLUGINS_MD5 <|>" /* send after login, this identifies the plugins stored at the server */
#define PLIST_START "SERVER <|> PLUGIN_LIST <|>" /* server start marker to send the plugin list to the client */
#define PREFS_START "SERVER <|> PREFERENCES <|>" /* server start marker to send the preferences to the client */
#define RULES_START "SERVER <|> RULES <|>"       /* server start marker to send the server rules to the client */
/* The spec is inconsistent, the next message does not end with a <|> */
/* http://www.openvas.org/compendium/otp-plugin_dependencies.html     */
/* server start marker to send the plugin dependencies to the client  */
#define PDEPS_START "SERVER <|> PLUGINS_DEPENDENCIES"

/* OTP server messages sent during the scan to the client */
#define SCAN_START "SERVER <|> TIME <|> SCAN_START <|>"
#define HOST_START "SERVER <|> TIME <|> HOST_START <|>"
#define STATS_START "SERVER <|> STATUS <|>"
#define ERROR_START "SERVER <|> ERROR <|>"
#define LOGS_START  "SERVER <|> LOG <|>"
#define PORTS_START "SERVER <|> PORT <|>"
#define HOLES_START "SERVER <|> HOLE <|>"
#define INFOS_START "SERVER <|> INFO <|>"
#define NOTES_START "SERVER <|> NOTE <|>"
#define HOST_END  "SERVER <|> FINISHED <|>"
#define SCAN_END  "SERVER <|> TIME <|> SCAN_END <|>"
/* The next message from the server notifies about the scan completion */
/* of a single host, but only if ntp_opt_show_end is set/              */
#define SERVER_FIN "SERVER <|> FINISHED <|>"
/* The next message is send by the server when the scan session ends   */
#define SERVER_BYE "SERVER <|> BYE <|> BYE <|> SERVER"
/* The client confirms the scan session end to the server              */
#define CLIENT_BYE "CLIENT <|> BYE <|> ACK"

/* OTP client messages sent to the server to initiate actions */
#define PLIST_GET "CLIENT <|> COMPLETE_LIST <|>" /* request plugins from server */
#define PREFS_SET "CLIENT <|> PREFERENCES <|>"   /* send prefs to server */
#define PLUGS_SET "plugin_set <|>"               /* start sending selected plugins */
#define RULES_SET "CLIENT <|> RULES <|>"         /* request rules from server */
#define PREFS_REQ "CLIENT <|> GO ON <|>"         /* request prefs from server */
#define NSCAN_REQ "CLIENT <|> LONG_ATTACK <|>"   /* start a new scan */
/* End of the OTP protocol definitions */

#define TEMPL_SPREF_START "begin(SERVER_PREFS)\n"
#define TEMPL_SPREF_END   "end(SERVER_PREFS)\n"
#define TEMPL_SCANR_START "begin(SCANNER_SET)\n"
#define TEMPL_SCANR_END   "end(SCANNER_SET)\n"
#define TEMPL_PLUGS_START "begin(PLUGIN_SET)\n"
#define TEMPL_PLUGS_END   "end(PLUGIN_SET)\n"
#define TEMPL_PPREF_START "begin(PLUGINS_PREFS)\n"
#define TEMPL_PPREF_END   "end(PLUGINS_PREFS)"

void pagehead(char *title, char *session, FILE *out);
void pagefoot(FILE *out);

#define int_error(msg)  handle_error(__FILE__, __LINE__, msg)
void handle_error(const char *file, int lineno, const char *msg);

SSL * scanner_connect(char *ip, int port, char *encr, char *cert);
int scanner_login(SSL *ssl, char *user, char *pass);
int scanner_getplugs(SSL *ssl);
void scanner_getgroups();
int scanner_getprefs(SSL *ssl);
int scanner_getrules(SSL *ssl);
int scanner_getpdeps(SSL *ssl);
void set_credentials(char *type, char *user, char *pass, int prefs_counter);
void scanner_setprefs(SSL *ssl, int prefs_counter);
int scanner_setplugs(SSL *ssl);
int template_setplugs(SSL *ssl);
int scanner_target(SSL *ssl, char *target_ip);
char * create_session_id(SSL *ssl);
void scanner_getstats(SSL *ssl, char *session);
void write_hostresults(char *t_ip, char *s_ip, char *session);
void write_hostupdates(char *session, char *t_ip, char *type, char *progress);
void get_dns(char *ip);
void get_template_name(char *file);
void get_template_date(char *file);
void get_template_prefs(char *file);
void get_template_plugs(char *file);
void update_prefslist();
void update_plugslist();
FILE * new_template_file();
void write_template_file(FILE *file, char *session_name, int prefs_counter, int famly_counter);

typedef struct plugs Plugs;
typedef struct prefs Prefs;
typedef struct rules Rules;
typedef struct catgy Catgy;
typedef struct famly Famly;

struct plugs {
   char id[128];
   char name[255];
   char category[255];
   char author[255];
   char descr[16192];
   char summary[255];
   char family[255];
   char revision[255];
   char cve[1024];
   char bid[255];
   char mdvsa[255];
   char hash[255];
   char infos[255];
};

struct prefs {
   char name[128];
   char value[1024];
};

struct rules {
   char command[128];
   char network[128];
};

/* Here is our array-of-structs */
struct plugs plugslist[MAXPLUGS];
struct prefs prefslist[MAXPREFS];
struct rules ruleslist[MAXRULES];

/* Here is our array-of-pointers to the structs */
struct plugs *plugslist_ptr[MAXPLUGS];
struct prefs *prefslist_ptr[MAXPREFS];
struct rules *ruleslist_ptr[MAXRULES];

struct catgy {
		char name[sizeof(plugslist->category)];
		struct plugs *plugs_ptr[MAXPLUGS];
		int plugscount;
                int enabled;
             };

struct catgy catgylist[MAXCATGY];

struct famly {
		char name[sizeof(plugslist->family)];
		struct plugs *plugs_ptr[MAXPLUGS];
		int plugscount;
                int enabled;
             };

struct famly famlylist[MAXFAMLY];

struct result {
                 char type[6];
                 char service[81];
                 char data[16192];
                 char plugin_id[128];
               };

struct result reslist[MAXRESULTS];

struct serviceport {
               char name[81];
               int  number;
               char protocol[4];
};

struct serviceport portlist[65365];

struct template_plug {
   char         id[128];
   int          enabled;
};

struct template_plug template_plug_list[MAXPLUGS];

struct template_pref {
   char         name[81];
   char         value[81];
};

struct template_pref template_pref_list[MAXPREFS];

/* Here are our group counters */

int plugs_counter;
int catgy_counter;
int famly_counter;
int ports_counter;
int result_counter;
int template_scanr_all;
int template_scanr_enabled;
int template_scanr_disabled;
int template_plugs_all;
int template_plugs_enabled;
int template_plugs_disabled;
int template_prefs_all;
char dns_name[255];
char template_name[81];
char template_date[81];
char templatefilestr[81];
FILE *debugfile;

/******************************* end inovasc.h ********************************/
