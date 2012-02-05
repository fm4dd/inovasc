/* ------------------------------------------------------------------------ *
 *                                                                          *
 * template.c  provides functions and routines for template management      *
 *                                                                          *
 * ------------------------------------------------------------------------ */

/* needed for getline() */
#define _XOPEN_SOURCE
#define __USE_XOPEN
#define __USE_GNU
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <errno.h>
#include <cgic.h>
#include "inovasc.h"

char template_path[256] = "";

/* ------------------------------------------------------------------------ *
 * get_template_name loads the name of the template from file.              *
 * Assumption: There is a line >" Session: <name> on top of the scan config *
 * ------------------------------------------------------------------------ */
void get_template_name(char *file) {
  FILE *TEMPLATE = NULL;
  char *linebuf = NULL;
  size_t len = 0;
  ssize_t read = 0;

  /* try to open the template file */
  snprintf(template_path, sizeof(template_path), "%s/%s", TEMPLATE_DIR, file);
  if(! (TEMPLATE = fopen(template_path, "r"))) 
                                int_error("Can't open template file.");

  /* cycle through each line of the template file until we find "# Session: " */
  
  strncpy(template_name, "", sizeof(template_name));
  while ((read = getline(&linebuf, &len, TEMPLATE)) != -1) {
    if(strstr(linebuf, "# Session: ")) {
       strncpy(template_name, (strchr(linebuf, ':')+2), sizeof(template_name));
       break;
    }
  }
  if(strcmp(template_name, "") == 0)
       strncpy(template_name, "No Session Name", sizeof(template_name));

  /* remove the newline character at the end */
  if((template_name[strlen(template_name) -1] = '\n'))
    template_name[strlen(template_name) -1] = '\0';

  if(linebuf) free(linebuf);
  fclose(TEMPLATE);
}

/* ------------------------------------------------------------------------ *
 * get_template_date loads the creation date of the template from file.     *
 * Assumption: There is a line >" Exported <date> on top of the scan config *
 * ------------------------------------------------------------------------ */
void get_template_date(char *file) {
  FILE *TEMPLATE = NULL;
  char *linebuf = NULL;
  size_t len = 0;
  ssize_t read = 0;

  /* try to open the template file */
  snprintf(template_path, sizeof(template_path), "%s/%s", TEMPLATE_DIR, file);
  if(! (TEMPLATE = fopen(template_path, "r"))) 
                                int_error("Can't open template file.");

  /* cycle through each line of the template file until we find "# Session: " */
  
  strncpy(template_date, "", sizeof(template_date));
  while ((read = getline(&linebuf, &len, TEMPLATE)) != -1) {
    if(strstr(linebuf, "# Exported ")) {
       strncpy(template_date, (linebuf + strspn(linebuf, "# Exported ")), sizeof(template_date));
       break;
    }
  }
  if(strcmp(template_date, "") == 0)
       strncpy(template_date, "No Session Date", sizeof(template_date));

  if(linebuf) free(linebuf);
  fclose(TEMPLATE);
}

/* ------------------------------------------------------------------------ *
 * get_template_prefs loads the template preferences list from file.        *
 * Assumption: list is between "begin(SERVER_PREFS)" and "end(SERVER_PREFS)"*
 * ------------------------------------------------------------------------ */
void get_template_prefs(char *file) {
  FILE *TEMPLATE;
  char *linebuf = 0;
  size_t len = 0;
  size_t namelen = 0;
  size_t valuelen = 0;
  ssize_t read;

  /* initialize counters */
  template_prefs_all = -1;

  /* try to open the template file */
  snprintf(template_path, sizeof(template_path), "%s/%s", TEMPLATE_DIR, file);
  if(! (TEMPLATE = fopen(template_path, "r"))) 
                                int_error("Can't open template file.");

  /* cycle through each line of the template file */
  while ((read = getline(&linebuf, &len, TEMPLATE)) != -1) {

    if(strstr(linebuf, "begin(SERVER_PREFS)")) {
       /* zero all counters */
       template_prefs_all = 0;
    }

    if(strstr(linebuf, "end(SERVER_PREFS)")) break;

    if(template_prefs_all >= 0 && strstr(linebuf, "=")) {

        /* split the line into name and value */

        /* calculate the string length to the "=" */
        namelen = strcspn(linebuf, "=");
        valuelen = strcspn((linebuf + namelen +2), " ");
        /* remove leading and trailing space and copy the value to the struct list */
        strncpy(template_pref_list[template_prefs_all].name, linebuf+1, namelen-2);
        strncpy(template_pref_list[template_prefs_all].value, 
                 (linebuf + namelen + 2), valuelen-1);
        template_prefs_all++;
    }
  }

  if(linebuf) free(linebuf);
  fclose(TEMPLATE);
}

/* ------------------------------------------------------------------------ *
 * get_template_plugs loads the template plugin list from file.             *
 * Assumption: list is between "begin(PLUGIN_SET) and "end(PLUGIN_SET)"     *
 * ------------------------------------------------------------------------ */
void get_template_plugs(char *file) {
  FILE *TEMPLATE;
  char *linebuf = NULL;
  char *tmp_buf = NULL;
  int  str_len = 0;
  size_t len = 0;
  ssize_t read;

  /* zero all counters */
  template_plugs_all = -1;
  template_plugs_enabled = -1;
  template_plugs_disabled = -1;
  template_scanr_all = -1;
  template_scanr_enabled = -1;
  template_scanr_disabled = -1;

  /* try to open the template file */
  snprintf(template_path, sizeof(template_path), "%s/%s", TEMPLATE_DIR, file);
  if(! (TEMPLATE = fopen(template_path, "r"))) 
                                int_error("Can't open template file.");

  /* cycle through each line of the template file */
  while ((read = getline(&linebuf, &len, TEMPLATE)) != -1) {

    if(strstr(linebuf, "begin(SCANNER_SET)")) {
       /* zero all counters */
       template_scanr_all = 0;
       template_scanr_enabled = 0;
       template_scanr_disabled = 0;
    }

    if(strstr(linebuf, "end(SCANNER_SET)")) break;

    if(template_scanr_all >= 0 && strstr(linebuf, "=")) {

     /* use linebuf+1 to remove the leading space before the id *
      * (NessusWX formatting) and set the string length.        */
      tmp_buf = strchr(linebuf, '=') -1;
      str_len = tmp_buf - linebuf - 1;
      strncpy(template_plug_list[template_scanr_all].id, linebuf+1, str_len);
      template_plug_list[template_scanr_all].id[str_len] = '\0';

      if(template_scanr_disabled >= 0 && strstr(linebuf, "no")) {
        template_plug_list[template_scanr_all].enabled = 0;
        template_scanr_disabled++;
      }
      else if(template_scanr_enabled >=0 && strstr(linebuf, "yes")) {
        template_plug_list[template_scanr_all].enabled = 1;
        template_scanr_enabled++;
      }
      template_scanr_all++;
    }
  }

  /* cycle through each line of the template file */
  while ((read = getline(&linebuf, &len, TEMPLATE)) != -1) {

    if(strstr(linebuf, "begin(PLUGIN_SET)")) {
       /* zero all counters */
       template_plugs_all = 0;
       template_plugs_enabled = 0;
       template_plugs_disabled = 0;
    }

    if(strstr(linebuf, "end(PLUGIN_SET)")) break;

    if(template_plugs_all >= 0 && strstr(linebuf, "=")) {

     /* use linebuf+1 to remove the leading space before the id *
      * (NessusWX formatting) and set the string length to 5    */
      tmp_buf = strchr(linebuf, '=') -1;
      str_len = tmp_buf - linebuf - 1;
      strncpy(template_plug_list[template_plugs_all + template_scanr_all].id,
                linebuf+1, str_len);
      template_plug_list[template_plugs_all + template_scanr_all].id[str_len] = '\0';

      if(template_plugs_disabled >= 0 && strstr(linebuf, "no")) {
        template_plug_list[template_plugs_all + template_scanr_all].enabled = 0;
        template_plugs_disabled++;
      }
      else if(template_plugs_enabled >=0 && strstr(linebuf, "yes")) {
        template_plug_list[template_plugs_all + template_scanr_all].enabled = 1;
        template_plugs_enabled++;
      }
      template_plugs_all++;
    }
  }

  /* Scanner plugins count as normal plugins, so we add them up here */
  template_plugs_all = template_plugs_all + template_scanr_all;
  template_plugs_enabled = template_plugs_enabled + template_scanr_enabled;
  template_plugs_disabled = template_plugs_disabled + template_scanr_disabled;

  if(linebuf) free(linebuf);
  fclose(TEMPLATE);
}

/* ------------------------------------------------------------------------ *
 * new_template_file generates a new file name and file using the INOVASC   *
 * file name convention for templates: template-<3digit-id>.rc              *
 * ------------------------------------------------------------------------ */

int templ_select(const struct dirent *entry);

FILE * new_template_file () {
  FILE * TEMPLATE = NULL;
  char id_string[4];
  int  template_id = 0;
  int  i = 0;
  int  rescounter = 0;
  struct dirent **templatedir_list;
  char error_string[256] = "";

  rescounter = scandir(TEMPLATE_DIR, &templatedir_list, templ_select, alphasort);

  /* scan through the template directory and check for the highest assigned *
   * template id. If there is no file with an id, we start with '000', else *
   * we simply increment the highest we can find - up to MAXTEMPL (999).    */

  if(rescounter>0) {
    for(i=0; i < rescounter; i++) {

      if(strlen(templatedir_list[i]->d_name) == 15)
        if(strcspn(templatedir_list[i]->d_name, "-") == 8)
          if(strcspn(templatedir_list[i]->d_name, ".") == 12) {
            strncpy(id_string, templatedir_list[i]->d_name+9, 3);
            template_id = atoi(id_string);
            if(template_id < 999) {
              snprintf(templatefilestr, sizeof(templatefilestr),
                     "template-%.3d.rc", template_id+1);
              snprintf(template_path, sizeof(template_path),
                     "%s/%s", TEMPLATE_DIR, templatefilestr);
              if(! (TEMPLATE = fopen(template_path, "r")))
                if((TEMPLATE = fopen(template_path, "w"))) break;
            }
            else
              int_error("Reached template file limit of 999 files.");

          }
    }
  }
  if(TEMPLATE == NULL) {
    snprintf(templatefilestr, sizeof(templatefilestr),
             "template-%.3d.rc", template_id+1);
    snprintf(template_path, sizeof(template_path),
                   "%s/%s", TEMPLATE_DIR, templatefilestr);
    if(! (TEMPLATE = fopen(template_path, "r")))
      if(! (TEMPLATE = fopen(template_path, "w"))) {
        snprintf(error_string, sizeof(error_string), "Can't create template file %s.", template_path);
        int_error(error_string);
      }
  }

  return TEMPLATE;
}

/* ------------------------------------------------------------------------ *
 * write_template_file writes the scan configuration to file using the      *
 * same formating and standards as seen in NessusWX.                        *
 * ------------------------------------------------------------------------ */
void write_template_file (FILE *file, char *session_name, int prefs_counter, int famly_counter) {
  char linebuf[81] = "";
  time_t now;
  int i = 0, j = 0;

  fputs(TEMPLATE_HEAD, file);

  if (strlen(cgiRemoteAddr) != 0) {
    get_dns(cgiRemoteAddr);
    snprintf(linebuf, sizeof(linebuf), "# Created by: %s [%s]\n",
             cgiRemoteAddr, dns_name);
    fputs(linebuf, file);
  }

  snprintf(linebuf, sizeof(linebuf), "# Session: %s\n", session_name);
  fputs(linebuf, file);

  now = time(NULL);
  snprintf(linebuf, sizeof(linebuf), "# Exported %s\n", ctime(&now));
  fputs(linebuf, file);

  /* write the server preferences */
  fputs(TEMPL_SPREF_START, file);

  for (i=0; i<prefs_counter; i++) {

    if(! (strchr(prefslist_ptr[i]->name, ':'))) {
      snprintf(linebuf, sizeof(linebuf), " %s = %s\n",
               prefslist_ptr[i]->name, prefslist_ptr[i]->value);
      fputs(linebuf, file);
    }
  }

  fputs(TEMPL_SPREF_END, file);

  /* write the scanner plugins  (plugins in family "Port scanners") */
  fputs(TEMPL_SCANR_START, file);

  for(i=0; i<famly_counter; i++) {

    if(strcmp(famlylist[i].name, "Port scanners") == 0) {

      for(j=0; j<famlylist[i].plugscount; j++) {

        if(famlylist[i].enabled == 1)
          snprintf(linebuf, sizeof(linebuf), " %s = %s\n",
               famlylist[i].plugs_ptr[j]->id, "yes");
        else
          /* enable the 2 default scanner plugins 10335 and 10180 anyways */
          if(strcmp(famlylist[i].plugs_ptr[j]->id, "10335") == 0 ||
             strcmp(famlylist[i].plugs_ptr[j]->id, "10180") == 0 ) 
            snprintf(linebuf, sizeof(linebuf), " %s = %s\n",
                 famlylist[i].plugs_ptr[j]->id, "yes");
          else
            snprintf(linebuf, sizeof(linebuf), " %s = %s\n",
                 famlylist[i].plugs_ptr[j]->id, "no");
        fputs(linebuf, file);
      }
    }
  }
  fputs(TEMPL_SCANR_END, file);

  /* write the remaining plugins */
  fputs(TEMPL_PLUGS_START, file);

  for(i=0; i<famly_counter; i++) {

    if(strcmp(famlylist[i].name, "Port scanners") != 0) {

      for(j=0; j<famlylist[i].plugscount; j++) {

        if(famlylist[i].enabled == 1)
          snprintf(linebuf, sizeof(linebuf), " %s = %s\n",
               famlylist[i].plugs_ptr[j]->id, "yes");
        else
          snprintf(linebuf, sizeof(linebuf), " %s = %s\n",
               famlylist[i].plugs_ptr[j]->id, "no");
        fputs(linebuf, file);
      }
    }
  }
  fputs(TEMPL_PLUGS_END, file);

  fputs(TEMPL_PPREF_START, file);
  fputs(TEMPL_PPREF_END, file);

  fclose(file);
}
