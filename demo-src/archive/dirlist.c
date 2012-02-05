/* -------------------------------------------------------------------------- *
 * file:         dirlist.c                                                    *
 * purpose:      example to list files in the results directory               *
 * ---------------------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#define _XOPEN_SOURCE

#define RESULTS_DIR "/home/htdocs/frank4dd.com/nessuswc/results"
#define MAXRESDISPLAY 10


int file_select(const struct dirent *entry) {
  char *ptr;
  
  if(entry->d_name[0]=='.') return 0;
  /* Check for .htm file name extensions */
  ptr = rindex(entry->d_name, '.');
  if((ptr != NULL) && (strcmp(ptr, ".htm") == 0)) return 1;
  else return 0;
}

int main() {

  struct	dirent **resultsdir_list;
  int filecounter = 0;

  filecounter = scandir(RESULTS_DIR, &resultsdir_list, 
                             file_select, alphasort);
  printf("files in dir: %d\n", filecounter);

  return(0);
}
