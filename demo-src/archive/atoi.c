/* tests the correct ascii - to - integer conversion, a file length and *
 * creates a large number of templates to verify the 999 files limit    */

#include <stdio.h>
#include <stdlib.h>

int main(void) {

  static char test[] = "rgf";
  int result = 0, i=0;
  static char t2[] = "template-002.rc";
  char command[256] = "";

  result = atoi(test);

  printf("Convert string [%s] to int [%d] format [%.3d].\n",
                  test, result, result);
 
  printf("len: %d, len to -: %d len to .: %d\n",
                 strlen(t2),
                 strcspn(t2, "-"),
                 strcspn(t2, "."));

  for(i=0; i<990; i++) {
    snprintf(command, sizeof(command),
              "cp template-001.rc template-%.3d.rc", i);
    system(command);
  }

  return 0;
}
