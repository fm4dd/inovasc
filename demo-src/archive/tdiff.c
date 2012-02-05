/* --------------------------------------------------------------------------
 * file:         tdiff.c
 * purpose:      example of printing a time difference
 * -------------------------------------------------------------------------- */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(void) {

   time_t tstamp_now;
   time_t tstamp_later;
   struct tm *now;
   struct tm *later;
   double timediff;
   long hours = 0;
   long mins = 0;
   long secs = 0;
   ldiv_t tdiff;

   tstamp_now = time(NULL);
   sleep(1);
   tstamp_later = time(NULL);

   now = localtime(&tstamp_now);
   later = localtime(&tstamp_later);

   timediff = difftime(tstamp_later, tstamp_now) + 3598;
 
   secs = (long) (timediff+0.5);

  if (secs>=3600) {
    tdiff = ldiv(secs, 3600);
    hours = tdiff.quot;
    secs = tdiff.rem;
  }

  if (secs>=60) {
    tdiff = ldiv(secs, 60);
    mins = tdiff.quot;
    secs = tdiff.rem;
  }

   printf("Time difference HH:MM:SS:%02d:%02d:%02d\n", hours, mins, secs);

   exit(0);
}

