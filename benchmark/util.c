#include<stdarg.h>
#include<stdio.h>
#include <time.h>

#include "util.h"

void log_write(const char* sourcefilename, int line, const char* msg, ...) {
    static char dest[4*1024] = {0};
    va_list argptr;
    va_start(argptr, msg);
    vsnprintf(dest, 4*1024, msg, argptr);
    va_end(argptr);
    printf("%s:%d: %s\n", sourcefilename, line, dest);
    return;
}

int64_t get_real_time(void) {
   struct timespec ts; 
   clock_gettime (CLOCK_REALTIME, &ts);
   return (ts.tv_sec*1000000) + (ts.tv_nsec/(1000));
}    

int64_t get_monotonic_time(void) {
   struct timespec ts; 
   clock_gettime (CLOCK_MONOTONIC, &ts);
   return (ts.tv_sec*((int64_t)1000000)) + (ts.tv_nsec/((int64_t)1000));
}

