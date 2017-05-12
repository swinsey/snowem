#include<stdarg.h>
#include<stdio.h>

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



