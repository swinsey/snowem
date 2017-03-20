#include <stdio.h>

#include "module.h"

#include "videocall.h"


void
videocall_handle_msg(void *ctx, char *buffer, int len) {

   printf("videocall handle msg\n");
   return;
}


snw_module_methods_t videocall_methods = {
   .handle_msg = videocall_handle_msg
};

void
module_init(void* ctx) {
   snw_module_t *module = (snw_module_t *)ctx;

   module->methods = &videocall_methods;

   printf("videocall init\n");

   return;
}


