#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>

#include "module.h"

void
snw_module_init(snw_context_t *ctx) {
   void *handle;
   void (*init)(void*);

   if (!ctx) return;

   DEBUG(ctx->log, "module info, name=%s, type=%0x, sofile=%s", 
          ctx->module->name,
          ctx->module->type,
          ctx->module->sofile);

   handle = dlopen(ctx->module->sofile, RTLD_LAZY);
   if (!handle) {
      DEBUG(ctx->log, "failed to load so, s=%s", dlerror());
      exit(1);
   }

   init = (void (*)(void*))dlsym(handle, "module_init");
   ctx->module->init = init;
   init(ctx->module);

   return;
}



