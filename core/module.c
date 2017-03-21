#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>

#include "module.h"
#include "mq.h"
#include "log.h"

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


void
snw_module_enqueue(void *mq, const time_t curtime, const void* data,
       uint32_t len, uint32_t flow) {
   snw_shmmq_enqueue((snw_shmmq_t *)mq, curtime, data, len, flow);
}

