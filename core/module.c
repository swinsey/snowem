
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "core.h"
#include "module.h"
#include "mq.h"
#include "linux_list.h"
#include "log.h"

void
snw_module_init(snw_context_t *ctx) {
   snw_log_t *log = 0;
   struct list_head *p;
   void *handle;
   void (*init)(void*);

   if (!ctx) return;
   log = ctx->log;

   list_for_each(p,&ctx->modules.list) {
      snw_module_t *m = list_entry(p,snw_module_t,list);
<<<<<<< HEAD
      DEBUG(log, "initialize module, name=%s, type=0x%0x, sofile=%s", 
             m->name, m->type, m->sofile);
      handle = dlopen(m->sofile, RTLD_LAZY);
      if (!handle) {
         DEBUG(ctx->log, "failed to load so, s=%s", dlerror());
=======
      handle = dlopen(m->sofile, RTLD_LAZY);
      if (!handle) {
         ERROR(ctx->log, "failed to load library s=%s", dlerror());
>>>>>>> dev
         exit(1);
      }
      m->ctx = ctx;
      init = (void (*)(void*))dlsym(handle, "module_init");
      m->init = init;
      init(m);
   }

<<<<<<< HEAD

   /*DEBUG(ctx->log, "module info, name=%s, type=%0x, sofile=%s", 
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
   init(ctx->module);*/

=======
>>>>>>> dev
   return;
}


void
snw_module_enqueue(void *mq, const time_t curtime, const void* data,
       uint32_t len, uint32_t flow) {
   snw_shmmq_enqueue((snw_shmmq_t *)mq, curtime, data, len, flow);
}

