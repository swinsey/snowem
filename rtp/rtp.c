
#include "core/log.h"
#include "rtp/rtp.h"
#include "rtp/rtp_h264.h"

#define USE_MODULE_COMMON
#define DECLARE_MODULE(name) &(g_rtp_##name##_module),
snw_rtp_module_t *g_rtp_modules[] = {
   #include "rtp_module_dec.h"
   0
};
#undef DECLARE_MODULE
#undef USE_MODULE_COMMON

int
snw_rtp_init(snw_ice_context_t *ctx) {
   snw_log_t *log;
   int i = 0;

   if (!ctx) return -1;
   log = ctx->log;
    
   for (i=0; ; i++) {
      snw_rtp_module_t *m = g_rtp_modules[i];
      if (!m) break;

      DEBUG(log,"init module, name=%s",m->name);
      m->init(ctx);
   }
   return 0;
}


int
snw_rtp_handle_pkg(snw_rtp_ctx_t *ctx, char *buffer, int len) {
   snw_log_t *log;
   int i = 0;

   if (!ctx) return -1;
   log = ctx->log;

   for (i=0; ; i++) {
      snw_rtp_module_t *m = g_rtp_modules[i];
      if (!m) break;

      DEBUG(log,"rtp handling, name=%s",m->name);
      m->handle_pkg(ctx,buffer,len);
   }

   return 0;
}

