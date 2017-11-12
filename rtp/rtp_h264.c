#include "core/log.h"
#include "rtp/rtp_h264.h"
#include "rtp/rtp_rtmp.h"

#define USE_MODULE_H264
#define DECLARE_MODULE(name) &(g_rtp_##name##_module),
snw_rtp_module_t *g_rtp_h264_modules[] = {
   #include "rtp_module_dec.h"
   0
};
#undef DECLARE_MODULE
#undef USE_MODULE_H264

int
snw_rtp_h264_init(void *c) {
   snw_ice_context_t *ctx = (snw_ice_context_t*)c;
   snw_log_t *log = 0;
   snw_rtp_module_t *prev = &g_rtp_h264_module;
   int i = 0;
   
   if (!ctx) return -1;
   log = ctx->log;
   
   DEBUG(log,"init rtp h264");
   //FIXME init rtmp module
    
   for (i=0; ; i++) {
      snw_rtp_module_t *m = g_rtp_h264_modules[i];
      if (!m) break;

      DEBUG(log,"init module, name=%s",m->name);
      m->init(ctx);
      prev->next = m;
      prev = m;
   }

   return 0;
}

int
snw_rtp_h264_handle_pkg(void *ctx, char *buffer, int len) {
   return 0;
}

int
snw_rtp_h264_fini() {
   return 0;
}

snw_rtp_module_t g_rtp_h264_module = { 
   "h264",
   0,/*ctx*/
   snw_rtp_h264_init, 
   snw_rtp_h264_handle_pkg, 
   snw_rtp_h264_fini,
   0 /*next*/
};


