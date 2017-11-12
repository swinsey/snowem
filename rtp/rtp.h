#ifndef _SNOW_RTP_H_
#define _SNOW_RTP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "core/types.h"
#include "core/linux_list.h"
#include "ice/ice.h"

typedef struct snw_rtp_module snw_rtp_module_t;
struct snw_rtp_module {
   char  *name;
   void  *ctx;
   int  (*init)(void *ctx);
   int  (*handle_pkg)(void *ctx, char *buffer, int len);
   int  (*fini)();

   snw_rtp_module_t *next;
};

int
snw_rtp_init(snw_ice_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif //_SNOW_RTP_H_



