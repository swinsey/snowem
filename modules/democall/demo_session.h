#ifndef _SNOW_DEMOCALL_DEMO_SESSION_H_
#define _SNOW_DEMOCALL_DEMO_SESSION_H_

#include <stdint.h>

#include "demo.h"

typedef struct snw_demo_session snw_demo_session_t;
struct snw_demo_session {
   uint32_t roomid;
   uint32_t creatorid;
   uint32_t peerid;

   snw_demo_context_t *demo_ctx;
};


int
snw_demo_session_init(snw_demo_context_t *ctx);

snw_demo_session_t*
snw_demo_session_get(snw_demo_context_t *ctx, uint32_t roomid, int *is_new);

snw_demo_session_t*
snw_demo_session_search(snw_demo_context_t *ctx, uint32_t roomid);

snw_demo_session_t*
snw_demo_session_insert(snw_demo_context_t *ctx, snw_demo_session_t *sitem);

int 
snw_demo_session_remove(snw_demo_context_t *ctx, snw_demo_session_t *sitem);

#endif //_SNOW_DEMOCALL_DEMO_SESSION_H_


