#ifndef _SNOW_ICE_ICE_H_
#define _SNOW_ICE_ICE_H_

#include <arpa/inet.h>

#include "cache.h"
#include "connection.h"
#include "mempool.h"
#include "session.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct snw_ice_context {
   void      *ctx;
   snw_log_t *log;

   int        rtcpmux_enabled;
   int        ice_lite_enabled;
   int        ipv6_enabled;
   int        ice_tcp_enabled;

   char       local_ip[INET6_ADDRSTRLEN];
   char       public_ip[INET6_ADDRSTRLEN];

   /* caches, efficiency in search */
   snw_hashbase_t *session_cache;

   /* mempools for fixed-size objects, fast in allocation */
   snw_mempool_t  *stream_mempool;
   snw_mempool_t  *component_mempool;
};

void 
snw_ice_init(snw_context_t *ctx);

//void
//ice_srtp_handshake_done(ice_session_t *session, ice_component_t *component);

#ifdef __cplusplus
}
#endif

#endif //_SNOW_ICE_ICE_H_
