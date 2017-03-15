#ifndef _SNOW_CORE_CORE_H_
#define _SNOW_CORE_CORE_H_

#include <stdio.h>
#include <time.h>

#include <event.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "cache.h"
#include "mempool.h"
#include "mq.h"
#include "types.h"
#include "ice.h"

#ifdef __cplusplus
extern "C" {
#endif

struct snw_context {
   snw_log_t          *log;
   time_t              cur_time;
   struct event_base  *ev_base;
   SSL_CTX            *ssl_ctx;

   const char         *config_file;
   const char         *cert_file;
   const char         *key_file;

   /* ice stuff */
   snw_ice_context_t  *ice_ctx;
  
   /* message queues */
   snw_shmmq_t  *snw_ice2core_mq;

   /* caches */
   snw_hashbase_t *session_cache;

   /* mempool for fixed-size objects */
   snw_mempool_t *rcvvars_mp;
};

snw_context_t*
snw_create_context();

void 
daemonize();

void
snw_net_setup(snw_context_t *ctx);

void
snw_worker_setup(snw_context_t *ctx);

void
snw_ice_setup(snw_context_t *ctx);


#ifdef __cplusplus
}
#endif

#endif //_SNOW_CORE_CORE_H_



