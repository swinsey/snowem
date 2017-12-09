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
<<<<<<< HEAD
=======
#include "channel_mgr.h"
#include "ice/ice.h"
>>>>>>> dev
#include "mempool.h"
#include "mq.h"
#include "module.h"
#include "types.h"
<<<<<<< HEAD
#include "ice.h"
=======
>>>>>>> dev

#ifdef __cplusplus
extern "C" {
#endif

// shared mem info for message queues
#define SHAREDMEM_SIZE 33554432
#define ICE2CORE_KEY 1168647512
#define CORE2ICE_KEY 1168647513
#define NET2CORE_KEY 1168647514
#define CORE2NET_KEY 1168647515

typedef void (*dispatch_fn)(int fd, short int event,void* data);
struct snw_context {
   snw_log_t          *log;
   time_t              cur_time;
   struct event_base  *ev_base;
   SSL_CTX            *ssl_ctx;

   const char         *config_file;
   const char         *ice_cert_file;
   const char         *ice_key_file;

   const char         *wss_cert_file;
   const char         *wss_key_file;
   const char         *wss_ip;
   uint16_t            wss_port;

   const char         *log_file;
   uint32_t            log_file_maxsize;
   uint32_t            log_rotate_num;
   uint32_t            log_level;
<<<<<<< HEAD
=======
   int                 ice_log_enabled;
>>>>>>> dev

   /* message queues */
   snw_shmmq_t  *snw_ice2core_mq;
   snw_shmmq_t  *snw_core2ice_mq;
   snw_shmmq_t  *snw_net2core_mq;
   snw_shmmq_t  *snw_core2net_mq;

   /* caches */
<<<<<<< HEAD
   snw_hashbase_t *session_cache;
=======
   snw_hashbase_t *channel_cache;
   snw_hashbase_t *peer_cache;

   /* channel set */
   snw_set_t      *channel_mgr;
>>>>>>> dev

   /* mempool for fixed-size objects */
   snw_mempool_t *rcvvars_mp;

   snw_module_t  *module;
   snw_module_t   modules;
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



