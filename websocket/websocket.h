#ifndef _WEBSOCKET_WEBSOCKET_H_
#define _WEBSOCKET_WEBSOCKET_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "core.h"
#include "flow.h"

typedef struct snw_websocket_context snw_websocket_context_t;
struct snw_websocket_context {
   snw_context_t  *ctx;
   snw_flowset_t  *flowset;
   SSL_CTX        *ssl_ctx;
   snw_log_t      *log;
};

void
snw_websocket_init(snw_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* EVWS_EVWS_H_ */
