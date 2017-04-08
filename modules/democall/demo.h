#ifndef _SNOW_MODULES_DEMOCALL_DEMOCALL_H_
#define _SNOW_MODULES_DEMOCALL_DEMOCALL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "core.h"

/* module type */
#define SNW_DEMO 0x44454D4F

/* module api */
#define SNW_DEMO_CONNECT       1
#define SNW_DEMO_JOIN_ROOM     2
#define SNW_DEMO_ROOM_READY    3
#define SNW_DEMO_ICE_START     4
#define SNW_DEMO_ICE_SDP       5
#define SNW_DEMO_ICE_CANDIDATE 6
#define SNW_DEMO_MSG           7

/* session key*/
#define SNW_DEMO_KEY      0x44454D4F
#define SNW_DEMO_HASHLEN  1024
#define SNW_DEMO_HASHTIME 10

typedef struct snw_demo_context snw_demo_context_t;
struct snw_demo_context {
   snw_hashbase_t *session_cache;
};

void
module_init(void* ctx);

void
snw_democall_handle_msg(void *ctx, void *conn, char *data, int len);


#ifdef __cplusplus
}
#endif

#endif // _SNOW_MODULES_DEMOCALL_DEMOCALL_H_



