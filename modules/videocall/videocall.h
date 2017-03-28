#ifndef _SNOW_MODULES_VIDEOCALL_VIDEOCALL_H_
#define _SNOW_MODULES_VIDEOCALL_VIDEOCALL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "core.h"

/* module type */
#define SNW_VIDEOCALL 0x564443

/* module api */
#define SNW_VIDEOCALL_CREATE 1

typedef struct snw_videocall_context snw_videocall_context_t;
struct snw_videocall_context {
   
};


void
module_init(void* ctx);

void
snw_videocall_handle_msg(void *ctx, void *conn, char *data, int len);


#ifdef __cplusplus
}
#endif

#endif // _SNOW_MODULES_VIDEOCALL_VIDEOCALL_H_



