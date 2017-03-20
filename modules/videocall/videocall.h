#ifndef _SNOW_MODULE_VIDEOCALL_H_
#define _SNOW_MODULE_VIDEOCALL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "core.h"

void
module_init(void* ctx);

void
videocall_handle_msg(void *ctx, char *buffer, int len);


#ifdef __cplusplus
}
#endif

#endif // _SNOW_MODULE_VIDEOCALL_H_



