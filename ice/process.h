#ifndef _SNOW_ICE_PROCESS_H_
#define _SNOW_ICE_PROCESS_H_

#include "core.h"
#include "ice_types.h"

#ifdef __cplusplus
extern "C" {
#endif

void
snw_ice_process_msg(snw_ice_context_t *ice_ctx, char *data, uint32_t len, uint32_t flowid);

#ifdef __cplusplus
}
#endif

#endif // _SNOW_ICE_PROCESS_H_
