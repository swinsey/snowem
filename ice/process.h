#ifndef _SNOW_ICE_PROCESS_H_
#define _SNOW_ICE_PROCESS_H_

#include "core.h"
#include "ice_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SDP offer/answer templates */
#define OPUS_PT   111
#define VP8_PT    100

void
snw_ice_process_msg(snw_ice_context_t *ice_ctx, char *data, uint32_t len, uint32_t flowid);

void 
ice_setup_remote_candidates(snw_ice_session_t *session, uint32_t stream_id, uint32_t component_id);

#ifdef __cplusplus
}
#endif

#endif // _SNOW_ICE_PROCESS_H_
