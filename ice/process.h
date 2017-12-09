#ifndef _SNOW_ICE_PROCESS_H_
#define _SNOW_ICE_PROCESS_H_

<<<<<<< HEAD
#include "core.h"
=======
#include "core/core.h"
>>>>>>> dev
#include "ice_types.h"

#ifdef __cplusplus
extern "C" {
#endif

<<<<<<< HEAD
/* SDP offer/answer templates */
=======
>>>>>>> dev
#define OPUS_PT   111
#define VP8_PT    100

void
snw_ice_process_msg(snw_ice_context_t *ice_ctx, char *data, uint32_t len, uint32_t flowid);

void 
ice_setup_remote_candidates(snw_ice_session_t *session, uint32_t stream_id, uint32_t component_id);

void
ice_srtp_handshake_done(snw_ice_session_t *session, snw_ice_component_t *component);

void 
send_rtp_pkt(snw_ice_session_t *session, int control, int video, char* buf, int len);

#ifdef __cplusplus
}
#endif

#endif // _SNOW_ICE_PROCESS_H_
