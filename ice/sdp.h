#ifndef _SNOW_ICE_SDP_H
#define _SNOW_ICE_SDP_H
   
#include <inttypes.h>
#include <sofia-sip/sdp.h>

#include "ice_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ice_sdp_attr ice_sdp_attr_t;
struct ice_sdp_attr {
   int audio;
   int video;
   //int data;
   int bundle;
   int rtcpmux;
   int trickle;
};

int
snw_ice_sdp_init(snw_ice_context_t *ctx);

void
snw_ice_sdp_deinit(void);

int
snw_ice_get_sdp_attr(snw_ice_context_t *ctx, char *sdp, ice_sdp_attr_t *sdp_attr);

sdp_parser_t *
snw_ice_sdp_get_parser(const char *jsep_sdp);

int 
snw_ice_sdp_handle_answer(snw_ice_session_t *session, sdp_parser_t *parser);

char*
snw_ice_sdp_merge(snw_ice_session_t *session, const char *origsdp);

int
snw_ice_sdp_handle_candidate(snw_ice_stream_t *stream, const char *candidate/*, int trickle*/);

#ifdef __cplusplus
}
#endif

#endif // _SNOW_ICE_SDP_H_


