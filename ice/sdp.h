#ifndef _ICE_SDP_H
#define _ICE_SDP_H
   
#include <inttypes.h>
#include <sofia-sip/sdp.h>

#include "ice_types.h"

/*typedef struct ice_sdp ice_sdp_t;
struct ice_sdp {
   void *parser;
   void *sdp;  
};*/

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
ice_sdp_init(snw_ice_context_t *ctx);

void
ice_sdp_deinit(void);

sdp_parser_t *ice_sdp_get_parser(const char *jsep_sdp);
int ice_get_sdp_attr(sdp_parser_t *parser, ice_sdp_attr_t *sdp_attr);
int ice_sdp_handle_answer(snw_ice_session_t *session, sdp_parser_t *parser);
char* ice_sdp_merge(snw_ice_session_t *session, const char *origsdp);
int ice_sdp_handle_candidate(snw_ice_stream_t *stream, const char *candidate/*, int trickle*/);

#endif // _ICE_SDP_H_


