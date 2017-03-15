#ifndef _RECORDPLAY_H_
#define _RECORDPLAY_H_

#include "session.h"
#include "types.h"

/* SDP offer/answer templates for the playout */
#define OPUS_PT      111
#define VP8_PT    100
#define sdp_template \
      "v=0\r\n" \
      "o=- %lu %lu IN IP4 127.0.0.1\r\n"  /* We need current time here */ \
      "s=%s\r\n"                    /* Recording playout id */ \
      "t=0 0\r\n" \
      "%s%s"                        /* Audio and/or video m-lines */
#define sdp_a_template \
      "m=audio 1 RTP/SAVPF %d\r\n"     /* Opus payload type */ \
      "c=IN IP4 1.1.1.1\r\n" \
      "a=%s\r\n"                    /* Media direction */ \
      "a=rtpmap:%d opus/48000/2\r\n"      /* Opus payload type */
#define sdp_v_template \
      "m=video 1 RTP/SAVPF %d\r\n"     /* VP8 payload type */ \
      "c=IN IP4 1.1.1.1\r\n" \
      "a=%s\r\n"                    /* Media direction */ \
      "a=rtpmap:%d VP8/90000\r\n"         /* VP8 payload type */ \
      "a=rtcp-fb:%d ccm fir\r\n"       /* VP8 payload type */ \
      "a=rtcp-fb:%d nack\r\n"          /* VP8 payload type */ \
      "a=rtcp-fb:%d nack pli\r\n"         /* VP8 payload type */ \
      "a=rtcp-fb:%d goog-remb\r\n"     /* VP8 payload type */


void
record_start(ice_session_t *handle);

#endif // _RECORDPLAY_H_
