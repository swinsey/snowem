#ifndef _SNOW_ICE_ICETYPES_H_
#define _SNOW_ICE_ICETYPES_H_

#include <stdint.h>
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ice_session ice_session_t;
typedef struct ice_stream ice_stream_t;
typedef struct ice_component ice_component_t;
typedef struct snw_ice_context snw_ice_context_t;

#define ENABLE_SNW_DEBUG
#define PRINT_CANDIDATE(c_)\
{\
   char address[SNW_ADDRESS_STRING_LEN];\
   int port = address_get_port(&(c_->addr));\
   address_to_string(&(c_->addr), (char *)&address);\
   DEBUG("Address:    %s:%d", address, port);\
   DEBUG("Priority:   %d", c_->priority);\
   DEBUG("Foundation: %s", c_->foundation);\
   DEBUG("Username:   %s", c_->username);\
   DEBUG("Password:   %s", c_->password);\
} while(0);

#define ICE_DEBUG2(...) do {} while(0)
#define ICE_ERROR2(...) do {} while(0)

#define SNW_BUFSIZE   8192
#define SNW_USEC_PER_SEC 1000000

//status
#define WEBRTC_START           0x0001
#define WEBRTC_READY           0x0002

//features
#define WEBRTC_BUNDLE          0x0004
#define WEBRTC_RTCPMUX         0x0008
#define WEBRTC_TRICKLE         0x0010
#define WEBRTC_GATHER_DONE     0x0020
#define WEBRTC_AUDIO           0x0040
#define WEBRTC_VIDEO           0x0080

// client role
#define ICE_SENDER             0x0100
#define ICE_RECEIVER           0x0200
#define ICE_REPLAY             0x0400


#define IS_FLAG(f,i) ((f->flags & i) != 0)
#define SET_FLAG(f,i) (f->flags |= i)
#define CLEAR_FLAG(f,i) (f->flags &= ~i)


#define RTP_PROFILE       "RTP/SAVPF"
#define RTP_OPUS_FORMAT   "111"
#define RTP_VP8_FORMAT    "100"
#define NO_FORMAT         "0"

#ifdef __cplusplus
}
#endif

#endif //_SNOW_CORE_TYPES_H_



