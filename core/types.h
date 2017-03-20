#ifndef _SNOW_CORE_TYPES_H_
#define _SNOW_CORE_TYPES_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct snw_log snw_log_t;
typedef struct snw_context snw_context_t;
typedef struct snw_module snw_module_t;

enum  SGN_CMD{
   SGN_ROOM = 1,
   SGN_REPLAY = 7,
   SGN_VIDEO = 8,
   SGN_INTERNAL = 9
};

enum SGN_REPLAY_SUBCMD {
   SGN_REPLAY_REQ = 1,
   SGN_REPLAY_SDP = 2,
   SGN_REPLAY_CANDIDATE = 3,
   SGN_REPLAY_CLOSE = 4,
};

enum SGN_VIDEO_SUBCMD {
   SGN_VIDEO_START = 1,
   SGN_VIDEO_STOP  = 2,
   SGN_VIDEO_VIEW  = 3,
   SGN_VIDEO_SDP   = 4,
   SGN_VIDEO_CANDIDATE = 5,
   SGN_VIDEO_FIR = 6,
};

enum SGN_INTERNAL_SUBCMD {
   SGN_INTERNAL_PEER_DATA = 2,
};


#define ENABLE_SNW_DEBUG
#define HEXDUMP(p,len,type)\
{\
   char __buf__[4*1024];\
   int i, j, _i;\
   DEBUG("---- dump buffer (%s) ---- len=%d",type,len);\
   for (i = 0; i < (int)len; ) {\
      memset(__buf__, sizeof(__buf__), ' ');\
      sprintf(__buf__, "%5d: ", i); \
      _i = i;\
      for (j=0; j < 16 && i < (int)len; i++, j++)\
         sprintf(__buf__ +7+j*3, "%02x ", (uint8_t)((p)[i]));\
      i = _i;   \
      for (j=0; j < 16 && i < (int)len; i++, j++)\
         sprintf(__buf__ +7+j + 48, "%c",\
            isprint((p)[i]) ? (p)[i] : '.'); \
      DEBUG("%s: %s", type, __buf__);\
   }\
}

#define SNW_USE(p) (void)(p);
#define SNW_MALLOC(type_) (type_*)malloc(sizeof(type_))
#define SNW_FREE(p_) { if (p_!=NULL) free(p_); }
#define SNW_MEMZERO(p_,type_) memset(p_,0,sizeof(type_))

#define MAX_BUFFER_SIZE 16*1024*1024

#ifdef __cplusplus
}
#endif

#endif //_SNOW_CORE_TYPES_H_



