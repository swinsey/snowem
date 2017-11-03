#ifndef _SNOW_CORE_TYPES_H_
#define _SNOW_CORE_TYPES_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CORE_CHANNEL_SHM_KEY   0x081001
#define CORE_CHANNEL_HASHTIME  10
#define CORE_CHANNEL_HASHLEN   100

#define CORE_PEER_SHM_KEY   0x081002
#define CORE_PEER_HASHTIME  10
#define CORE_PEER_HASHLEN   100



typedef struct snw_log snw_log_t;
typedef struct snw_context snw_context_t;
typedef struct snw_module snw_module_t;

#define ENABLE_SNW_DEBUG
#define HEXDUMP(log,p,len,type)\
{\
   char __buf__[4*1024];\
   int i, j, _i;\
   DEBUG(log,"---- dump buffer (%s) ---- len=%d",type,len);\
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
      DEBUG(log, "%s: %s", type, __buf__);\
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



