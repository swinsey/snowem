#ifndef _BENCHMARK_UTIL_H
#define _BENCHMARK_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>

#define HEXDUMP(_p,len,type)\
{\
   char __buf__[4*1024];\
   char *p = (char*)_p;\
   int i, j, _i;\
   STUN_DEBUG("---- dump buffer (%s) ---- len=%lu",type,len);\
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
      STUN_DEBUG("%s: %s", type, __buf__);\
   }\
}


enum ws_header {
  NOT_RELEVANT = 0,
  UPGRADE = 1,
  CONNECTION = 2,
  SEC_WEBSOCKET_KEY = 3,
  SEC_WEBSOCKET_VERSION = 4,
  SEC_WEBSOCKET_PROTOCOL = 5,
};

struct http_wsparse_info {
  const char** supported_subprotocols;
  char *accept_key;
  const char** subprotocol;
  unsigned char found_upgrade : 1;
  unsigned char found_connection : 1;
  unsigned char found_key : 1;
  unsigned char found_version : 1;
  // internal use
  enum ws_header header;
};

#define DEBUG(fmt,...)\
    { log_write(__FUNCTION__, __LINE__,fmt, ##__VA_ARGS__); }
    //{ log_write(__FILE__, __LINE__,fmt, ##__VA_ARGS__); }

void log_write(const char* sourcefilename, int line, const char* msg, ...);

int64_t get_real_time(void);

int64_t get_monotonic_time(void);

#ifdef __cplusplus
}
#endif

#endif // _BENCHMARK_UTIL_H
