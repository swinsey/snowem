#ifndef _BENCHMARK_UTIL_H
#define _BENCHMARK_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>

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

#ifdef __cplusplus
}
#endif

#endif // _BENCHMARK_UTIL_H
