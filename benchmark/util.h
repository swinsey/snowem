#ifndef _BENCHMARK_UTIL_H

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


#endif // _BENCHMARK_UTIL_H
