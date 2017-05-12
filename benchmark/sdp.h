#ifndef _BENCHMARK_SDP_H_
#define _BENCHMARK_SDP_H_


#ifdef __cplusplus
extern "C" {
#endif

#include <sofia-sip/sdp.h>


int
sdp_init();

sdp_parser_t*
sdp_get_parser(const char *sdp);

#ifdef __cplusplus
}
#endif

#endif //_BENCHMARK_DTLS_H_

