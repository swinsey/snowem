#ifndef _SNOW_CORE_CHANNEL_MGR_H_
#define _SNOW_CORE_CHANNEL_MGR_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define MAX_CHANNEL_NUM 10000

typedef struct snw_channel_mgr snw_channel_mgr_t;
struct snw_channel_mgr {
   uint32_t cur_pos;
   uint32_t channels[MAX_CHANNEL_NUM];
};

#ifdef __cplusplus
}
#endif

#endif // _CHANNEL_MGR_H_







