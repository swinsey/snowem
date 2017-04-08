#ifndef _SNOW_MODULES_DEMOCALL_DEMO_ROOM_H_
#define _SNOW_MODULES_DEMOCALL_DEMO_ROOM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "demo.h"

#define DEMO_ROOM_USER_MAXNUM 2

typedef struct demo_room demo_room_t;
struct demo_room {
   uint32_t roomid;
   uint32_t creatorid;
   uint32_t peerid;
};


#ifdef __cplusplus
}
#endif

#endif // _SNOW_MODULES_DEMOCALL_DEMOROOM_H_



