#ifndef _SNOW_MODULES_MODULE_H_
#define _SNOW_MODULES_MODULE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "core.h"

/* Built-in module type */
enum {
   SNW_MIN = 1,
   SNW_ICE = SNW_MIN,
   SNW_RTP = 2,
   SNW_RTCP = 3,

   /* reserve range */
   SNW_MAX = 255,
};

/* ICE api */
enum {
   SNW_ICE_MIN = 1,
   SNW_ICE_CREATE = SNW_ICE_MIN,
   SNW_ICE_START = 2,
   SNW_ICE_STOP = 3,
   SNW_ICE_SDP = 4,
   SNW_ICE_CANDIDATE = 5,

   /* reserve range */
   SNW_ICE_MAX = 255,
};

typedef struct snw_module_callbacks snw_module_callbacks_t;
struct snw_module_callbacks {

int   (*enqueue)(void *mq, const time_t curtime, const void* data, 
                 uint32_t len, uint32_t flow);
};

typedef struct snw_module_methods snw_module_methods_t;
struct snw_module_methods {
   void               (*handle_msg)(void *ctx, void *conn, char *buffer, int len);
};

struct snw_module {
   uint32_t              type; //module type
   uint32_t              version;
   char                 *name;
   char                 *sofile;
   snw_module_methods_t *methods;

   void               (*init)(void *ctx);
   void               (*fini)();

   char                 reserve[128];
};

void
snw_module_init(snw_context_t *ctx);

void
snw_module_enqueue(void *mq, const time_t curtime, const void* data,
                  uint32_t len, uint32_t flow);


#ifdef __cplusplus
}
#endif

#endif //_SNOW_MODULES_MODULE_H_



