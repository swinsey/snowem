#ifndef _SNOW_MODULES_MODULE_H_
#define _SNOW_MODULES_MODULE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "core.h"

enum {
   SNW_MIN = 1,
   SNW_ICE = SNW_MIN,
   SNW_RTP = 2,
   SNW_RTCP = 3,
   SNW_RSTP = 4,
   /* reserve range */
   SNW_MAX = 255,
};

typedef struct snw_module_methods snw_module_methods_t;
struct snw_module_methods {
   void               (*handle_msg)(void *ctx, char *buffer, int len);
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


#ifdef __cplusplus
}
#endif

#endif //_SNOW_MODULES_MODULE_H_



