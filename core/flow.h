#ifndef _SNOW_CORE_FLOW_H_
#define _SNOW_CORE_FLOW_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "linux_list.h"

typedef struct snw_flow snw_flow_t;
struct snw_flow {
   struct list_head  list;
   uint32_t  flowid;
   void     *obj;
};

typedef struct snw_flowset snw_flowset_t;
struct snw_flowset {
   struct list_head  freelist;
   struct list_head  usedlist;
   uint32_t          totalnum;
   uint32_t          usednum;
   uint32_t          baseidx;

   snw_flow_t       *data;
};

snw_flowset_t*
snw_flowset_init(uint32_t num);

uint32_t
snw_flowset_getid(snw_flowset_t *s);

void
snw_flowset_freeid(snw_flowset_t *s, uint32_t id);

void
snw_flowset_setobj(snw_flowset_t *s, uint32_t id, void *obj);

void*
snw_flowset_getobj(snw_flowset_t *s, uint32_t id);

void
snw_flowset_free(snw_flowset_t *s);

int
snw_flowset_is_in_range(snw_flowset_t *s, uint32_t id);

#ifdef __cplusplus
}
#endif

#endif //_SNOW_CORE_FLOW_H_
