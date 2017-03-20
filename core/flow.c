#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "flow.h"

snw_flowset_t*
snw_flowset_init(uint32_t num) {
   snw_flow_t *flow;
   snw_flowset_t *flowset;
   uint32_t i, size;
   uint32_t total_size;
   int res;

   flowset = (snw_flowset_t *)malloc(sizeof(*flowset));
   if (flowset == 0) {
      return 0;
   }
   size = (sizeof(snw_flow_t)+3) & ~0x3;
   total_size = num * size;

   res = posix_memalign((void **)&flowset->data, getpagesize(), total_size);
   if (res != 0) {
      //printf("posix_memalign failed, size=%ld\n", total_size);
      assert(0);
      if (flowset) free(flowset);
      return 0;
   }

   /* init flow set */
   flowset->totalnum = num;
   flowset->usednum = 0;
   INIT_LIST_HEAD(&flowset->freelist);
   INIT_LIST_HEAD(&flowset->usedlist);
   for (i = 1; i < num; i++) {
      flow = flowset->data + i;
      INIT_LIST_HEAD(&flow->list);
      flow->flowid = i;
      flow->obj = 0;
      list_add_tail(&flow->list, &flowset->freelist);
   }

   return flowset;
}

uint32_t
snw_flowset_getid(snw_flowset_t *s) {
   uint32_t id = 0;
   snw_flow_t *flow = 0;

   if (s == 0) return 0;

   if (!list_empty(&s->freelist)) {
      flow = list_first_entry(&s->freelist,snw_flow_t,list);
      id = flow->flowid;
      list_move_tail(&flow->list,&s->usedlist); 
      s->usednum++;
   } 

   return id;
}

void
snw_flowset_freeid(snw_flowset_t *s, uint32_t id) {
   snw_flow_t *flow = 0;

   if (s == 0 || id == 0)
      return;
   
   if (id >= s->totalnum)
      return;
   
   flow = s->data + id;
   flow->obj = 0;
   list_move_tail(&flow->list,&s->freelist);
   if (s->usednum == 0)
      return;
   else 
      s->usednum--;

   return;
}

void
snw_flowset_setobj(snw_flowset_t *s, uint32_t id, void *obj) {
   snw_flow_t *flow = 0;

   if (s == 0 || id == 0)
      return;
   
   if (id >= s->totalnum)
      return;
 
   flow = s->data + id; 
   flow->obj = obj;
   return;
}

void*
snw_flowset_getobj(snw_flowset_t *s, uint32_t id) {
   snw_flow_t *flow = 0;

   if (s == 0 || id == 0)
      return 0;
   
   if (id >= s->totalnum)
      return 0;
 
   flow = s->data + id; 
   return flow->obj;
}

void
snw_flowset_free(snw_flowset_t *set) {
   /*FIXME: impl*/
   return;
}





