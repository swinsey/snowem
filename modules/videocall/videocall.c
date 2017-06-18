#include <stdio.h>
#include <time.h>

#include "module.h"
#include "json/json.h"
#include "log.h"
#include "videocall.h"

void
snw_videocall_create(snw_context_t *ctx, snw_connection_t *conn, Json::Value &root) {
   snw_log_t *log = ctx->log;
   Json::FastWriter writer;
   std::string output;

   try {
      root["id"] = conn->flowid;
      root["rc"] = 0;
      output = writer.write(root);
      snw_shmmq_enqueue(ctx->snw_core2net_mq,0,output.c_str(),output.size(),conn->flowid);

      DEBUG(log,"videocall create, mq=%p, flowid=%u, len=%u, res=%s", 
                ctx->snw_core2net_mq, conn->flowid, output.size(), output.c_str());

   } catch (...) {
      ERROR(log, "json format error, data=%s", output.c_str());
      return;
   }

   return;
}

void
snw_videocall_handle_msg(void *p, void *conn, char *data, int len) {
   snw_module_t *module = (snw_module_t *)p;
   snw_context_t    *ctx = (snw_context_t*)module->ctx;
   snw_connection_t *c = (snw_connection_t*)conn;
   snw_log_t *log = ctx->log;
   Json::Value root;
   Json::Reader reader;
   uint32_t type = 0, api = 0;
   int ret;

   ret = reader.parse(data,data+len,root,0);
   if (!ret) {
      ERROR(log,"error json format, s=%s",data);
      return;
   }

   DEBUG(log, "get msg, flowid=%u, data=%s", c->flowid, data);
   try {
      type = root["msgtype"].asUInt();
      if (type!=SNW_VIDEOCALL) {
         ERROR(log,"wrong type, s=%s",data);
         return;
      }
      api = root["api"].asUInt();
      
   } catch (...) {
      ERROR(log, "json format error, data=%s", data);
      return;
   }

   switch(api) {
      case SNW_VIDEOCALL_CREATE:
         snw_videocall_create(ctx,c,root);
         break;

      default:
         ERROR(log, "unknow api, api=%u", api);
         break;
   }




   return;
}


snw_module_methods_t videocall_methods = {
   .handle_msg = snw_videocall_handle_msg
};

void
module_init(void* ctx) {
   snw_module_t *module = (snw_module_t *)ctx;

   module->methods = &videocall_methods;

   printf("videocall init\n");

   return;
}


