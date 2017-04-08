#include <stdio.h>
#include <time.h>
//#include <unistd.h>

#include "connection.h"
#include "module.h"
#include "json/json.h"
#include "log.h"
#include "demo.h"
#include "demo_session.h"

uint32_t
snw_demo_room_create(snw_module_t *module, uint32_t flowid) {
   snw_context_t    *ctx = (snw_context_t*)module->ctx;
   snw_demo_context_t    *demo_ctx = (snw_demo_context_t*)module->data;
   snw_log_t        *log = ctx->log;
   snw_demo_session_t *session;
   uint32_t roomid = 0;
   int is_new = 0;
   int cnt = 0;

   while (cnt<3) {
      roomid = rand();
      session = snw_demo_session_get(demo_ctx,roomid,&is_new);
      if (!session || is_new) {
         /* setup session */
         DEBUG(log,"new room created, roomid=%u",roomid);
         //session->flowid = flowid;
         return roomid;
      }

      /* old or null session - choose other room */
      cnt++;
   } 

   return 0;
}

void
snw_demo_connect(snw_module_t *module, snw_connection_t *conn, Json::Value &root) {
   snw_context_t    *ctx = (snw_context_t*)module->ctx;
   snw_log_t        *log = ctx->log;
   Json::FastWriter  writer;
   std::string       output;
   uint32_t          roomid; 

   try {

      if (root["room"].isNull()) {
         roomid = snw_demo_room_create(module,conn->flowid);
         root["id"] = conn->flowid;
         root["room"] = roomid;
         root["created"] = 1;

         if (roomid != 0 )
            root["rc"] = 0;
         else
            root["rc"] = -1;

         output = writer.write(root);
         snw_shmmq_enqueue(ctx->snw_core2net_mq,0,output.c_str(),output.size(),conn->flowid);

         DEBUG(log,"democall connect, mq=%p, flowid=%u, len=%u, res=%s", 
                ctx->snw_core2net_mq, conn->flowid, output.size(), output.c_str());
      } else {
         roomid = root["room"].asUInt();
         /* check & update roomid */

         root["id"] = conn->flowid;
         root["created"] = 0;
         root["rc"] = 0;
         output = writer.write(root);
         snw_shmmq_enqueue(ctx->snw_core2net_mq,0,output.c_str(),output.size(),conn->flowid);

         DEBUG(log,"democall connect, mq=%p, flowid=%u, len=%u, res=%s", 
                ctx->snw_core2net_mq, conn->flowid, output.size(), output.c_str());

      }

   } catch (...) {
      ERROR(log, "json format error, data=%s", output.c_str());
      return;
   }
   return;
}

void
snw_demo_join_room(snw_module_t *module, snw_connection_t *conn, Json::Value &root) {
   snw_context_t    *ctx = (snw_context_t*)module->ctx;
   snw_demo_context_t    *demo_ctx = (snw_demo_context_t*)module->data;
   snw_log_t        *log = ctx->log;
   snw_demo_session_t *session;
   std::string output;
   Json::FastWriter writer;
   Json::Value msg;
   uint32_t roomid = 0;
   uint32_t flowid = 0;
   int is_broadcast = 0;

   try {
      roomid = root["roomid"].asUInt();
      flowid = root["flowid"].asUInt();
      DEBUG(log, "search room, roomid=%u, flowid=%u",roomid, flowid);
      session = snw_demo_session_search(demo_ctx,roomid);
      if (!session) {
         root["rc"] = -1;
      } else {
         root["rc"] = 0;
         if (session->creatorid == 0) {
            session->creatorid = conn->flowid;
         } else {
            session->peerid = conn->flowid;
            is_broadcast = 1;
         }
         output = writer.write(root);
      }

   } catch (...) {
      root["rc"] = -1;
      output = writer.write(root);
      ERROR(log, "json format error, data=%s", output.c_str());
      return;
   }
   snw_shmmq_enqueue(ctx->snw_core2net_mq,0,output.c_str(),output.size(),conn->flowid);

   if (is_broadcast) {
      msg["msgtype"] = SNW_DEMO;
      msg["api"] = SNW_DEMO_ROOM_READY;
      msg["roomid"] = session->roomid;
      msg["creatorid"] = session->creatorid;
      msg["peerid"] = session->peerid;
      output = writer.write(msg);
      DEBUG(log, "broadcast msg, creator=%u, peerid=%u", session->creatorid, session->peerid);
      snw_shmmq_enqueue(ctx->snw_core2net_mq,0,output.c_str(),output.size(),session->creatorid);
      snw_shmmq_enqueue(ctx->snw_core2net_mq,0,output.c_str(),output.size(),session->peerid);
   }
   return;
}

void
snw_demo_ice_start(snw_module_t *module, snw_connection_t *conn, Json::Value &root) {
   snw_context_t    *ctx = (snw_context_t*)module->ctx;
   snw_demo_context_t    *demo_ctx = (snw_demo_context_t*)module->data;
   snw_log_t        *log = ctx->log;
   snw_demo_session_t *session;
   std::string output;
   Json::FastWriter writer;
   Json::Value msg;
   uint32_t roomid = 0;
   uint32_t creatorid = 0;
   uint32_t peerid = 0;

   try {
      roomid = root["roomid"].asUInt();
      creatorid = root["creatorid"].asUInt();
      peerid = root["peerid"].asUInt();
      if (!roomid || !creatorid || !peerid) {
         ERROR(log, "wrong msg, roomid=%u, creatorid=%u, peerid=%u", 
                    roomid, creatorid, peerid);
         return;
      }

      DEBUG(log, "search room, roomid=%u, flowid=%u",roomid, conn->flowid);
      session = snw_demo_session_search(demo_ctx,roomid);
      if (!session) {
         ERROR(log, "wrong msg, roomid=%u, creatorid=%u, peerid=%u", 
                    roomid, creatorid, peerid);
         return;
      }

      if (session->creatorid != creatorid) {
         ERROR(log, "creatorid mismatch, roomid=%u, creatorid=%u, id=%u", 
                    roomid, creatorid, session->creatorid);
         return;
      } else {
         output = writer.write(root);
         snw_shmmq_enqueue(ctx->snw_core2net_mq,0,output.c_str(),output.size(),peerid);
      }
      

   } catch (...) {
      output = writer.write(root);
      ERROR(log, "json format error, data=%s", output.c_str());
      return;
   }

   return;
}


void
snw_demo_ice_sdp(snw_module_t *module, snw_connection_t *conn, Json::Value &root) {
   snw_context_t    *ctx = (snw_context_t*)module->ctx;
   snw_demo_context_t    *demo_ctx = (snw_demo_context_t*)module->data;
   snw_log_t        *log = ctx->log;
   snw_demo_session_t *session;
   std::string output;
   Json::FastWriter writer;
   Json::Value msg;
   uint32_t roomid = 0;
   uint32_t creatorid = 0;
   uint32_t peerid = 0;

   try {
      roomid = root["roomid"].asUInt();
      creatorid = root["creatorid"].asUInt();
      peerid = root["peerid"].asUInt();
      if (!roomid || !creatorid || !peerid) {
         ERROR(log, "wrong msg, roomid=%u, creatorid=%u, peerid=%u", 
                    roomid, creatorid, peerid);
         return;
      }

      DEBUG(log, "search room, roomid=%u, flowid=%u",roomid, conn->flowid);
      session = snw_demo_session_search(demo_ctx,roomid);
      if (!session) {
         ERROR(log, "wrong msg, roomid=%u, creatorid=%u, peerid=%u", 
                    roomid, creatorid, peerid);
         return;
      }

      if (session->creatorid == conn->flowid) {
         DEBUG(log, "send peerid, roomid=%u, creatorid=%u, id=%u", 
                    roomid, creatorid, session->peerid);
         output = writer.write(root);
         snw_shmmq_enqueue(ctx->snw_core2net_mq,0,output.c_str(),output.size(),session->peerid);
      } else if (session->peerid == conn->flowid) {
         DEBUG(log, "send creatorid, roomid=%u, creatorid=%u, id=%u", 
                    roomid, creatorid, session->creatorid);
         output = writer.write(root);
         snw_shmmq_enqueue(ctx->snw_core2net_mq,0,output.c_str(),output.size(),session->creatorid);
      } else {
         DEBUG(log, "wrong msg, roomid=%u, creatorid=%u, id=%u", 
                    roomid, creatorid, session->creatorid);
      }

      //sleep(2);
   } catch (...) {
      output = writer.write(root);
      ERROR(log, "json format error, data=%s", output.c_str());
      return;
   }

   return;
}

void
snw_demo_ice_candidate(snw_module_t *module, snw_connection_t *conn, Json::Value &root) {
   snw_context_t    *ctx = (snw_context_t*)module->ctx;
   snw_log_t        *log = ctx->log;
   std::string output;
   Json::FastWriter writer;
   Json::Value msg;
   uint32_t peerid = 0;

   try {
      peerid = root["peerid"].asUInt();
      if (!peerid) {
         ERROR(log, "wrong msg, peerid=%u", peerid);
         return;
      }

      output = writer.write(root);
      snw_shmmq_enqueue(ctx->snw_core2net_mq,0,output.c_str(),output.size(),peerid);

   } catch (...) {
      output = writer.write(root);
      ERROR(log, "json format error, data=%s", output.c_str());
      return;
   }

   return;
}

void
snw_demo_msg(snw_module_t *module, snw_connection_t *conn, Json::Value &root) {
   snw_context_t    *ctx = (snw_context_t*)module->ctx;
   snw_log_t        *log = ctx->log;
   std::string output;
   Json::FastWriter writer;
   Json::Value msg;
   uint32_t peerid = 0;

   try {
      peerid = root["peerid"].asUInt();
      if (!peerid) {
         ERROR(log, "wrong msg, peerid=%u", peerid);
         return;
      }

      output = writer.write(root);
      snw_shmmq_enqueue(ctx->snw_core2net_mq,0,output.c_str(),output.size(),peerid);

   } catch (...) {
      output = writer.write(root);
      ERROR(log, "json format error, data=%s", output.c_str());
      return;
   }

   return;
}


void
snw_demo_handle_msg(void *p, void *conn, char *data, int len) {
   snw_module_t     *module = (snw_module_t*)p;
   snw_context_t    *ctx = (snw_context_t*)module->ctx;
   //snw_demo_context_t    *demo_ctx = (snw_demo_context_t*)module->data;
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
      if (type!=SNW_DEMO) {
         ERROR(log,"wrong type, s=%s",data);
         return;
      }
      api = root["api"].asUInt();
      
   } catch (...) {
      ERROR(log, "json format error, data=%s", data);
      return;
   }

   switch(api) {
      case SNW_DEMO_CONNECT:
         snw_demo_connect(module,c,root);
         break;
      case SNW_DEMO_JOIN_ROOM:
         snw_demo_join_room(module,c,root);
         break;
      case SNW_DEMO_ICE_START:
         snw_demo_ice_start(module,c,root);
         break;
      case SNW_DEMO_ICE_SDP:
         snw_demo_ice_sdp(module,c,root);
         break;
      case SNW_DEMO_ICE_CANDIDATE:
         snw_demo_ice_candidate(module,c,root);
         break;
      case SNW_DEMO_MSG:
         snw_demo_msg(module,c,root);
         break;

      default:
         ERROR(log, "unknown api, api=%u", api);
         break;
   }




   return;
}


snw_module_methods_t democall_methods = {
   .handle_msg = snw_demo_handle_msg
};

void
module_init(void* p) {
   snw_module_t *module = (snw_module_t *)p;
   snw_demo_context_t *demo_ctx = 0;

   demo_ctx = (snw_demo_context_t*)malloc(sizeof(snw_demo_context_t));
   if (!demo_ctx) return;
   module->data = demo_ctx;
   module->methods = &democall_methods;

   snw_demo_session_init(demo_ctx);

   printf("democall init\n");

   return;
}


