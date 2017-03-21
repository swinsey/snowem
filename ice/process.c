
#include "module.h"
#include "mq.h"
#include "ice_session.h"
#include "json/json.h"
#include "process.h"
#include "utils.h"


void
snw_ice_create(snw_ice_context_t *ice_ctx, Json::Value &root, uint32_t flowid) {
   snw_context_t *ctx = (snw_context_t*)ice_ctx->ctx;
   snw_log_t *log = ice_ctx->log;
   Json::FastWriter writer;
   std::string output;

   try {
      root["id"] = flowid;
      root["sessionid"] = flowid;
      root["rc"] = 0;
      output = writer.write(root);
      snw_shmmq_enqueue(ctx->snw_ice2core_mq,0,output.c_str(),output.size(),flowid);

      DEBUG(log,"ice create, mq=%p, flowid=%u, len=%u, res=%s", 
                ctx->snw_ice2core_mq, flowid, output.size(), output.c_str());

   } catch (...) {
      ERROR(log, "json format error, data=%s", output.c_str());
      return;
   }

   return;
}

//video_offer_sdp
static int
snw_ice_offer_sdp(snw_ice_context_t *ice_ctx, 
      snw_ice_session_t *session, uint32_t flowid, int sendonly) {
   snw_log_t *log = ice_ctx->log;
   char sdptemp[1024], audio_mline[256], video_mline[512];

   DEBUG(log,"sendonly=%u",sendonly);

   memset(audio_mline,0,512);
   snprintf(audio_mline, 256, sdp_audio_mline,
       OPUS_PT, sendonly ? "sendonly" : "sendrecv", OPUS_PT);

   memset(video_mline,0,512);
   snprintf(video_mline, 512, sdp_video_mline,
       VP8_PT, sendonly ? "sendonly" : "sendrecv",
       VP8_PT, VP8_PT, VP8_PT, VP8_PT, VP8_PT);

   memset(sdptemp,0,1024);
   snprintf(sdptemp, 1024, sdp_template,
       get_real_time(), get_real_time(),
       "PeerCall Replay", audio_mline, video_mline);

   session->tempsdp = strdup(sdptemp);
   //handle_sdp(session,sdptemp);

   return 0;
}

//video_start_handler
void
snw_ice_start(snw_ice_context_t *ice_ctx, Json::Value &root, uint32_t flowid, uint32_t is_publisher) {
   snw_context_t *ctx = (snw_context_t*)ice_ctx->ctx;
   snw_log_t *log = ice_ctx->log;
   snw_ice_session_t key;
   snw_ice_session_t *session;
   int is_new = 0;
   
   /*
   try {
      Json::FastWriter writer;
      std::string output;
      root["id"] = flowid;
      root["sessionid"] = flowid;
      root["rc"] = 0;
      output = writer.write(root);
      DEBUG(log,"ice start, flowid=%u, len=%u, root=%s", 
                flowid, output.size(), output.c_str());

   } catch (...) {
      ERROR(log, "json format error, data=%s", output.c_str());
      return;
   }*/

   session = (snw_ice_session_t*)ice_session_get(ice_ctx,flowid,&is_new);
   if (session == NULL) {
      ERROR(log,"failed to malloc, flowid=%u",flowid);
      return;
   }

   if (!is_new) {
      ERROR(log,"old session, flowid=%u",session->flowid);
      return;
   }

   DEBUG(log,"init new session, flowid=%u",session->flowid);
   //session->flowid = flowid;
   session->controlling = 0;
   session->base = ctx->ev_base;
   session->ready = 0;
   session->flags = 0;
   if ( is_publisher ) {
      SET_FLAG(session,ICE_PUBLISHER);
   } else {
      SET_FLAG(session,ICE_SUBSCRIBER);
   }
   INIT_LIST_HEAD(&session->streams.list);
 
   snw_ice_offer_sdp(ice_ctx,session,flowid,0);
   return;
}

void
snw_ice_process_msg(snw_ice_context_t *ice_ctx, char *data, uint32_t len, uint32_t flowid) {
   snw_log_t *log = ice_ctx->log;
   Json::Value root;
   Json::Reader reader;
   Json::FastWriter writer;
   std::string output;
   uint32_t msgtype = 0, api = 0, is_publisher = 0;
   int ret;

   ret = reader.parse(data,data+len,root,0);
   if (!ret) {
      ERROR(log,"error json format, s=%s",data);
      return;
   }
   DEBUG(log, "get ice msg, data=%s", data);
   try {
      msgtype = root["msgtype"].asUInt();
      if (msgtype != SNW_ICE) {
         ERROR(log, "wrong msg, msgtype=%u data=%s", msgtype, data);
         return;
      }
      api = root["api"].asUInt();
      is_publisher = root["publish"].asUInt();
   } catch (...) {
      ERROR(log, "json format error, data=%s", data);
   }

   switch(api) {
      case SNW_ICE_CREATE:
         snw_ice_create(ice_ctx,root,flowid);
         break;
      case SNW_ICE_START:
         snw_ice_start(ice_ctx,root,flowid,is_publisher);
         break;

      default:
         ERROR(log, "unknow api, api=%u", api);
         break;
   }




   return;
}


