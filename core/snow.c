
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <json/json.h>

#include "channel.h"
#include "conf.h"
#include "connection.h"
#include "core.h"
#include "log.h"
#include "module.h"
#include "peer.h"
#include "snow.h"
#include "snw_event.h"
#include "utils.h"

int
snw_ice_handler(snw_context_t *ctx, snw_connection_t *conn, uint32_t type, char *data, uint32_t len) {

   DEBUG(ctx->log, "ice handler, flowid=%u, len=%u", conn->flowid, len);
   snw_shmmq_enqueue(ctx->snw_core2ice_mq, 0, data, len, conn->flowid);
   return 0;
}

int
snw_sig_auth_msg(snw_context_t *ctx, snw_connection_t *conn, Json::Value &root) {
   snw_log_t *log = ctx->log;
   snw_peer_t *peer = 0;
   Json::FastWriter writer;
   std::string output;
   std::string auth_data;
   uint32_t peerid = 0;
   int is_new = 0;
   
   try {
      auth_data = root["auth_data"].asString();
      DEBUG(log,"auth_data, s=%s", auth_data.c_str());

      //FIXME: send event to redis, and get id instead of using flowid.
      peerid = conn->flowid; 
      peer = snw_peer_get(ctx->peer_cache,peerid,&is_new);
      if (peer == 0) {
         ERROR(log, "can not create peer, flowid=%u", conn->flowid);
         return -1;
      }
      if (!is_new) {
         ERROR(log,"reseting existing peer, flowid=%u", conn->flowid);
         memset(peer,0,sizeof(snw_peer_t));
         peer->peerid = peerid;
      }
      peer->flowid = conn->flowid;

      root["id"] = peer->peerid;
      root["rc"] = 0;
      output = writer.write(root);
      snw_shmmq_enqueue(ctx->snw_core2net_mq,0,output.c_str(),output.size(),peer->flowid);
   } catch (...) {
      ERROR(log, "json format error");
      return -1;
   }
   return 0;
}

int
snw_sig_create_msg(snw_context_t *ctx, snw_connection_t *conn, Json::Value &root) {
   snw_log_t *log = ctx->log;
   Json::FastWriter writer;
   std::string output;
   snw_channel_t *channel = 0;
   snw_peer_t *peer = 0;
   uint32_t channelid = 0;
   uint32_t peerid = 0;
   int is_new = 0;
   
   try {
      peerid = root["id"].asUInt();
      peer = snw_peer_search(ctx->peer_cache,peerid);
      if (!peer) {
         ERROR(log, "peer not found, flowid=%u, peerid=%u", conn->flowid, peerid);
         return -1;
      }

      //Step1: get channel id from a pool.
      channelid = snw_set_getid(ctx->channel_mgr);
      if (channelid == 0) {
         ERROR(log, "can not create channel, flowid=%u", conn->flowid);
         return -1;
      }

      //Step2: get channel object.
      channel = snw_channel_get(ctx->channel_cache,channelid,&is_new);
      if (channel == 0) {
         ERROR(log, "can not create channel, flowid=%u", conn->flowid);
         return -1;
      }
      if (!is_new) {
         ERROR(log,"reseting existing channel, channelid=%u",channelid);
         memset(channel,0,sizeof(snw_channel_t));
         channel->id = channelid;
      }
      channel->flowid = conn->flowid;
      channel->peerid = peer->peerid;
      peer->channelid = channelid;
       
      DEBUG(log,"create channel, channelid=%u", channelid);
      root["channelid"] = channelid;
      root["rc"] = 0;
      output = writer.write(root);
      snw_shmmq_enqueue(ctx->snw_core2net_mq,0,output.c_str(),output.size(),conn->flowid);

      //inform ice component about new channel
      root["msgtype"] = SNW_ICE;
      root["api"] = SNW_ICE_CREATE;
      output = writer.write(root);
      snw_shmmq_enqueue(ctx->snw_core2ice_mq,0,output.c_str(),output.size(),conn->flowid);
   } catch (...) {
      ERROR(log, "json format error");
      return -1;
   }
   return 0;
}

int
snw_sig_connect_msg(snw_context_t *ctx, snw_connection_t *conn, Json::Value &root) {
   snw_log_t *log = ctx->log;
   Json::FastWriter writer;
   snw_peer_t *peer = 0;
   snw_channel_t *channel = 0;
   std::string output;
   std::string peer_type;
   uint32_t channelid = 0;
   uint32_t peerid = 0;
   int forward_to_ice = 0;
   
   //snw_ice_connect_msg
   try {
      peerid = root["id"].asUInt();
      channelid = root["channelid"].asUInt();
      peer_type = root["peer_type"].asString();
   } catch (...) {
      ERROR(log, "json format error");
      return -1;
   }

   channel = snw_channel_search(ctx->channel_cache,channelid);
   if (!channel) {
      ERROR(log, "peer not found, channelid=%u", channelid);
      return -1;
   }

   peer = snw_peer_search(ctx->peer_cache,peerid);
   if (!peer) {
      ERROR(log, "peer not found, peerid=%u", peerid);
      return -1;
   }
   peer->channelid = channelid;

   if (!strncmp(peer_type.c_str(),"pub",3)) {
      peer->peer_type = PEER_TYPE_PUBLISHER;
      forward_to_ice = 1;
   } else if (!strncmp(peer_type.c_str(),"pla",3)) {
      peer->peer_type = PEER_TYPE_PLAYER;
      forward_to_ice = 1;
   } else if (!strncmp(peer_type.c_str(),"p2p",3)) {
      peer->peer_type = PEER_TYPE_P2P;
   } else {
      ERROR(log,"unknown peer type, flowid=%u, peer_type=%s",conn->flowid,peer_type.c_str());
      peer->peer_type = PEER_TYPE_UNKNOWN;
      return -2;
   }

   if (forward_to_ice) {
      //TODO: remove ice_connect from client request
   }

   if (channel->flowid != conn->flowid) {
     Json::Value notify;
     Json::FastWriter writer;
     std::string output;

     DEBUG(log,"notify peer joined event, flowid=%u",peer->flowid);
     notify["msgtype"] = SNW_EVENT;
     notify["api"] = SNW_EVENT_PEER_JOINED;
     notify["remoteid"] = peer->flowid;
     notify["peerid"] = channel->peerid;
     notify["channelid"] = channelid;
     notify["is_p2p"] = peer->peer_type == PEER_TYPE_P2P ? 1 : 0;
     output = writer.write(notify);
     snw_shmmq_enqueue(ctx->snw_ice2core_mq,0,output.c_str(),output.size(),channel->flowid);
   }

   return 0;
}

int
snw_sig_call_msg(snw_context_t *ctx, snw_connection_t *conn, Json::Value &root) {
   snw_log_t *log = ctx->log;
   Json::FastWriter writer;
   snw_peer_t *peer = 0;
   //snw_channel_t *channel = 0;
   std::string output;
   std::string peer_type;
   //uint32_t channelid = 0;
   uint32_t peerid = 0;
   
   try {
      peerid = root["remoteid"].asUInt();

      //TODO: verify peer in channel
      //channelid = root["channelid"].asUInt();
      
      DEBUG(log,"forward call req to peer, flowid=%u, peerid=%u",conn->flowid, peerid);
      output = writer.write(root);
      snw_shmmq_enqueue(ctx->snw_ice2core_mq,0,output.c_str(),output.size(),peerid);
   } catch (...) {
      ERROR(log, "json format error");
   }

   return 0;
}


int
snw_sig_sdp_msg(snw_context_t *ctx, snw_connection_t *conn, Json::Value &root) {
   snw_log_t *log = ctx->log;
   Json::FastWriter writer;
   std::string output;
   uint32_t remoteid = 0;
   
   try {
      remoteid = root["remoteid"].asUInt();
      output = writer.write(root);
      snw_shmmq_enqueue(ctx->snw_core2net_mq,0,output.c_str(),output.size(),remoteid);
   } catch (...) {
      ERROR(log, "json format error");
      return -1;
   }
   return 0;
}

int
snw_sig_candidate_msg(snw_context_t *ctx, snw_connection_t *conn, Json::Value &root) {
   snw_log_t *log = ctx->log;
   Json::FastWriter writer;
   std::string output;
   uint32_t remoteid = 0;
   
   try {
      remoteid = root["remoteid"].asUInt();
      output = writer.write(root);
      snw_shmmq_enqueue(ctx->snw_core2net_mq,0,output.c_str(),output.size(),remoteid);
   } catch (...) {
      ERROR(log, "json format error");
      return -1;
   }
   return 0;
}

int
snw_sig_handler(snw_context_t *ctx, snw_connection_t *conn, Json::Value &root) {
   snw_log_t *log = ctx->log;
   uint32_t api = 0;

   try {
      api = root["api"].asUInt();
      DEBUG(log, "sig handler, flowid=%u, api=%u", conn->flowid, api);
      switch(api) {
         case SNW_SIG_AUTH:
            snw_sig_auth_msg(ctx,conn,root);
            break;
         case SNW_SIG_CREATE:
            snw_sig_create_msg(ctx,conn,root);
            break;
         case SNW_SIG_CONNECT:
            snw_sig_connect_msg(ctx,conn,root);
            break;
         case SNW_SIG_CALL:
            snw_sig_call_msg(ctx,conn,root);
            break;
         case SNW_SIG_SDP:
            snw_sig_sdp_msg(ctx,conn,root);
            break;
         case SNW_SIG_CANDIDATE:
            snw_sig_candidate_msg(ctx,conn,root);
            break;
         default:
            DEBUG(log, "unknown api, api=%u", api);
            break;
      }
   } catch(...) {
      return -1;
   }

   return 0;
}

int
snw_module_handler(snw_context_t *ctx, snw_connection_t *conn, uint32_t type, char *data, uint32_t len) {
   snw_log_t *log = ctx->log;
   struct list_head *p;
   
   DEBUG(log, "module handling, type=%x", type);   
   list_for_each(p,&ctx->modules.list) {
      snw_module_t *m = list_entry(p,snw_module_t,list);
      DEBUG(log, "module info, name=%s, type=%0x, sofile=%s", 
             m->name, m->type, m->sofile);
      if (m->type == type) {
         m->methods->handle_msg(m,conn,data,len);
         //call snw_videocall_handle_msg
      }
   }

   return 0;
}

int
snw_core_process_msg(snw_context_t *ctx, snw_connection_t *conn, char *data, uint32_t len) {
   snw_log_t *log = ctx->log;
   Json::Value root;
   Json::Reader reader;
   uint32_t msgtype = 0;
   uint32_t api = 0;
   int ret;

   ret = reader.parse(data,data+len,root,0);
   if (!ret) {
      ERROR(log,"error json format, s=%s",data);
      return -1;
   }

   DEBUG(log, "get msg, data=%s", data);
   try {
      msgtype = root["msgtype"].asUInt();
      api = root["api"].asUInt();

      switch(msgtype) {
         case SNW_ICE:
            snw_ice_handler(ctx,conn,msgtype,data,len);
            break;

         case SNW_SIG:
            snw_sig_handler(ctx,conn,root);
            break;

         default:
            snw_module_handler(ctx,conn,msgtype,data,len);
            break;
      }
      
   } catch (...) {
      ERROR(log, "json format error, data=%s", data);
   }

   return 0;
}

int
snw_core_connect(snw_context_t *ctx, snw_connection_t *conn) {

   //TODO: handle connect activity etc
   //      for example, limit connections per ip
   return 0;
}

int
snw_core_disconnect(snw_context_t *ctx, snw_connection_t *conn) {
   Json::Value root;
   Json::FastWriter writer;
   std::string output;

   try {
      root["msgtype"] = SNW_ICE;
      root["api"] = SNW_ICE_STOP;
      root["id"] = conn->flowid;
      output = writer.write(root);
      snw_shmmq_enqueue(ctx->snw_core2ice_mq,0,output.c_str(),output.size(),conn->flowid);
   } catch(...) {
      return -1;
   }

   return 0;
}

int
snw_net_preprocess_msg(snw_context_t *ctx, char *buffer, uint32_t len, uint32_t flowid) {
   snw_event_t* header = (snw_event_t*) buffer; 
   snw_log_t *log = (snw_log_t*)ctx->log;
   snw_connection_t conn;

   ctx->cur_time = time(0);

   //hexdump(buf,len,"req");
   if (len < SNW_EVENT_HEADER_LEN) {
      ERROR(log, "msg too small, len=%u,flowid=%u",len,flowid);
      return -1;
   }

   if (header->magic_num != SNW_EVENT_MAGIC_NUM) {        
      ERROR(log, "no event header, len=%u,flowid=%u, magic=%u",
            len,flowid,header->magic_num);
      return -2;
   }    

   memset(&conn, 0, sizeof(conn));
   conn.flowid = flowid;
   conn.srctype = WSS_SOCKET_UDP;
   conn.port = header->port;
   conn.ipaddr = header->ipaddr;

   if(header->event_type == snw_ev_connect) {     
      ERROR(log, "event connect error, len=%u,flowid=%u",len,flowid);
      snw_core_connect(ctx,&conn);
      return 0;
   }    

   if(header->event_type == snw_ev_disconnect) {     
      ERROR(log, "event disconnect error, len=%u,flowid=%u",len,flowid);
      snw_core_disconnect(ctx,&conn);
      return 0;
   }

   DEBUG(log, "get msg, srctype: %u, ip: %s, port: %u, flow: %u, data_len: %u, msg_len: %u",
       conn.srctype,
       ip_to_str(conn.ipaddr),
       conn.port,
       conn.flowid,
       len,
       len - sizeof(snw_event_t));

   snw_core_process_msg(ctx,&conn,buffer+sizeof(snw_event_t),len-sizeof(snw_event_t));
   return 0;
}

int
snw_process_msg_from_ice(snw_context_t *ctx, char *buffer, uint32_t len, uint32_t flowid) {

   DEBUG(ctx->log, "ice preprocess msg, flowid=%u, msg=%s", flowid, buffer);
   snw_shmmq_enqueue(ctx->snw_core2net_mq, 0, buffer, len, flowid);
   return 0;
}

void
snw_ice_msg(int fd, short int event,void* data) {
   static char buffer[MAX_BUFFER_SIZE];
   snw_context_t *ctx = (snw_context_t *)data;
   uint32_t len = 0;
   uint32_t flowid = 0;
   uint32_t cnt = 0;

#ifdef USE_ADAPTIVE_CONTROL
   while(true){
      len = 0; flowid = 0; cnt++;
      if ( cnt >= 10000) {
         DEBUG(ctx->log, "breaking the loop, cnt=%d", cnt);
         break;
      }
#endif
      // _mq_ccd_2_mcd->dequeue(buffer, MAX_BUFFER_SIZE, len, conn_id);
      snw_shmmq_dequeue(ctx->snw_ice2core_mq, buffer, MAX_BUFFER_SIZE, &len, &flowid);

      if (len == 0) return;

      DEBUG(ctx->log,"dequeue msg from ice, flowid=%u, len=%u, cnt=%d",
          flowid, len, cnt);
      buffer[len] = 0;
      snw_process_msg_from_ice(ctx,buffer,len,flowid);

#ifdef USE_ADAPTIVE_CONTROL
   }
#endif

   return;

}

void
snw_net_msg(int fd, short int event,void* data) {
   static char buffer[MAX_BUFFER_SIZE];
   snw_context_t *ctx = (snw_context_t *)data;
   uint32_t len = 0;
   uint32_t flowid = 0;
   uint32_t cnt = 0;

#ifdef USE_ADAPTIVE_CONTROL
   while(true){
      len = 0; flowid = 0; cnt++;
      if ( cnt >= 10000) {
         DEBUG(ctx->log, "breaking the loop, cnt=%d", cnt);
         break;
      }
#endif
      // _mq_ccd_2_mcd->dequeue(buffer, MAX_BUFFER_SIZE, len, conn_id);
      snw_shmmq_dequeue(ctx->snw_net2core_mq, buffer, MAX_BUFFER_SIZE, &len, &flowid);

      if (len == 0 || len >= MAX_BUFFER_SIZE) return;

      DEBUG(ctx->log,"dequeue msg from net, flowid=%u, len=%u, cnt=%d",
          flowid, len, cnt);
      buffer[len] = 0; // null-terminated string
      snw_net_preprocess_msg(ctx,buffer,len,flowid);

#ifdef USE_ADAPTIVE_CONTROL
   }
#endif

   return;
}

void
snw_main_process(snw_context_t *ctx) {
   int ret = 0;
   struct event *q_event;

   if (ctx == 0)
      return;

   ctx->ev_base = event_base_new();
   if (ctx->ev_base == 0) {
      exit(-2);
   }

   /*initialize main log*/
   ctx->log = snw_log_init("./main.log",ctx->log_level,0,0);
   if (ctx->log == 0) {
      exit(-1);   
   }

   snw_module_init(ctx);
   ctx->channel_cache = snw_channel_init();
   if (ctx->channel_cache == 0) {
      ERROR(ctx->log,"failed to init channel cache");
      return;
   }

   ctx->peer_cache = snw_peer_init();
   if (ctx->peer_cache == 0) {
      ERROR(ctx->log,"failed to init peer cache");
      return;
   }

   ctx->channel_mgr = snw_set_init(1100000, 10000);
   if (ctx->channel_mgr == 0) {
      ERROR(ctx->log,"failed to init channel set");
      return;
   }


   ctx->snw_net2core_mq = (snw_shmmq_t *)
          malloc(sizeof(*ctx->snw_net2core_mq));
   if (ctx->snw_net2core_mq == 0) {
      return;
   }

   ret = snw_shmmq_init(ctx->snw_net2core_mq,
             "/tmp/snw_net2core_mq.fifo", 0, 0, 
             NET2CORE_KEY, SHAREDMEM_SIZE);
   if (ret < 0) {
      ERROR(ctx->log,"failed to init net2core mq");
      return;
   }

   ctx->snw_core2net_mq = (snw_shmmq_t *)
          malloc(sizeof(*ctx->snw_core2net_mq));
   if (ctx->snw_net2core_mq == 0) {
      return;
   }

   ret = snw_shmmq_init(ctx->snw_core2net_mq,
             "/tmp/snw_core2net_mq.fifo", 0, 0, 
             CORE2NET_KEY, SHAREDMEM_SIZE);
   if (ret < 0) {
      ERROR(ctx->log,"failed to init core2net mq");
      return;
   }

   q_event = event_new(ctx->ev_base, ctx->snw_net2core_mq->_fd, 
        EV_TIMEOUT|EV_READ|EV_PERSIST, snw_net_msg, ctx);
   event_add(q_event, NULL);

   ctx->snw_ice2core_mq = (snw_shmmq_t *)
          malloc(sizeof(*ctx->snw_ice2core_mq));
   if (ctx->snw_ice2core_mq == 0) {
      return;
   }

   ret = snw_shmmq_init(ctx->snw_ice2core_mq,
             "/tmp/snw_ice2core_mq.fifo", 0, 0, 
             ICE2CORE_KEY, SHAREDMEM_SIZE);
   if (ret < 0) {
      ERROR(ctx->log,"failed to init core2net mq");
      return;
   }

   ctx->snw_core2ice_mq = (snw_shmmq_t *)
          malloc(sizeof(*ctx->snw_core2ice_mq));
   if (ctx->snw_core2ice_mq == 0) {
      return;
   }

   ret = snw_shmmq_init(ctx->snw_core2ice_mq,
             "/tmp/snw_core2ice_mq.fifo", 0, 0, 
             CORE2ICE_KEY, SHAREDMEM_SIZE);
   if (ret < 0) {
      ERROR(ctx->log,"failed to init core2net mq");
      return;
   }

   q_event = event_new(ctx->ev_base, ctx->snw_ice2core_mq->_fd, 
        EV_TIMEOUT|EV_READ|EV_PERSIST, snw_ice_msg, ctx);
   event_add(q_event, NULL);

   event_base_dispatch(ctx->ev_base);

   return;
}

int
main(int argc, char** argv) {
   int pid;
   snw_context_t *ctx;

   srand(time(NULL));

   ctx = snw_create_context();
   if (ctx == NULL)
      exit(-1);

   if (argc < 2)
      exit(-2);

   snw_config_init(ctx,argv[1]);
   daemonize();

   pid = fork();
   if (pid < 0) {
      printf("error");
   } else if (pid == 0) {//child
      snw_ice_setup(ctx);
      return 0;
   } else {
      //continue 
   }

   pid = fork();
   if (pid < 0) {
      printf("error");
   } else if (pid == 0) {
      snw_net_setup(ctx);
      return 0;
   } else {
      //continue
   }

   snw_main_process(ctx);
   return 0;
}

