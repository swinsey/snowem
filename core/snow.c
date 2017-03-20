
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <json/json.h>

#include "base_str.h"
#include "config_file.h"
#include "connection.h"
#include "core.h"
#include "module.h"
#include "snow.h"
#include "snw_event.h"
#include "utils.h"

using namespace mqf::base;

int
snw_conf_init(snw_context_t *ctx, const char *file) {
   CFileConfig &page = * new CFileConfig();

   printf("config file: %s\n",file);

   page.Init(file);
   ctx->config_file = file;
   ctx->ice_cert_file = strdup(page["root\\ice\\cert_file"].c_str());
   ctx->ice_key_file = strdup(page["root\\ice\\key_file"].c_str());

   ctx->wss_cert_file = strdup(page["root\\websocket\\cert_file"].c_str());
   ctx->wss_key_file = strdup(page["root\\websocket\\key_file"].c_str());
   ctx->wss_port = from_str<uint16_t>(page["root\\websocket\\bind_port"]);
   ctx->wss_ip = strdup(page["root\\websocket\\bind_ip"].c_str());

   const vector<string> &module_list = page.GetDomains("root\\modules");
   unsigned int module_num = module_list.size();
   for ( unsigned int i = 0; i < module_num; i++) {
      std::string module_path = "root\\" + module_list[i]; 
      ctx->module = (snw_module_t*)malloc(sizeof(snw_module_t));
      if (!ctx->module) 
         return -1;
      ctx->module->name = strdup(page[module_path + "\\name"].c_str());
      ctx->module->type = from_str<uint32_t>(page[module_path + "\\type"]);
      ctx->module->sofile = strdup(page[module_path + "\\sofile"].c_str());
      //printf("module info, name=%s, type=%0x, sofile=%s\n", 
      //       ctx->module->name,
      //       ctx->module->type,
      //       ctx->module->sofile);
   }

   return 0;
}

int
snw_net_process_msg(snw_context_t *ctx, snw_connection_t *conn, char *data, uint32_t len) {
   snw_log_t *log = ctx->log;
   Json::Value root;
   Json::Reader reader;
   int ret;

   ret = reader.parse(data,data+len,root,0);
   if (!ret) {
      ERROR(log,"error json format, s=%s",data);
      return -1;
   }
   DEBUG(log, "get msg, data=%s", data);

   return 0;
}

int
snw_preprocess_msg(snw_context_t *ctx, char *buffer, uint32_t len, uint32_t flowid) {
   snw_event_t* header = (snw_event_t*) buffer; 
   snw_log_t *log = (snw_log_t*)ctx->log;
   snw_connection_t conn;

   ctx->cur_time = time(0);

   //hexdump(buf,len,"req");
   if (len < SNW_EVENT_HEADER_LEN) {
      ERROR(log, "msg too small, len=%u,flowid=%u",len,flowid);
      return -1;
   }

   if(header->magic_num != SNW_EVENT_MAGIC_NUM) {        
      ERROR(log, "no ccd event header, len=%u,flowid=%u, magic=%u",
            len,flowid,header->magic_num);
      return -2;
   }    

   if(header->event_type == snw_ev_connect) {     
      ERROR(log, "event connect error, len=%u,flowid=%u",len,flowid);
      return -3;
   }    

   if(header->event_type == snw_ev_disconnect) {     
      ERROR(log, "event disconnect error, len=%u,flowid=%u",len,flowid);
      return -3;
   }

   memset(&conn, 0, sizeof(conn));
   conn.srctype = WSS_SOCKET_UDP;
   conn.port = header->port;
   conn.ipaddr = header->ipaddr;

   DEBUG(log, "get msg, srctype: %u, ip: %s, port: %u, flow: %u, data_len: %u, msg_len: %u",
       conn.srctype,
       ip_to_str(conn.ipaddr),
       conn.port,
       conn.flowid,
       len,
       len - sizeof(snw_event_t));


   snw_net_process_msg(ctx,&conn,buffer+sizeof(snw_event_t),len-sizeof(snw_event_t));

   return 0;
}

void
snw_dispatch_msg(int fd, short int event,void* data) {
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

      if (len == 0) return;

      DEBUG(ctx->log,"dequeue msg from net, flowid=%u, len=%u, cnt=%d",
          flowid, len, cnt);
      snw_preprocess_msg(ctx,buffer,len,flowid);

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
   ctx->log = snw_log_init("./main.log",0,0,0);
   if (ctx->log == 0) {
      exit(-1);   
   }

   snw_module_init(ctx);

   //test methods
   //ctx->module->methods->handle_msg(ctx,0,0);

   ctx->snw_net2core_mq = (snw_shmmq_t *)
          malloc(sizeof(*ctx->snw_net2core_mq));
   if (ctx->snw_net2core_mq == 0) {
      return;
   }

   ret = snw_shmmq_init(ctx->snw_net2core_mq,
             "/tmp/snw_net2core_mq.fifo", 0, 0, 
             NET2CORE_KEY, SHAREDMEM_SIZE, 0);
   if (ret < 0) {
      ERROR(ctx->log,"failed to init net2core mq");
      return;
   }
 
   q_event = event_new(ctx->ev_base, ctx->snw_net2core_mq->_fd, 
        EV_TIMEOUT|EV_READ|EV_PERSIST, snw_dispatch_msg, ctx);
   event_add(q_event, NULL);
   event_base_dispatch(ctx->ev_base);

   return;
}

int
main(int argc, char** argv) {
   int pid;
   snw_context_t *ctx;

   ctx = snw_create_context();
   if (ctx == NULL)
      exit(-1);

   if (argc < 2)
      exit(-2);

   snw_conf_init(ctx,argv[1]);
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

