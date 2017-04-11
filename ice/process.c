
#include <net/if.h>
#include <ifaddrs.h>
#include <sys/types.h>

#include "module.h"
#include "mq.h"
#include "ice_channel.h"
#include "ice_session.h"
#include "json/json.h"
#include "sdp.h"
#include "rtcp.h"
#include "process.h"
#include "utils.h"


void ice_send_candidate(snw_ice_session_t *session, int video, char *buffer, int len) {
   snw_context_t *ctx;
   snw_log_t *log = 0;
   Json::Value root,candidate;
   std::string output;
   Json::FastWriter writer;
   std::string str(buffer,len);

   if (!session) return;
   ctx = (snw_context_t*)session->ice_ctx->ctx;
   log = session->ice_ctx->log;

   root["msgtype"] = SNW_ICE;
   root["api"] = SNW_ICE_CANDIDATE;
   root["roomid"] = 0;
   root["callid"] = "callid";
   candidate["type"] = "candidate";
   if (video) {
      candidate["label"] = 1;
      candidate["id"] = "video";
   } else {
      candidate["label"] = 0;
      candidate["id"] = "audio";
   }
   candidate["candidate"] = str;
   root["candidate"] = candidate;

   output = writer.write(root);
   DEBUG(log, "Sending sdp, sdp=%s",output.c_str());
   //enqueue_msg_to_mcd(output.c_str(),output.size(),session->flowid);
   snw_shmmq_enqueue(ctx->snw_ice2core_mq,0,output.c_str(),output.size(),session->flowid);

   return;
}

void
snw_ice_send_local_candidate(snw_ice_session_t *session, int video, uint32_t stream_id, uint32_t component_id) {
   snw_log_t *log = 0;
   agent_t* agent = 0;
   snw_ice_stream_t *stream = 0;
   ice_component_t *component = 0;
   struct list_head *i,*n;
   candidate_t *candidates;
   int len;

   if (!session || !session->agent)
      return;
   log = session->ice_ctx->log;

   agent = session->agent;
   stream = snw_stream_find(&session->streams, stream_id);
   if(!stream) {
      ERROR(log, "No stream %d", stream_id);
      return;
   }

   component = snw_component_find(&stream->components, component_id);
   if (!component) {
      ERROR(log, "No component %d in stream %d", component_id, stream_id);
      return;
   }

   candidates = ice_agent_get_local_candidates(agent, stream_id, component_id);
   if (candidates == NULL )
      return;

   DEBUG(log, "got candidates, size=%u, sid=%u, cid=%u",
         list_size(&candidates->list), stream_id, component_id);

   list_for_each_safe(i,n,&candidates->list) {
      char buffer[100] = {0};
      candidate_t *c = list_entry(i,candidate_t,list);
      char address[ICE_ADDRESS_STRING_LEN], base_address[ICE_ADDRESS_STRING_LEN];
      int port = 0, base_port = 0;
      address_to_string(&(c->addr), (char *)&address);
      port = address_get_port(&(c->addr));
      address_to_string(&(c->base_addr), (char *)&base_address);
      base_port = address_get_port(&(c->base_addr));

      DEBUG(log, "candidate info, sid=%u, cid=%u, addr=%s, port=%u, priority=%u, foundation=%u",
            c->stream_id, c->component_id, address, port, c->priority, c->foundation);

      if (c->type == ICE_CANDIDATE_TYPE_HOST) {
         if (c->transport == ICE_CANDIDATE_TRANSPORT_UDP) {
            //snprintf(buffer, 100, "a=candidate:%s %d %s %d %s %d typ host\r\n",
            len = snprintf(buffer, 100, "candidate:%s %d %s %d %s %d typ host generation 0",
                  c->foundation, c->component_id, "udp", c->priority, address, port);
         } else {
            DEBUG(log, "only ice-udp supported");
            candidate_free(c);
            continue;
         }
      } else if (c->type == ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE) {
         if (c->transport == ICE_CANDIDATE_TRANSPORT_UDP) {
            address_to_string(&(c->base_addr), (char *)&base_address);
            int base_port = address_get_port(&(c->base_addr));
            len = snprintf(buffer, 100, "candidate:%s %d %s %d %s %d typ srflx raddr %s rport %d",
                  c->foundation, c->component_id, "udp", c->priority, address, port, base_address, base_port);
         } else {
            DEBUG(log, "only ice-udp supported");
            candidate_free(c);
            continue;
         }
      } else if(c->type == ICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
         DEBUG(log, "skipping prflx candidate");
         candidate_free(c);
         continue;
      } else if(c->type == ICE_CANDIDATE_TYPE_RELAYED) {
         if(c->transport == ICE_CANDIDATE_TRANSPORT_UDP) {
            len = snprintf(buffer, 100, "candidate:%s %d %s %d %s %d typ relay raddr %s rport %d",
                  c->foundation, c->component_id, "udp", c->priority, address, port, base_address, base_port);
         } else {
            DEBUG(log, "only ice-udp supported");
            candidate_free(c);
            continue;
         }
      }
      //strncat(sdp, buffer, ICE_BUFSIZE);
      DEBUG(log, "output, len=%d, sdp=%s", len, buffer);
      if ( len > 0 ) {
         ice_send_candidate(session,video,buffer,len);
      }

      candidate_free(c);
   }

   DEBUG(log, "FXIME: free list of candidates");
   /*list_for_each_safe(i,n,&candidates->list) {
      candidate_t *c = list_entry(i,candidate_t,list);
      candidate_free(c);
      list_del(i);
   }*/

   return;
}


void
snw_ice_sdp_send_candidates(snw_ice_session_t *session, int video) {
   snw_ice_stream_t *stream = NULL;

   if (video) {
      uint32_t id = session->video_id;
      if (id == 0 && IS_FLAG(session, WEBRTC_BUNDLE))
          id = session->audio_id > 0 ? session->audio_id : session->video_id;
      stream = snw_stream_find(&session->streams, id);
   } else {
      stream = snw_stream_find(&session->streams, session->audio_id);
   }

   if ( stream == NULL )
      return;

   snw_ice_send_local_candidate(session, video, stream->stream_id, 1);
   if(!SET_FLAG(session, WEBRTC_RTCPMUX))
      snw_ice_send_local_candidate(session, video, stream->stream_id, 2);

   return;
}

void
snw_ice_create_msg(snw_ice_context_t *ice_ctx, Json::Value &root, uint32_t flowid) {
   snw_context_t *ctx = (snw_context_t*)ice_ctx->ctx;
   snw_log_t *log = ice_ctx->log;
   snw_ice_channel_t *channel = 0;
   Json::FastWriter writer;
   std::string output;
   int is_new = 0;

   channel = (snw_ice_channel_t*)snw_ice_channel_get(ice_ctx,flowid,&is_new);

   try {
      if (!channel || !is_new) {
         root["rc"] = -1;
         output = writer.write(root);
         snw_shmmq_enqueue(ctx->snw_ice2core_mq,0,output.c_str(),output.size(),flowid);
         return;
      }
      channel->ownerid = flowid;
      root["id"] = flowid;
      root["channelid"] = flowid; //FIXME: create 'real' sessionid
      root["rc"] = 0;
      output = writer.write(root);

      DEBUG(log,"ice create, mq=%p, flowid=%u, len=%u, res=%s", 
                ctx->snw_ice2core_mq, flowid, output.size(), output.c_str());

      snw_shmmq_enqueue(ctx->snw_ice2core_mq,0,output.c_str(),output.size(),flowid);
   } catch (...) {
      ERROR(log, "json format error, data=%s", output.c_str());
      return;
   }

   return;
}

int
verify_disabled_streams(snw_ice_session_t *session, int audio, int video, const char *jsep_sdp) {
   snw_log_t *log = 0;

   if (!session) return -1;
   log = session->ice_ctx->log;

   if (strstr(jsep_sdp, "m=audio 0")) {
      if(!IS_FLAG(session, WEBRTC_BUNDLE) || !video) {
         snw_ice_stream_t *stream = snw_stream_find(&session->streams, session->audio_id);
         if (stream) {
            DEBUG(log, "disable audio stream, sid=%u",stream->stream_id);
            stream->disabled = 1;
         }
      }
   }

   if (strstr(jsep_sdp, "m=video 0")) {
      if (!IS_FLAG(session, WEBRTC_BUNDLE) || !audio) {
         snw_ice_stream_t *stream = NULL;
         if (!IS_FLAG(session, WEBRTC_BUNDLE)) {
            stream = snw_stream_find(&session->streams, session->video_id);
         } else {
            uint32_t id = session->audio_id > 0 ? session->audio_id : session->video_id;
            stream = snw_stream_find(&session->streams, id);
         }
         if (stream) {
            DEBUG(log, "disable video stream, sid=%u",stream->stream_id);
            stream->disabled = 1;
         }
      }
   }

   return 0;
}


int
snw_ice_generate_sdp(snw_ice_session_t *session) {
   snw_log_t *log = session->ice_ctx->log;
   ice_sdp_attr_t sdp_attr;
   char *sdp_merged;

   if (!session)
      return -1;

   DEBUG(log, "sdp info, sdp=%s",session->sdp);
   snw_ice_get_sdp_attr(session->ice_ctx,session->sdp,&sdp_attr);

   sdp_merged = snw_ice_sdp_merge(session, session->sdp);
   if (!sdp_merged) {
      return -2;
   }

   verify_disabled_streams(session,sdp_attr.audio, sdp_attr.video, sdp_merged);
   session->local_sdp = sdp_merged;
   //DEBUG("generated sdp, local_sdp=%s",sdp_merged);

   return 0;
}

static void
snw_ice_cb_candidate_gathering_done(agent_t *agent, uint32_t stream_id, void *user_data) {
   snw_ice_session_t *session = (snw_ice_session_t *)user_data;
   snw_context_t *ctx = (snw_context_t*)session->ice_ctx->ctx;
   snw_log_t *log = session->ice_ctx->log;
   Json::Value root,sdp;
   std::string output;
   Json::FastWriter writer;

   if (!session) return;

   session->cdone++;
   DEBUG(log, "gathering done, user_data=%p, stream=%d, cdone=%u, streams_num=%u",
          user_data, stream_id, session->cdone, session->streams_num);

   snw_ice_stream_t *stream = snw_stream_find(&session->streams, stream_id);
   if (!stream) {
      DEBUG(log, "no stream, stream_id=%d", stream_id);
      return;
   }
   stream->cdone = 1;

   if (session->cdone == session->streams_num) {
      int ret = snw_ice_generate_sdp(session);
      if (ret < 0 || !session->local_sdp) {
         ERROR(log, "failed to generate sdp, ret=%d, local_sdp=%s",ret,session->local_sdp);
      }

      //send sdp into to client.
      DEBUG(log, "Sending local sdp, sdp=%s",session->local_sdp);
      root["msgtype"] = SNW_ICE;
      root["api"] = SNW_ICE_SDP;
      root["sdp"]["type"] = "offer";
      root["sdp"]["sdp"] = session->local_sdp;
      output = writer.write(root);
      DEBUG(log, "Sending ice sdp, flowid=%u, len=%u, sdp=%s", 
                 session->flowid, output.size(), output.c_str());
      snw_shmmq_enqueue(ctx->snw_ice2core_mq,0,output.c_str(),output.size(),session->flowid);

      snw_ice_sdp_send_candidates(session,0);//candidate for audio component
      snw_ice_sdp_send_candidates(session,1);//candidate for video component
   }

   return;
}

void
snw_ice_cb_new_selected_pair(agent_t *agent, uint32_t stream_id,
       uint32_t component_id, char *local, char *remote, void *data) {
   snw_log_t *log = 0;
   snw_ice_session_t *session = 0;
   snw_ice_stream_t *stream = 0;
   ice_component_t *component = 0;

   session = (snw_ice_session_t *)data;
   if (!session) return;
   log = session->ice_ctx->log;

   if (component_id > 1 && IS_FLAG(session, WEBRTC_RTCPMUX)) {
      ERROR(log, "wait for webrtc rtcpmux, component_id=%u",component_id);
      return;
   }

   DEBUG(log, "new selected pair, cid=%d, sid=%d, local=%s, remote=%s",
                component_id, stream_id, local, remote);
   stream = snw_stream_find(&session->streams, stream_id);
   if (!stream) {
      ERROR(log, "No stream %d", stream_id);
      return;
   }

   component = snw_component_find(&stream->components, component_id);
   if (!component) {
      ERROR(log, "component not found, cid=%d, sid=%d", component_id, stream_id);
      return;
   }

   DEBUG(log, "starting DTLS handshake");
   if (component->dtls != NULL) {
      return;
   }

   component->fir_latest = get_monotonic_time();
   component->dtls = srtp_context_new(component, stream->dtls_role);
   if (!component->dtls) {
      ERROR(log, "No component DTLS-SRTP session");
      return;
   }

   srtp_do_handshake(component->dtls);
   DEBUG(log, "FIXME: Creating retransmission timer");
   //FIXME: timeout to call dtls_retry

   return;
}

void
snw_ice_cb_component_state_changed(agent_t *agent,
         uint32_t stream_id, uint32_t component_id, uint32_t state, void *data) {
   snw_ice_session_t *session = (snw_ice_session_t *)data;
   snw_log_t *log = 0;
   snw_ice_stream_t *stream = 0;
   ice_component_t *component = 0;

   if (!session) return;
   log = session->ice_ctx->log;

   if (component_id > 1 && IS_FLAG(session, WEBRTC_RTCPMUX)) {
      DEBUG(log,"Ignoring state, cid=%d, sid=%d, state=%u",
             component_id, stream_id, state);
      return;
   }

   DEBUG(log, "Component state changed, cid=%u, sid=%u, state=%d",
         component_id, stream_id, state);

   stream = snw_stream_find(&session->streams, stream_id);
   if (!stream) {
      ERROR(log, "No stream %d", stream_id);
      return;
   }

   component = snw_component_find(&stream->components, component_id);
   if (!component) {
      ERROR(log, "No component %d in stream %d", component_id, stream_id);
      return;
   }
   component->state = state;
   if ((state == ICE_COMPONENT_STATE_CONNECTED || state == ICE_COMPONENT_STATE_READY)) {
      session->ready = 1;
   }

   if(state == ICE_COMPONENT_STATE_FAILED) {
      ERROR(log, "ice component failed, cid=%u, sid=%u",component_id,stream_id);
   }  

   return;
}  

void
snw_ice_cb_new_remote_candidate(agent_t *agent, uint32_t stream_id,
                     uint32_t component_id, char *foundation, void *data) {
   char address[ICE_ADDRESS_STRING_LEN], base_address[ICE_ADDRESS_STRING_LEN];
   snw_ice_session_t *session = (snw_ice_session_t *)data;
   snw_log_t *log = 0;
   snw_ice_stream_t *stream = 0;
   ice_component_t *component = 0;
   candidate_t *candidate = 0;
   candidate_t *candidates = 0;
   struct list_head *tmp, *n;
   int port = 0, base_port = 0;
   char buffer[100];

   if (!session) return;
   log = session->ice_ctx->log;

   DEBUG(log, "discovered new remote candidate, cid=%d, sid=%d, foundation=%s",
          component_id, stream_id, foundation);

   if (component_id > 1 && IS_FLAG(session, WEBRTC_RTCPMUX)) {
      DEBUG(log, "ignore new candidate, component=%d,rtcpmux=%u",
            component_id, IS_FLAG(session, WEBRTC_RTCPMUX));
      return;
   }

   stream = snw_stream_find(&session->streams, stream_id);
   if (!stream) {
      ERROR(log, "stream not found, sid=%u", stream_id);
      return;
   }

   component = snw_component_find(&stream->components, component_id);
   if (!component) {
      ERROR(log, "component not found, cid=%u, sid=%u", component_id, stream_id);
      return;
   }
   candidates = ice_agent_get_remote_candidates(agent, component_id, stream_id);
   list_for_each_safe(tmp,n,&candidates->list) {
      candidate_t *c = list_entry(tmp,candidate_t,list);
      if(candidate == NULL) {
         if(!strcasecmp(c->foundation, foundation)) {
            DEBUG(log, "found candidate");
            print_candidate(c);
            candidate = c;
            continue;
         }
      }
   }

   if(candidate == NULL) {
      DEBUG(log, "candidate not found, foundation %s", foundation);
      return;
   }

   if(candidate->type != ICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
      DEBUG(log, "candidatedone");
      goto candidatedone;
   }

   DEBUG(log, "stream info, sid=%u, cid=%u", candidate->stream_id, candidate->component_id);

   {//DEBUG
      address_to_string(&(candidate->addr), (char *)&address);
      port = address_get_port(&(candidate->addr));
      address_to_string(&(candidate->base_addr), (char *)&base_address);
      base_port = address_get_port(&(candidate->base_addr));
      DEBUG(log, "Address:    %s:%d", address, port);
      DEBUG(log, "Priority:   %d", candidate->priority);
      DEBUG(log, "Foundation: %s", candidate->foundation);
   }

   if(candidate->transport == ICE_CANDIDATE_TRANSPORT_UDP) {
      snprintf(buffer, 100,
         "%s %d %s %d %s %d typ prflx raddr %s rport %d\r\n",
            candidate->foundation,
            candidate->component_id,
            "udp",
            candidate->priority,
            address,
            port,
            base_address,
            base_port);
   } else {
      ERROR(log, "transport not supported");
   }

candidatedone:
   candidate_free(candidate);
   return;
}

int
snw_ice_add_local_addresses(snw_ice_session_t *session) {
   struct ifaddrs *ifaddr, *ifa;
   int family, s;
   char host[NI_MAXHOST];

   if (getifaddrs(&ifaddr) == -1) {
      //ERROR("Error getting list of interfaces");
      return -1;
   } else {
      for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
         address_t addr_local;

         if (ifa->ifa_addr == NULL)
            continue;

         if (!((ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_RUNNING)))
            continue;

         if (ifa->ifa_flags & IFF_LOOPBACK)
            continue;

         family = ifa->ifa_addr->sa_family;
         if (family != AF_INET && family != AF_INET6)
            continue;

         if (family == AF_INET6 )
            continue;

         s = getnameinfo(ifa->ifa_addr,
               (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
               host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
         if(s != 0) {
            //DEBUG(log,"failed to getnameinfo, error=%s", gai_strerror(s));
            continue;
         }
         if (!strcmp(host, "0.0.0.0") || !strcmp(host, "::") || !strncmp(host, "fe80:", 5))
            continue;

         // add interface to the ICE agent
         //DEBUG(log, "gather candidates, host=%s", host);
         address_init(&addr_local);
         if(address_set_from_string(&addr_local, host) != ICE_OK) {
            //ERROR(log,"Skipping invalid address, host=%s", host);
            continue;
         }
         ice_agent_add_local_address(session->agent, &addr_local);
         break;
      }
      freeifaddrs(ifaddr);
   }

   return 0;
}

int
ice_verify_stream_status(snw_ice_session_t *session) {
   snw_log_t *log = 0;
   int64_t before,now;

   if (!session) return -1;
   log = session->ice_ctx->log;

   before = session->lasttime;
   now = get_monotonic_time();

   DEBUG(log, "time interval, delta=%lu, before=%lu, now=%lu",now-before,before,now);

   if (now-before >= ICE_USEC_PER_SEC) {
      if(session->audio_stream && session->audio_stream->rtp_component) {
         DEBUG(log, "FIXME: missing stream data");
      }

      if(session->video_stream && session->video_stream->rtp_component) {
         DEBUG(log, "FIXME: missing stream data");
      }
      before = now;
   }
   session->lasttime = now;

   return 0;
}

void 
send_rtcp_pkt_internal(snw_ice_session_t *session, rtp_packet_t *pkt) {
   snw_log_t *log = 0;
   snw_ice_stream_t *stream = 0;
   ice_component_t *component = 0;
   int video = 0;

   if (!session) return;
   log = session->ice_ctx->log;

   video = (pkt->type == RTP_PACKET_VIDEO);
   stream = IS_FLAG(session, WEBRTC_BUNDLE)
               ? (session->audio_stream ? session->audio_stream : session->video_stream)
               : (video ? session->video_stream : session->audio_stream);

   if (!stream) {
      goto done;
   }

   component = IS_FLAG(session, WEBRTC_RTCPMUX) ? stream->rtp_component : stream->rtcp_component;
   if (!component) {
      goto done;
   }

   //FIXME: check cdone equal to num of stream
   if (!stream->cdone) {
      goto done;
   }

   if(!component->dtls || !component->dtls->srtp_valid || !component->dtls->srtp_out) {
      goto done;
   }

   if (pkt->encrypted) {
      int sent = ice_agent_send(session->agent, stream->stream_id, component->component_id,
                                 (const char *)pkt->data, pkt->length);
      if (sent < pkt->length) {
         DEBUG(log, "only sent %d bytes? (was %d)", sent, pkt->length);
      }
   } else {
      /* FIXME Copy in a buffer and fix SSRC */
      char sbuf[ICE_BUFSIZE];
      int protected_ = 0;
      int ret = 0;

      memcpy(&sbuf, pkt->data, pkt->length);
      /* Fix all SSRCs! */
      DEBUG(log, "Fixing SSRCs (local %u, peer %u)",
            video ? stream->video_ssrc : stream->audio_ssrc,
            video ? stream->video_ssrc_peer : stream->audio_ssrc_peer);

      snw_rtcp_fix_ssrc((char *)&sbuf, pkt->length, 1,
            video ? stream->video_ssrc : stream->audio_ssrc,
            video ? stream->video_ssrc_peer : stream->audio_ssrc_peer);

      protected_ = pkt->length;
      ret = srtp_protect_rtcp(component->dtls->srtp_out, &sbuf, &protected_);
      if(ret != err_status_ok) {
         DEBUG(log, "SRTCP protect error, len=%d-->%d, s=%u", pkt->length, protected_, ret);
      } else {
         int sent = ice_agent_send(session->agent, stream->stream_id, component->component_id,
                                    (const char *)&sbuf, protected_);
         if(sent < protected_) {
            DEBUG(log, "only sent %d bytes? (was %d)", sent, protected_);
         }
      }
   }

done:
   if (pkt && pkt->data ) free(pkt->data);
   pkt->data = NULL;
   if (pkt) free(pkt);
   pkt = NULL;
   return;
}

void
send_rtp_pkt_internal(snw_ice_session_t *session, rtp_packet_t *pkt) {
   snw_log_t *log = 0;
   snw_ice_stream_t *stream = 0;
   ice_component_t *component = 0;
   int video = 0;

   if (!session) return;
   log = session->ice_ctx->log;

   video = (pkt->type == RTP_PACKET_VIDEO);
   stream = IS_FLAG(session, WEBRTC_BUNDLE)
         ? (session->audio_stream ? session->audio_stream : session->video_stream)
         : (video ? session->video_stream : session->audio_stream);
   if (!stream) {
      goto done;
   }

   component = stream->rtp_component;
   if (!component) {
      goto done;
   }

   if(!stream->cdone) {
      goto done;
   }

   if(!component->dtls || !component->dtls->srtp_valid || !component->dtls->srtp_out) {
      goto done;
   }

   if(pkt->encrypted) {
      rtp_header *header = (rtp_header *)pkt->data;
      DEBUG(log, "Retransmitting seq.nr %u", ntohs(header->seq_number));
      int sent = ice_agent_send(session->agent, stream->stream_id, component->component_id,
                                (const char *)pkt->data, pkt->length);
      if(sent < pkt->length) {
         DEBUG(log, "only sent %d bytes? (was %d)", sent, pkt->length);
      }
   } else {
      char sbuf[ICE_BUFSIZE];
      memcpy(&sbuf, pkt->data, pkt->length);
      rtp_header *header = (rtp_header *)&sbuf;
      header->ssrc = htonl(video ? stream->video_ssrc : stream->audio_ssrc);
      int protected_ = pkt->length;
      int ret = srtp_protect(component->dtls->srtp_out, &sbuf, &protected_);
      if(ret != err_status_ok) {
         rtp_header *header = (rtp_header *)&sbuf;
         uint32_t timestamp = ntohl(header->timestamp);
         uint16_t seq = ntohs(header->seq_number);
         DEBUG(log, "SRTP protect error, ret=%d ,len=%d-->%d, ts=%u, seq=%u",
               ret, pkt->length, protected_, timestamp, seq);
      } else {
         DEBUG(log, "send rtp packet");
         int sent = ice_agent_send(session->agent, stream->stream_id, component->component_id,
                                    (const char *)&sbuf, protected_);
         if(sent < protected_) {
            DEBUG(log, "only sent %d bytes? (was %d)", sent, protected_);
         }

         // Update stats
         /*if(sent > 0) {
            if(pkt->type == RTP_PACKET_AUDIO) {
               component->out_stats.audio_packets++;
               component->out_stats.audio_bytes += sent;
            } else if(pkt->type == RTP_PACKET_VIDEO) {
               component->out_stats.video_packets++;
               component->out_stats.video_bytes += sent;
            }
         }*/

         rtp_packet_t *p = (rtp_packet_t *)malloc(sizeof(rtp_packet_t));
         p->data = (char *)malloc(protected_);
         memcpy(p->data, (char *)&sbuf, protected_);
         p->length = protected_;
         p->last_retransmit = 0;
         rtp_list_add(&component->retransmit_buffer,p);
         DEBUG(log, "packet list, cur_num=%u, max_queue_num=%u",
               rtp_list_size(&component->retransmit_buffer), DEFAULT_MAX_NACK_QUEUE);
         if(rtp_list_size(&component->retransmit_buffer) > DEFAULT_MAX_NACK_QUEUE) {
            p = rtp_list_remove_last(&component->retransmit_buffer);
            free(p->data);
            p->data = NULL;
            free(p);
         }
      }
   }

done:
   if (pkt && pkt->data ) free(pkt->data);
   pkt->data = NULL;
   if (pkt) free(pkt);
   pkt = NULL;
   return;
}

void 
send_rtp_pkt(snw_ice_session_t *session, rtp_packet_t *pkt) {
   snw_log_t *log = 0;

   if (!session || !pkt)
      return;
   log = session->ice_ctx->log;

   if (pkt->data == NULL) {
      free(pkt);
      pkt = 0;
      return;
   }

   /* check status of receiver */
   ice_verify_stream_status(session);

   if (pkt->control) {
      send_rtcp_pkt_internal(session,pkt);
   } else {
      if(pkt->type == RTP_PACKET_AUDIO || pkt->type == RTP_PACKET_VIDEO) {
         send_rtp_pkt_internal(session,pkt);
      } else {
         //send_sctp_pkt_internal(session,pkt);
         ERROR(log, "unknow media packet, type=%u",pkt->type);
      }
   }

   return;
}


void 
ice_relay_rtcp(snw_ice_session_t *session, int video, char *buf, int len) {
   snw_log_t *log = 0;
   if (!session || !buf || len < 1)
      return;
   log = session->ice_ctx->log;

   //FIXME: rewrite, not use malloc
   rtp_packet_t *pkt = (rtp_packet_t *)malloc(sizeof(rtp_packet_t));
   pkt->data = (char*)malloc(len);
   memcpy(pkt->data, buf, len);
   pkt->length = len;
   pkt->type = video ? RTP_PACKET_VIDEO : RTP_PACKET_AUDIO;
   pkt->control = 1;
   pkt->encrypted = 0;
   DEBUG(log, "send rtcp packet, len=%u",len);
   send_rtp_pkt(session,pkt);
}

void 
snw_ice_rtp_nacks(snw_ice_session_t *session, ice_component_t *component, rtp_header *header, int video) {
   snw_log_t *log = 0;
   std::vector<int> nacklist;
   seq_info_t **last_seqs = 0;
   seq_info_t *cur_seq = 0;
   int last_seqs_len = 0; 
   int64_t now = get_monotonic_time();
   uint16_t new_seqn = ntohs(header->seq_number);
   uint16_t cur_seqn;

   if (!session || !component) return;
   log = session->ice_ctx->log;
     
   last_seqs = video ? &component->last_seqs_video : &component->last_seqs_audio;
   cur_seq = *last_seqs;

   if (cur_seq) {
      cur_seq = cur_seq->prev;
      cur_seqn = cur_seq->seq;
   } else {
      cur_seqn = new_seqn - (uint16_t)1; /* Can wrap */
   }

   // FIXME: check meaning of the second condition.
   if (!snw_ice_seq_in_range(new_seqn, cur_seqn, LAST_SEQS_MAX_LEN) &&
       !snw_ice_seq_in_range(cur_seqn, new_seqn, 1000)) {
      /* Jump too big, start fresh */
      DEBUG(log, "big sequence number jump %hu -> %hu , video=%u", cur_seqn, new_seqn, video);
      snw_ice_seq_list_free(last_seqs);
      cur_seq = NULL;
      cur_seqn = new_seqn - (uint16_t)1;
   }
   DEBUG(log, "current sequence number, video=%u, cur_seq=%u, new_seq=%u, last_seqs_len=%u",
         video, cur_seqn, new_seqn, last_seqs_len);

   if (snw_ice_seq_in_range(new_seqn, cur_seqn, LAST_SEQS_MAX_LEN)) {
      while(cur_seqn != new_seqn) {
         cur_seqn += (uint16_t)1; /* can wrap */
         seq_info_t *seq_obj = (seq_info_t*)malloc(sizeof(seq_info_t));
         seq_obj->seq = cur_seqn;
         seq_obj->ts = now; 
         seq_obj->state = (cur_seqn == new_seqn) ? SEQ_RECVED : SEQ_MISSING;
         snw_ice_seq_append(last_seqs, seq_obj);
         last_seqs_len++;
         if ( seq_obj->state == SEQ_MISSING ) {
            DEBUG(log, "missing packet, cur_seq=%u, new_seq=%u, last_seqs_len=%u",
               cur_seqn,new_seqn,last_seqs_len);
         }
      }
   }

   if (cur_seq) {
      for (;;) {
         last_seqs_len++;
         if(cur_seq->seq == new_seqn) {
            DEBUG(log, "Recieved missed sequence number %u", cur_seq->seq);
            cur_seq->state = SEQ_RECVED;
         } else if(cur_seq->state == SEQ_MISSING && now - cur_seq->ts > SEQ_MISSING_WAIT) {
            DEBUG(log, "Missed sequence number, sending 1st nack, seq=%u", cur_seq->seq);
            nacklist.push_back(cur_seq->seq);
            cur_seq->state = SEQ_NACKED;
         } else if(cur_seq->state == SEQ_NACKED  && now - cur_seq->ts > SEQ_NACKED_WAIT) {
            DEBUG(log, "Missed sequence number, sending 2nd nack, seq=%u", cur_seq->seq);
            nacklist.push_back(cur_seq->seq);
            cur_seq->state = SEQ_GIVEUP;
         }
         if(cur_seq == *last_seqs) {
            /* Just processed head */
            break;
         }
         cur_seq = cur_seq->prev;
      }
   }

   while (last_seqs_len > LAST_SEQS_MAX_LEN) {
      seq_info_t *node = snw_ice_seq_pop_head(last_seqs);
      free(node);
      last_seqs_len--;
   }

   uint32_t nacks_count = nacklist.size();
   if (nacks_count) {
      char nackbuf[120];
      int ret = snw_ice_rtcp_generate_nacks(nackbuf, sizeof(nackbuf), nacklist);

      DEBUG(log, "nacks missed packets, nacks_count=%u(%u), ret=%u", nacks_count, nacklist.size(), ret);
      DEBUG(log, "now sending NACK for missed packets, nacks_count=%u, ret=%u", nacks_count, ret);
      if (ret > 0)
         ice_relay_rtcp(session, video, nackbuf, ret);

      /* Update stats */
      //component->nack_sent_recent_cnt += nacks_count;
      /*if (video) {
         component->out_stats.video_nacks += nacks_count;
      } else {
         component->out_stats.audio_nacks += nacks_count;
      }*/
   }

   if (component->nack_sent_recent_cnt &&
       now - component->nack_sent_log_ts > 5 * ICE_USEC_PER_SEC) {
      DEBUG(log, "sent NACKs for %u missing packets\n",
      component->nack_sent_recent_cnt);
      component->nack_sent_recent_cnt = 0;
      component->nack_sent_log_ts = now;
   }

   return;
}
void
snw_ice_send_fir(snw_ice_session_t *session, ice_component_t *component, int force) {
   snw_log_t *log = 0;

   if (!session) return;
   log = session->ice_ctx->log;

   if (force || (component && (session->curtime - component->fir_latest > 10*ICE_USEC_PER_SEC))) {

      DEBUG(log, "sending fir request, cid=%u, curtime=%lu", component->component_id, session->curtime);
      {// send fir command
         rtp_packet_t *pkt = (rtp_packet_t *)malloc(sizeof(rtp_packet_t));
         char *rtcpbuf = (char*)malloc(24);

         snw_gen_rtcp_fir(rtcpbuf, 20, &component->fir_seq);
         pkt->data = rtcpbuf;
         pkt->length = 20;
         pkt->type = RTP_PACKET_VIDEO;
         pkt->control = 1;
         pkt->encrypted = 0;
         send_rtcp_pkt_internal(session,pkt);
      }

      {// send pli report
         rtp_packet_t *pkt = (rtp_packet_t *)malloc(sizeof(rtp_packet_t));
         char *rtcpbuf = (char*)malloc(12);

         snw_gen_rtcp_pli(rtcpbuf, 12);
         pkt->data = rtcpbuf;
         pkt->length = 12;
         pkt->type = RTP_PACKET_VIDEO;
         pkt->control = 1;
         pkt->encrypted = 0;
         send_rtcp_pkt_internal(session,pkt);
      }

      //if (force) {
      if (1) {
         DEBUG(log, "vp8 payload sending fir request, cid=%u, curtime=%lu", 
                    component->component_id, session->curtime);
         {// send fir command
            rtp_packet_t *pkt = (rtp_packet_t *)malloc(sizeof(rtp_packet_t));
            char *rtcpbuf = (char*)malloc(24);

            snw_gen_rtcp_fir(rtcpbuf, 20, &component->fir_seq);
            pkt->data = rtcpbuf;
            pkt->length = 20;
            pkt->type = RTP_PACKET_AUDIO;
            pkt->control = 1;
            pkt->encrypted = 0;
            send_rtcp_pkt_internal(session,pkt);
         }
         /*{// send pli report
            rtp_packet_t *pkt = (rtp_packet_t *)malloc(sizeof(rtp_packet_t));
            char *rtcpbuf = (char*)malloc(12);

            gen_rtcp_pli(rtcpbuf, 12);
            pkt->data = rtcpbuf; 
            pkt->length = 12;
            pkt->type = JANUS_ICE_PACKET_AUDIO;
            pkt->control = 1;
            pkt->encrypted = 0;
            send_rtcp_pkt_internal(handle,pkt);
         }*/
      }

      if (!force && component) {
         component->fir_latest = session->curtime;
      }
   }

   return;
}


void ice_rtp_incoming_msg(snw_ice_session_t *session, snw_ice_stream_t *stream,
                          ice_component_t *component, char* buf, int len) {
   snw_log_t *log = 0;
   rtp_header *header = (rtp_header *)buf;
   err_status_t ret;
   int buflen = len;
   int video = 0;

   if (!session) return;
   log = session->ice_ctx->log;

   DEBUG(log, "rtp incoming message, len=%u",len);

   if (!IS_FLAG(session, WEBRTC_BUNDLE)) {
      video = (stream->stream_id == session->video_id ? 1 : 0);
   } else {
      uint32_t packet_ssrc = ntohl(header->ssrc);
      video = ((stream->video_ssrc_peer == packet_ssrc) ? 1 : 0);
      if (!video && stream->audio_ssrc_peer != packet_ssrc) {
         DEBUG(log, "wrong ssrc or other format, ssrc=%u", packet_ssrc);
         return;
      }
   }

   ret = srtp_unprotect(component->dtls->srtp_in, buf, &buflen);
   if(ret != err_status_ok) {
      if(ret != err_status_replay_fail && ret != err_status_replay_old) {
         rtp_header *header = (rtp_header *)buf;
         uint32_t timestamp = ntohl(header->timestamp);
         uint16_t seq = ntohs(header->seq_number);
         ERROR(log, "SRTP unprotect error, len=%d, buflen=%d, ts=%u, seq=%u, res=%u",
               len, buflen, timestamp, seq, ret);
      }
   } else {
      if(video) {
         if(stream->video_ssrc_peer == 0) {
            stream->video_ssrc_peer = ntohl(header->ssrc);
            DEBUG(log, "got peer video ssrc, ssrc%u", stream->video_ssrc_peer);
         }
         if IS_FLAG(session,ICE_PUBLISHER)
         {
            //FIXME: uncomment
            //DEBUG(log, "sender save video packet, roomid: %u", session->roomid);
            //recorder_save_frame(handle->v_recorder, buf, buflen);
         }
      } else {
         if(stream->audio_ssrc_peer == 0) {
            stream->audio_ssrc_peer = ntohl(header->ssrc);
            DEBUG(log, "got peer audio ssrc, ssrc=%u", stream->audio_ssrc_peer);
         }
         if IS_FLAG(session,ICE_PUBLISHER)
         {
            //FIXME: uncomment
            //DEBUG(log, "sender save audio packet, roomid: %u", session->roomid);
            //recorder_save_frame(handle->a_recorder, buf, buflen);
         }
      }

      //FIXME: uncomment
      //ice_rtp_plugin(handle,stream,component,0,video,buf,buflen);
      snw_ice_handle_incoming_rtp(session, 0, video, buf, buflen);
      /*if(buflen > 0) {
         ice_rtp_update_stats(component,video,buflen);
      }*/
      snw_ice_rtp_nacks(session,component,header,video);
      snw_ice_send_fir(session,component,0);

   }

   return;
}

int
snw_ice_resend_pkt(snw_ice_session_t *session, ice_component_t *component,
              int video, int seqnr, int64_t now) {
   snw_log_t *log = session->ice_ctx->log;
   struct list_head *n;
   int retransmits_cnt = 0;
   int issent = 0;

   list_for_each(n,&component->retransmit_buffer.list) {
      rtp_packet_t *p = list_entry(n,rtp_packet_t,list);
      rtp_header *rh = (rtp_header *)p->data;
      if(ntohs(rh->seq_number) == seqnr) {
         if((p->last_retransmit > 0) && (now-p->last_retransmit < MAX_NACK_IGNORE)) {
            DEBUG(log, "retransmitted packet was skipped, seqnr=%u, ago=%lu",
                  seqnr, now-p->last_retransmit);
            break;
         }
         DEBUG(log, "scheduling for retransmission due to NACK, seqnr=%u", seqnr);
         p->last_retransmit = now;
         retransmits_cnt++;

         rtp_packet_t *pkt = (rtp_packet_t *)malloc(sizeof(rtp_packet_t));
         pkt->data = (char*)malloc(p->length);
         memcpy(pkt->data, p->data, p->length);
         pkt->length = p->length;
         pkt->type = video ? RTP_PACKET_VIDEO : RTP_PACKET_AUDIO;
         pkt->control = 0;
         pkt->encrypted = 1;
         issent = 1;

         send_rtp_pkt(session,pkt);
         break;
      }
   }

   DEBUG(log, "retransmission done, seqnr=%u, issent=%u", seqnr, issent);
   component->retransmit_recent_cnt += retransmits_cnt;

   return 0;
}

int snw_ice_rtcp_nacks(snw_ice_session_t *session, ice_component_t *component, 
                   int video, char *buf, int buflen) {
   snw_log_t *log = session->ice_ctx->log;
   int64_t now = get_monotonic_time();
   uint32_t nacks_count = 0; 
   std::vector<int> nacklist;

   snw_ice_rtcp_get_nacks(buf, buflen, nacklist);

   nacks_count = nacklist.size(); 
   if (nacks_count) {
      DEBUG(log, "nacks count, flow=%u, nacks_cnt=%u, is_sender=%u",
            session->flowid,nacklist.size(), IS_FLAG(session,ICE_PUBLISHER));
     
      for (unsigned int i=0; i<nacklist.size(); i++) {
         unsigned int seqnr = nacklist.front();
         nacklist.erase(nacklist.begin());
     
         DEBUG(log, "nacks >> %u", seqnr);
         snw_ice_resend_pkt(session,component,video,seqnr,now);
      }    

      /* FIXME Remove the NACK compound packet, we've handled it */
      buflen = snw_rtcp_remove_nacks(buf, buflen);
      /* Update stats */
      /*if(video) {
         component->in_stats.video_nacks += nacks_count;
      } else {
         component->in_stats.audio_nacks += nacks_count;
      }*/
   }

   if (component->retransmit_recent_cnt &&
       now - component->retransmit_log_ts > 5 * ICE_USEC_PER_SEC) {
      DEBUG(log, "retransmitted %u packets due to NACK",
             component->retransmit_recent_cnt);
      component->retransmit_recent_cnt = 0; 
      component->retransmit_log_ts = now; 
   }

   return 0;
}


void ice_rtcp_incoming_msg(snw_ice_session_t *session, snw_ice_stream_t *stream,
                          ice_component_t *component, char* buf, int len) {
   snw_log_t *log = 0;
   err_status_t ret;
   int buflen = len;

   if (!session) return;
   log = session->ice_ctx->log;

   ret = srtp_unprotect_rtcp(component->dtls->srtp_in, buf, &buflen);
   if (ret != err_status_ok) {
      DEBUG(log, "SRTCP unprotect error, ret=%u, len=%d, buflen=%d", ret, len, buflen);
   } else {
      int video = 0;
      if(!IS_FLAG(session, WEBRTC_BUNDLE)) {
         video = (stream->stream_id == session->video_id ? 1 : 0);
      } else {
         if(!IS_FLAG(session, WEBRTC_AUDIO)) {
            video = 1;
         } else if(!IS_FLAG(session, WEBRTC_VIDEO)) {
            video = 0;
         } else {
            if(stream->audio_ssrc_peer == 0 || stream->video_ssrc_peer == 0) {
               //FIXME: rewrite this code
               /* We don't know the remote SSRC: this can happen for recvonly clients
                * (see https://groups.google.com/forum/#!topic/discuss-webrtc/5yuZjV7lkNc)
                * Check the local SSRC, compare it to what we have */
               uint32_t rtcp_ssrc = snw_rtcp_get_receiver_ssrc(buf, len);
               if(rtcp_ssrc == stream->audio_ssrc) {
                  video = 0;
               } else if(rtcp_ssrc == stream->video_ssrc) {
                  video = 1;
               } else {
                  /* Mh, no SR or RR? Try checking if there's any FIR, PLI or REMB */
                  if (snw_rtcp_has_fir(buf, len) || snw_rtcp_has_pli(buf, len) || snw_rtcp_get_remb(buf, len)) {
                     video = 1;
                  }
               }
               DEBUG(log, "incoming rtcp, video=%u, local_video_ssrc=%u, local_audio_ssrc=%u, got=%u)",
                     video, stream->video_ssrc, stream->audio_ssrc, rtcp_ssrc);
            } else {
               /* Check the remote SSRC, compare it to what we have */
               uint32_t rtcp_ssrc = snw_rtcp_get_sender_ssrc(buf, len);
               video = (stream->video_ssrc_peer == rtcp_ssrc ? 1 : 0);
               DEBUG(log, "incoming rtcp, type=%u, is_sender=%u, remote_video_ssrc=%u, remote_audio_ssrc=%u, got=%u)",
                  video, IS_FLAG(session,ICE_PUBLISHER), stream->video_ssrc, stream->audio_ssrc, rtcp_ssrc);
            }
         }
      }
      //FIXME: uncomment
      //ice_rtp_plugin(handle,stream,component,1,video,buf,buflen);
      snw_ice_handle_incoming_rtp(session, 1, video, buf, buflen);
      snw_ice_rtcp_nacks(session, component, video, buf, buflen);
   }

   return;
}

void ice_data_recv_cb(agent_t *agent, uint32_t stream_id,
          uint32_t component_id, char *buf, uint32_t len, void *data) {
   snw_log_t *log = 0;
   snw_ice_session_t *session = 0;
   snw_ice_stream_t *stream = 0;
   ice_component_t *component = 0;
   int64_t now = get_monotonic_time();
   int pt = 0;

   component = (ice_component_t *)data;
   if (!component) return;

   stream = component->stream;
   if (!stream) return;

   session = stream->session;
   if (!session) return;
   log = session->ice_ctx->log;

   session->curtime = now;

   if (!component->dtls) {
      DEBUG(log, "dtls not setup yet, cid=%u, sid=%u", component_id, stream_id);
      return;
   }

   pt = ice_get_packet_type(buf,len);
   if (pt == UNKNOWN_PT) {
      ERROR(log, "unknown packet type, len=%u",len);
      return;
   }

   if (pt == DTLS_PT) {
      srtp_process_incoming_msg(component->dtls, buf, len);
      return;
   }

   // FIXME: rewrite this code
   //if (component_id == 1 && (!IS_FLAG(session, WEBRTC_RTCPMUX) || pt == RTP_PT)) {
   if (pt == RTP_PT) {
      if (!component->dtls || !component->dtls->srtp_valid || !component->dtls->srtp_in) {
         DEBUG(log, "dtls not setup yet, flow=%u", session->flowid);
      } else {
         ice_rtp_incoming_msg(session,stream,component,buf,len);
      }
      return;
   }

   //if ( component_id == 2 || ( component_id == 1 && pt == RTCP_PT && IS_FLAG(session, WEBRTC_RTCPMUX))) {
   if (pt == RTCP_PT) {
      if(!component->dtls || !component->dtls->srtp_valid || !component->dtls->srtp_in) {
         DEBUG(log, "dtls not setup yet, flow=%u", session->flowid);
      } else {
         ice_rtcp_incoming_msg(session,stream,component,buf,len);
      }
      return;
   }

   return;
}


ice_component_t*
snw_ice_create_media_component(snw_ice_session_t *session, snw_ice_stream_t *stream, uint32_t cid, int is_rtcp) {
   ice_component_t *rtp = 0;

   if (!session) return 0;

   rtp = snw_component_allocate(session->ice_ctx);
   if (!rtp) return 0;

   rtp->stream = stream;
   rtp->stream_id = stream->stream_id;
   rtp->component_id = cid;
   rtp->is_started = 0;
   INIT_LIST_HEAD(&rtp->candidates.list);
   INIT_LIST_HEAD(&rtp->retransmit_buffer.list);
   snw_component_insert(&stream->components, rtp);
   if (is_rtcp)
      stream->rtcp_component = rtp;
   else
      stream->rtp_component = rtp;

   //ice_agent_set_port_range(session->agent, stream->stream_id, cid, rtp_range_min, rtp_range_max);
   return rtp;
}


int
snw_ice_create_media_stream(snw_ice_session_t *session, int video) {
   snw_log_t *log = 0;
   snw_ice_stream_t *stream = 0;
   ice_component_t *rtp = 0;
   ice_component_t *rtcp = 0;
   uint32_t stream_id;

   if (!session) return -1;
   log = session->ice_ctx->log;

   stream_id = ice_agent_add_stream(session->agent, IS_FLAG(session, WEBRTC_RTCPMUX) ? 1 : 2);
   if (video) {
      session->video_id = stream_id;
   } else { //audio
      session->audio_id = stream_id;
   }

   stream = snw_stream_allocate(session->ice_ctx);
   if (stream == NULL) {
      return -2;
   }
   stream->stream_id = stream_id;
   stream->session = session;
   stream->cdone = 0;
   stream->payload_type = -1;
   stream->disabled = 0;
   stream->dtls_role = DTLS_ROLE_ACTPASS;
   INIT_LIST_HEAD(&stream->components.list);
   snw_stream_insert(&session->streams,stream);
      
   if (video) {
      session->video_mid = NULL;
      session->video_stream = stream;
      stream->video_ssrc = random();
      stream->video_ssrc_peer = 0;
      stream->audio_ssrc = 0;
      stream->audio_ssrc_peer = 0;
      DEBUG(log, "created video stream, sid=%u(%p)",
             session->video_stream->stream_id, session->video_stream);
   } else {
      session->audio_mid = NULL;
      stream->audio_ssrc = random();
      stream->audio_ssrc_peer = 0;
      if (IS_FLAG(session, WEBRTC_BUNDLE)) {
         stream->video_ssrc = random();
         DEBUG(log, "generate video ssrc, ssrc=%u",stream->video_ssrc);
      } else {
         stream->video_ssrc = 0;
      }
      stream->video_ssrc_peer = 0;
      session->audio_stream = stream;
   }

   rtp = snw_ice_create_media_component(session,stream,1,0);
   if (rtp == NULL) {
      return -3;
   }

   if (!IS_FLAG(session, WEBRTC_RTCPMUX)) {
      rtcp = snw_ice_create_media_component(session,stream,2,1);
      if(rtcp == NULL) {
         return -3;
      }
   }

   /*{//DEBUG
      struct list_head *n;
      list_for_each(n,&session->streams.list) {
         ice_stream_t *s = list_entry(n,ice_stream_t,list);
         DEBUG("view stream, s-sid=%u(%p)", s->stream_id, s);
      }
   }*/

   DEBUG(log, "initialize media stream, video=%u, stream_id=%u(%p), %p", 
              video, stream_id, stream, &session->streams);
   ice_agent_gather_candidates(session->agent, stream_id);
   ice_agent_attach_recv(session->agent, stream_id, 1, ice_data_recv_cb, rtp);
   if (!IS_FLAG(session, WEBRTC_RTCPMUX) && rtcp != NULL)
      ice_agent_attach_recv(session->agent, stream_id, 2, ice_data_recv_cb, rtcp);

   return 0;
}

int
snw_ice_session_setup(snw_ice_context_t *ice_ctx, snw_ice_session_t *session, int offer, char *sdp) {
   snw_log_t *log = ice_ctx->log;
   agent_t* agent;
   ice_sdp_attr_t sdp_attr;
   int ret = 0; 

   if (!session || !sdp) {
      return -1;
   }

   //ice_session_init(session);
   agent = (agent_t*)ice_agent_new(session->base,ICE_COMPATIBILITY_RFC5245,0);
   if (agent == NULL)
      return -1;

   DEBUG(log,"Creating ICE agent, session=%p, agent=%p",
         session, agent);

   // set callbacks and handler for ice protocols
   ice_set_candidate_gathering_done_cb(agent, snw_ice_cb_candidate_gathering_done, session);
   ice_set_new_selected_pair_cb(agent, snw_ice_cb_new_selected_pair, session);
   ice_set_component_state_changed_cb(agent, snw_ice_cb_component_state_changed, session);
   ice_set_new_remote_candidate_cb(agent, snw_ice_cb_new_remote_candidate, session);

   session->ice_ctx = ice_ctx;
   session->agent = agent;
   session->cdone = 0;
   session->streams_num = 0;
   session->controlling = ice_ctx->ice_lite_enabled;

   DEBUG(log,"Creating ICE agent, ice_lite=%u, controlling=%u",
         ice_ctx->ice_lite_enabled, session->controlling);

   ret = snw_ice_add_local_addresses(session);
   if (ret<0) {
      //FIXME: clean resources
      return -2;
   }


   //FIXME: rewrite this code
   snw_ice_get_sdp_attr(ice_ctx,sdp,&sdp_attr);
   DEBUG(log,"Setting ICE locally: offer=%u, audio=%u, video=%u,"
         " budnle=%u, rtcpmux=%u, trickle=%u", 
         offer, sdp_attr.audio, sdp_attr.video, 
         sdp_attr.bundle, sdp_attr.rtcpmux, sdp_attr.trickle);

   if (sdp_attr.audio) {
      SET_FLAG(session, WEBRTC_AUDIO);
   } else {
      CLEAR_FLAG(session, WEBRTC_AUDIO);
   }

   if (sdp_attr.video) {
      SET_FLAG(session, WEBRTC_VIDEO);
   } else {
      CLEAR_FLAG(session, WEBRTC_VIDEO);
   }

   if (sdp_attr.audio) {
      session->streams_num++;
   }

   if (sdp_attr.video && (!sdp_attr.audio || !IS_FLAG(session, WEBRTC_BUNDLE))) {
      session->streams_num++;
   }

   DEBUG(log, "Checking media stream, offer=%u, audio=%u, video=%u, streams_num=%u, flags=%u",
         offer,sdp_attr.audio,sdp_attr.video,session->streams_num, IS_FLAG(session, WEBRTC_BUNDLE));
   
   if (IS_FLAG(session, WEBRTC_AUDIO)) { 
   //if (sdp_attr.audio) {
      ret = snw_ice_create_media_stream(session,0);
      if (ret < 0) {
         ERROR(log, "ret=%d", ret);
         return ret;
      }
   }

   if (sdp_attr.video && (!sdp_attr.audio || !IS_FLAG(session, WEBRTC_BUNDLE))) {
      ret = snw_ice_create_media_stream(session,1);
      if (ret < 0) {
         ERROR(log, "ret=%d", ret);
         return ret;
      }
   }

   return 0;
}


//video_offer_sdp
static int
snw_ice_offer_sdp(snw_ice_context_t *ice_ctx, 
      snw_ice_session_t *session, uint32_t flowid, int sendonly) {
   static const char *sdp_template = 
      "v=0\r\no=- %lu %lu IN IP4 127.0.0.1\r\ns=%s\r\nt=0 0\r\n%s%s";
   static  const char *audio_mline_template = 
      "m=audio 1 RTP/SAVPF %d\r\nc=IN IP4 1.1.1.1\r\na=%s\r\na=rtpmap:%d opus/48000/2\r\n";
   static  const char *video_mline_template = 
      "m=video 1 RTP/SAVPF %d\r\nc=IN IP4 1.1.1.1\r\na=%s\r\na=rtpmap:%d VP8/90000\r\n"
      "a=rtcp-fb:%d ccm fir\r\na=rtcp-fb:%d nack\r\na=rtcp-fb:%d nack pli\r\na=rtcp-fb:%d goog-remb\r\n";
   snw_log_t *log = ice_ctx->log;
   char sdp[1024], audio_mline[256], video_mline[512];
   int ret = 0;

   DEBUG(log,"sendonly=%u",sendonly);

   memset(audio_mline,0,512);
   snprintf(audio_mline, 256, audio_mline_template,
       OPUS_PT, sendonly ? "sendonly" : "sendrecv", OPUS_PT);

   memset(video_mline,0,512);
   snprintf(video_mline, 512, video_mline_template,
       VP8_PT, sendonly ? "sendonly" : "sendrecv",
       VP8_PT, VP8_PT, VP8_PT, VP8_PT, VP8_PT);

   memset(sdp,0,1024);
   snprintf(sdp, 1024, sdp_template,
       get_real_time(), get_real_time(),
       "PeerCall Replay", audio_mline, video_mline);

   session->sdp = strdup(sdp);
   ret = snw_ice_session_setup(ice_ctx, session, 0, (char *)sdp);
   if (ret < 0) {
      ICE_ERROR2("Error setting ICE locally, ret=%d",ret);
      return -4;
   }

   return 0;
}

//video_start_handler
void
snw_ice_connect_msg(snw_ice_context_t *ice_ctx, Json::Value &root, uint32_t flowid) {
   snw_context_t *ctx = (snw_context_t*)ice_ctx->ctx;
   snw_log_t *log = ice_ctx->log;
   snw_ice_session_t *session;
   snw_ice_channel_t *channel;
   int is_new = 0;
   uint32_t channelid;
   
   try {
      /*Json::FastWriter writer;
      std::string output;
      root["id"] = flowid;
      root["sessionid"] = flowid;
      root["rc"] = 0;
      output = writer.write(root);
      DEBUG(log,"ice start, flowid=%u, len=%u, root=%s", 
                flowid, output.size(), output.c_str());*/
      channelid = root["channelid"].asUInt();
   } catch (...) {
      //ERROR(log, "json format error, data=%s", output.c_str());
      return;
   }

   session = (snw_ice_session_t*)snw_ice_session_get(ice_ctx,flowid,&is_new);
   if (!session) {
      ERROR(log,"failed to malloc, flowid=%u",flowid);
      return;
   }

   if (!is_new) {
      ERROR(log,"old session, flowid=%u",session->flowid);
      return;
   }

   DEBUG(log,"init new session, channelid=%u, flowid=%u", channelid, session->flowid);
   //session->flowid = flowid;
   session->channelid = channelid;
   session->controlling = 0;
   session->base = ctx->ev_base;
   session->ready = 0;
   session->flags = 0;
   /*if (is_publisher) {
      SET_FLAG(session,ICE_PUBLISHER);
   } else {
      snw_ice_session_t *s = 0;
      SET_FLAG(session,ICE_SUBSCRIBER);
      s = (snw_ice_session_t*)snw_ice_session_search(ice_ctx,roomid);
      if (s) {
         DEBUG(log, "forward session, flowid=%u, forwardid=%u", session->flowid, s->forwardid);
         s->forwardid = session->flowid;
      }
   }*/
   INIT_LIST_HEAD(&session->streams.list);
   DEBUG(log,"search channel, flowi=%u, channelid=%u",flowid,channelid);
   channel = (snw_ice_channel_t*)snw_ice_channel_search(ice_ctx,channelid);
   if (!channel) {
      ERROR(log,"channel not found, flowid=%u, channleid=%u",flowid,channelid);
      return;
   }
   session->channel = channel;
 
   snw_ice_offer_sdp(ice_ctx,session,flowid,0);
   return;
}

void
snw_ice_stop_msg(snw_ice_context_t *ice_ctx, Json::Value &root, uint32_t flowid) {
   snw_log_t *log = ice_ctx->log;
   snw_ice_session_t *session;
   
   session = (snw_ice_session_t*)snw_ice_session_search(ice_ctx,flowid);
   if (!session) {
      WARN(log,"session not found, flowid=%u",flowid);
      return;
   }
   WARN(log,"FIXME stop session, flowid=%u",flowid);

   return;
}



void 
ice_session_cleanup(snw_ice_session_t *session) {
   snw_log_t *log = 0;

   if (!session) return;
   log = session->ice_ctx->log;

   //FIXME: free streams

   DEBUG(log, "FIXME: free agent");
   if (session->agent != NULL) {
      session->agent = NULL;
   }

   free(session->rtp_profile);
   session->rtp_profile = NULL;
   free(session->local_sdp);
   session->local_sdp = NULL;
   free(session->remote_sdp);
   session->remote_sdp = NULL;

   if (session->audio_mid != NULL) {
      free(session->audio_mid);
      session->audio_mid = NULL;
   }

   if(session->video_mid != NULL) {
      free(session->video_mid);
      session->video_mid = NULL;
   }

   CLEAR_FLAG(session, WEBRTC_READY);
   DEBUG(log, "FIXME: WebRTC resources freed, flowid=%u", session->flowid);
   return;
}

void ice_component_cleanup(ice_component_t *component) {
   struct list_head *pos, *n;

   if (!component)
      return;

   if (component->dtls != NULL) {
      //FIXME: clean srtp object
      //dtls_srtp_destroy(component->dtls);
      //component->dtls = NULL;
   }

   list_for_each_safe(pos,n,&component->retransmit_buffer.list) {
      rtp_packet_t *p = list_entry(pos,rtp_packet_t,list);
      list_del(pos);
      free(p->data);
      free(p);
   }

   snw_component_deallocate(component->stream->session->ice_ctx, component);

   return;
}

void ice_component_free(ice_component_t *components, ice_component_t *component) {
   struct list_head *pos,*n;
   ice_component_t *c = NULL;

   if (!components || !component)
      return;

   /*{//DEBUG
      struct list_head *n;
      list_for_each(n,&components->list) {
         ice_component_t *t = list_entry(n,ice_component_t,list);
         //DEBUG("view component, cid=%u(%p)", t->component_id, t);
      }
   }*/

   list_for_each_safe(pos,n,&components->list) {
      ice_component_t *t = list_entry(pos,ice_component_t,list);
      if (t->component_id == component->component_id) {
         //DEBUG("remove component, cid=%u",t->component_id);
         list_del(pos);
         c = t;
      }
   }

   if (c) {
      ice_component_cleanup(c);
   } else {
      //ERROR("component not found, cid=%u", component->component_id);
   }

   /*{//DEBUG
      struct list_head *n;
      list_for_each(n,&components->list) {
         ice_component_t *s = list_entry(n,ice_component_t,list);
         //DEBUG("view component, cid=%u(%p)", s->component_id, s);
      }
   }*/

/*
   ice_stream_t *stream = component->stream;
   if(stream == NULL)
      return;
   ice_session_t *handle = stream->handle;
   if(handle == NULL)
      return;
   if(components != NULL)
      g_hash_table_remove(components, GUINT_TO_POINTER(component->component_id));
   component->stream = NULL;
   if(component->source != NULL) {
      g_source_destroy(component->source);
      g_source_unref(component->source);
      component->source = NULL;
   }
   if(component->dtls != NULL) {
      dtls_srtp_destroy(component->dtls);
      component->dtls = NULL;
   }
   if(component->retransmit_buffer != NULL) {
      rtp_packet_t *p = NULL;
      GList *first = g_list_first(component->retransmit_buffer);
      while(first != NULL) {
         p = (rtp_packet_t *)first->data;
         first->data = NULL;
         component->retransmit_buffer = g_list_delete_link(component->retransmit_buffer, first);
         g_free(p->data);
         p->data = NULL;
         g_free(p);
         first = g_list_first(component->retransmit_buffer);
      }
   }
*/
   //DEBUG("FIXME: remove candidate list, is_empty=%u",list_empty(&component->candidates.list));
   /*if( !list_empty(&component->candidates.list) ) {
      struct list_head *i, *n;
      list_for_each_safe(i,n,&component->candidates.list) {
         candidate_t *c = list_entry(i,candidate_t,list);
         candidate_free(c);
         list_del(i);
         //if(c != NULL) {
         //   candidate_free(c);
         //   c = NULL;
         //}
      }
      g_slist_free(candidates);
      candidates = NULL;
   }
   component->candidates = NULL;*/
   INIT_LIST_HEAD(&component->candidates.list);
/*
   if(component->local_candidates != NULL) {
      GSList *i = NULL, *candidates = component->local_candidates;
      for (i = candidates; i; i = i->next) {
         char *c = (char *) i->data;
         if(c != NULL) {
            g_free(c);
            c = NULL;
         }
      }
      g_slist_free(candidates);
      candidates = NULL;
   }
   component->local_candidates = NULL;
   if(component->remote_candidates != NULL) {
      GSList *i = NULL, *candidates = component->remote_candidates;
      for (i = candidates; i; i = i->next) {
         char *c = (char *) i->data;
         if(c != NULL) {
            g_free(c);
            c = NULL;
         }
      }
      g_slist_free(candidates);
      candidates = NULL;
   }
   component->remote_candidates = NULL;
   if(component->selected_pair != NULL)
      g_free(component->selected_pair);
   component->selected_pair = NULL;
   if(component->last_seqs_audio)
      seq_list_free(&component->last_seqs_audio);
   if(component->last_seqs_video)
      seq_list_free(&component->last_seqs_video);
   ice_stats_reset(&component->in_stats);
   ice_stats_reset(&component->out_stats);
   g_free(component);
*/
}

void ice_stream_cleanup(snw_ice_stream_t *stream) {
   snw_ice_context_t *ice_ctx = 0;

   if (!stream)
      return;
   ice_ctx = stream->session->ice_ctx;

   //FIXME: delete components
   if (stream->rtp_component != NULL) {
      ice_component_free(&stream->components, stream->rtp_component);
   }

   if (stream->rtcp_component != NULL) {
      ice_component_free(&stream->components, stream->rtcp_component);
   }

   snw_stream_deallocate(ice_ctx,stream);

   return;
}

void 
ice_stream_free(snw_ice_stream_t *streams, snw_ice_stream_t *stream) {
   snw_log_t *log = 0;
   struct list_head *pos,*n;
   snw_ice_stream_t *d = NULL; 

         
   if (!streams || !stream)
      return;
   log = stream->session->ice_ctx->log;

   /*{//DEBUG
      struct list_head *n;
      list_for_each(n,&streams->list) {
         ice_stream_t *s = list_entry(n,ice_stream_t,list);
         DEBUG("view stream, sid=%u(%p)", s->stream_id, s);
      }
   }*/


   list_for_each_safe(pos,n,&streams->list) {
      snw_ice_stream_t *s = list_entry(pos,snw_ice_stream_t,list);
      //DEBUG("delete stream, sid=%u(%p), sid=%u(%p)",
      //      s->stream_id, s, stream->stream_id, stream);
      if ( s->stream_id == stream->stream_id ) {
         //DEBUG("delete stream, sid=%u",s->stream_id);
         list_del(pos);
         d = s;
      }
   }

   if (d) {
      ice_stream_cleanup(d);
   } else {
      ERROR(log, "stream not found, sid=%u", stream->stream_id);
   }

   /*{//DEBUG
      struct list_head *n;
      list_for_each(n,&streams->list) {
         ice_stream_t *s = list_entry(n,ice_stream_t,list);
         DEBUG("view stream, s-sid=%u(%p)", s->stream_id, s);
      }
   }*/

   return;
}

int
snw_ice_merge_streams(snw_ice_session_t *session, int audio, int video) {
   snw_log_t *log = 0;

   if (!session) return -1;
   log = session->ice_ctx->log;

   DEBUG(log, "remove unneccessary RTP components, audio=%u,video=%u",audio,video);
   if (audio) {
      if( !list_empty(&session->streams.list) && session->video_stream) {
         session->audio_stream->video_ssrc = session->video_stream->video_ssrc;
         session->audio_stream->video_ssrc_peer = session->video_stream->video_ssrc_peer;
         ice_agent_attach_recv(session->agent, session->video_stream->stream_id, 1, NULL, NULL);
         ice_agent_attach_recv(session->agent, session->video_stream->stream_id, 2, NULL, NULL);
         ice_agent_remove_stream(session->agent, session->video_stream->stream_id);
         DEBUG(log, "delete stream due to bundle, sid=%u",session->video_stream->stream_id);
         ice_stream_free(&session->streams, session->video_stream);
      }
      session->video_stream = NULL;
      session->video_id = 0;
   } else if (video) {
      //FIXME: what to do?
   }

   return 0;
}

int
snw_ice_merge_components(snw_ice_session_t *session) {
   snw_log_t *log = 0;

   if (!session) return -1;
   log = session->ice_ctx->log;

   DEBUG(log, "removing unneccessary rtcp components");
   //FIXME: compare with pre_do_conncheck

   if(session->audio_stream && !list_empty(&session->audio_stream->components.list) ) {
      ice_agent_attach_recv(session->agent, session->audio_id, 2, NULL, NULL);
      ice_component_free(&session->audio_stream->components, session->audio_stream->rtcp_component);
      session->audio_stream->rtcp_component = NULL;
      //FIXME: remove component from stream
   }

   if(session->video_stream && !list_empty(&session->video_stream->components.list)) {
      ice_agent_attach_recv(session->agent, session->video_id, 2, NULL, NULL);
      ice_component_free(&session->video_stream->components, session->video_stream->rtcp_component);
      session->video_stream->rtcp_component = NULL;
      //FIXME: remove component from stream
   }

   return 0;
}

int
ice_merge_streams(snw_ice_session_t *session, int audio, int video) {
   snw_log_t *log = 0;

   if (!session) return -1;
   log = session->ice_ctx->log;

   DEBUG(log, "remove unneccessary RTP components, audio=%u,video=%u",audio,video);
   if (audio) {
      if( !list_empty(&session->streams.list) && session->video_stream) {
         session->audio_stream->video_ssrc = session->video_stream->video_ssrc;
         session->audio_stream->video_ssrc_peer = session->video_stream->video_ssrc_peer;
         ice_agent_attach_recv(session->agent, session->video_stream->stream_id, 1, NULL, NULL);
         ice_agent_attach_recv(session->agent, session->video_stream->stream_id, 2, NULL, NULL);
         ice_agent_remove_stream(session->agent, session->video_stream->stream_id);
         DEBUG(log, "delete stream due to bundle, sid=%u",session->video_stream->stream_id);
         ice_stream_free(&session->streams, session->video_stream);
      }
      session->video_stream = NULL;
      session->video_id = 0;
   } else if (video) {
      //FIXME: what to do?
   }

   return 0;
}  

int
ice_merge_components(snw_ice_session_t *session) {
   snw_log_t *log = 0;

   if (!session) return -1;
   log = session->ice_ctx->log;

   DEBUG(log, "removing unneccessary rtcp components");
   //FIXME: compare with pre_do_conncheck

   if(session->audio_stream && !list_empty(&session->audio_stream->components.list) ) {
      ice_agent_attach_recv(session->agent, session->audio_id, 2, NULL, NULL);
      ice_component_free(&session->audio_stream->components, session->audio_stream->rtcp_component);
      session->audio_stream->rtcp_component = NULL;
      //FIXME: remove component from stream
   }

   if(session->video_stream && !list_empty(&session->video_stream->components.list)) {
      ice_agent_attach_recv(session->agent, session->video_id, 2, NULL, NULL);
      ice_component_free(&session->video_stream->components, session->video_stream->rtcp_component);
      session->video_stream->rtcp_component = NULL;
      //FIXME: remove component from stream
   }

   return 0;
}


int ice_setup_remote_credentials(snw_ice_session_t *session, snw_ice_stream_t *stream, ice_component_t *component) {
   snw_log_t *log = 0;
   candidate_t *c = NULL;
   struct list_head *gsc,*n;
   char *ufrag = NULL, *pwd = NULL;

   if (!session) return -1;
   log = session->ice_ctx->log;

   /* FIXME: make sense? */
   list_for_each_safe(gsc,n,&component->candidates.list) {
      c = list_entry(gsc,candidate_t,list);
      DEBUG(log, "remote stream info, sid=%d, cid=%d", c->stream_id, c->component_id);
      if (c->username && !ufrag)
         ufrag = c->username;
      if (c->password && !pwd)
         pwd = c->password;

      //PRINT_CANDIDATE(c);
      if (address_is_private(&(c->addr)) ) {
         char address[ICE_ADDRESS_STRING_LEN];
         address_to_string(&(c->addr), (char *)&address);
         DEBUG(log, "not removing private ip, ip=%s",address);
         //list_del(&c->list);
         /* FIXME: removing private ips causes failure of ICE process */
      }
   }

   if (ufrag && pwd) {
      DEBUG(log, "setting remote credentials, ufrag=%s,pwd=%s",ufrag,pwd);
      if (ice_agent_set_remote_credentials(session->agent, stream->stream_id, ufrag, pwd) != ICE_OK) {
         DEBUG(log, "failed to set remote credentials, sid=%u, cid=%u",stream->stream_id, component->component_id);
         return -1;
      }
   }

   return 0;
}

void 
ice_setup_remote_candidates(snw_ice_session_t *session, uint32_t stream_id, uint32_t component_id) {
   snw_log_t *log = 0;
   snw_ice_stream_t *stream = 0;
   ice_component_t *component = 0;
   int added = 0;
   
   if (!session || !session->agent || list_empty(&session->streams.list))
      return;
   log = session->ice_ctx->log;

   stream = snw_stream_find(&session->streams, stream_id);
   if (!stream || list_empty(&stream->components.list)) {
      ERROR(log, "stream not found, sid=%d, cid=%d", stream_id, component_id);
      return;
   }  
      
   if (stream->disabled) {
      ERROR(log, "stream info, disabled=%u, sid=%u, cid=%u", 
            stream->disabled, stream_id, component_id);
      return;
   }     
      
   component = snw_component_find(&stream->components, component_id);
   if (!component) {
      ERROR(log, "component not found, sid=%u, cid=%u", stream_id, component_id);
      return;
   }

   if(component->is_started) {
      DEBUG(log, "component started, sid=%u, cid=%u", stream_id, component_id);
      return;
   }

   if(list_empty(&component->candidates.list)) {
      DEBUG(log, "candidate list is empty");
      return;
   }
   DEBUG(log, "Setting credentials of remote candidates, sid=%d, cid=%d", stream_id, component_id);
   ice_setup_remote_credentials(session,stream,component);

   added = ice_agent_set_remote_candidates(session->agent, stream_id, component_id, &component->candidates);
   if(added <=  0 ) { //FIXME: compare to size of list candidates
      DEBUG(log, "failed to set remote candidates, added=%u", added);
   } else {
      DEBUG(log, "remote candidates set, added=%u",added);
      component->is_started = 1;
   }

   return;
}


int
try_ice_start(snw_ice_session_t *session) {
   snw_log_t *log = 0;

   if (!session) return -1;
   log = session->ice_ctx->log;

   //process_pending_trickles(session);

   if (IS_FLAG(session, WEBRTC_TRICKLE) && !IS_FLAG(session, WEBRTC_GATHER_DONE)) {
      DEBUG(log, "webrtc start with trickle");
      SET_FLAG(session, WEBRTC_START);
   } else {
      /* FIXME: never reach here */
      DEBUG(log, "Sending connectivity checks, audio_id=%u,video_id=%u",
             session->audio_id, session->video_id);
      if (session->audio_id > 0) {
         ice_setup_remote_candidates(session, session->audio_id, 1);
         if(!IS_FLAG(session, WEBRTC_RTCPMUX))  {
            /* section-5.1.3 in rfc5761 */
            ice_setup_remote_candidates(session, session->audio_id, 2);
         }
      }
      if (session->video_id > 0) {
         ice_setup_remote_candidates(session, session->video_id, 1);
         if(!IS_FLAG(session, WEBRTC_RTCPMUX))
            /* section-5.1.3 in rfc5761 */
            ice_setup_remote_candidates(session, session->video_id, 2);
      }
   }

   return 0;
}


void
snw_ice_sdp_msg(snw_ice_context_t *ice_ctx, Json::Value &root, uint32_t flowid) {
   snw_context_t *ctx = (snw_context_t*)ice_ctx->ctx;
   snw_log_t *log = ice_ctx->log;
   snw_ice_session_t *session;
   ice_sdp_attr_t sdp_attr;
   Json::Value type,jsep,jsep_trickle,sdp;
   Json::FastWriter writer;
   const char *jsep_type = NULL;
   char *jsep_sdp = NULL;
   //sdp_parser_t *sdp_parser = 0;
   std::string output;
   int ret = 0;

   session = (snw_ice_session_t*)snw_ice_session_search(ice_ctx, flowid);
   if (session == NULL) {
      ERROR(log, "failed to malloc");
      return;
   }

   try {

      jsep = root["sdp"];
      if (!jsep.isNull()) {
         type = jsep["type"];
         jsep_type = type.asString().c_str();
         DEBUG(log, "get sdp type, type=%s",jsep_type);
      } else {
         output = writer.write(root);
         ERROR(log, "failed to get sdp type, root=%s",output.c_str());
         goto jsondone;
      }

      if (!strcasecmp(jsep_type, "answer")) {
         // only handle answer
         DEBUG(log, "got sdp answer, answer=%s",jsep_type);
      } else if(!strcasecmp(jsep_type, "offer")) {
         ERROR(log, "not handling offer, type=%s", jsep_type);
         goto jsondone;
      } else {
         ERROR(log, "unknown message type, type=%s", jsep_type);
         goto jsondone;
      }
      sdp = jsep["sdp"];
      if (sdp.isNull() || !sdp.isString() ) {
         ERROR(log, "sdp not found");
         goto jsondone;
      }

      jsep_sdp = strdup(sdp.asString().c_str()); //FIXME: don't use strdup
      DEBUG(log, "Remote SDP, trickle=%u, s=%s", sdp_attr.trickle, jsep_sdp);

      ret = snw_ice_get_sdp_attr(ice_ctx,jsep_sdp,&sdp_attr);
      if (ret < 0) {
         ERROR(log, "invalid sdp, sdp=%s",jsep_sdp);
         goto jsondone;
      }

      /*DEBUG("stream info, audio=%u, video=%u, bundle=%u, rtcpmux=%u, trickle=%u",
            sdp_attr.audio, 
            sdp_attr.video, 
            sdp_attr.bundle, 
            sdp_attr.rtcpmux, 
            sdp_attr.trickle);*/
      /*if (sdp_attr.audio > 1 || sdp_attr.video > 1 ) {
         DEBUG("stream not supported more than one, audio=%u, video=%u", 
               sdp_attr.audio, sdp_attr.video);
      }*/

      if (!IS_FLAG(session, WEBRTC_READY)) {
         snw_ice_sdp_handle_answer(session, jsep_sdp);//sdp_parser);

         DEBUG(log, "setting webrtc flags, bundle=%u,rtcpmux=%u,trickle=%u",
                  sdp_attr.bundle,sdp_attr.rtcpmux,sdp_attr.trickle);
         if (sdp_attr.bundle) {
            SET_FLAG(session, WEBRTC_BUNDLE);
            ice_merge_streams(session,sdp_attr.audio,sdp_attr.video);
         } else {
            CLEAR_FLAG(session, WEBRTC_BUNDLE);
         }

         if (sdp_attr.rtcpmux) {
            SET_FLAG(session, WEBRTC_RTCPMUX);
            ice_merge_components(session);
         } else {
            CLEAR_FLAG(session, WEBRTC_RTCPMUX);
         }

         if (sdp_attr.trickle) {
            SET_FLAG(session, WEBRTC_TRICKLE);
         } else {
            CLEAR_FLAG(session, WEBRTC_TRICKLE);
         }

         //FIXME: rewrite it, move to sdp_attr_parsing
         verify_disabled_streams(session,sdp_attr.audio,sdp_attr.video,jsep_sdp);

         try_ice_start(session);

      } else {
         ERROR(log, "state error, flags=%u",session->flags);
         goto jsondone;
      }
      session->remote_sdp = strdup(jsep_sdp);

      root["rc"] = 0;
      output = writer.write(root);
      DEBUG(log, "Sending result to client, result=%s",output.c_str());
      //enqueue_msg_to_mcd(output.c_str(),output.size(),flowid);
      snw_shmmq_enqueue(ctx->snw_ice2core_mq,0,output.c_str(),output.size(),flowid);
   } catch (...) {
      root["rc"] = -1;
      output = writer.write(root);
      DEBUG(log, "json format error, root=%s",output.c_str());
      //enqueue_msg_to_mcd(output.c_str(),output.size(),flowid);
      snw_shmmq_enqueue(ctx->snw_ice2core_mq,0,output.c_str(),output.size(),flowid);
   }

jsondone:
   if (jsep_sdp)
      free(jsep_sdp);
   return;
}
int ice_sdp_handle_candidate(snw_ice_stream_t *stream, const char *candidate) {
   snw_log_t *log = 0;
   snw_ice_session_t *session = 0;
   ice_component_t *component = 0;
   candidate_t *c = 0;
   char foundation[16], transport[4], type[6]; 
   char ip[32], relip[32];
   uint32_t component_id, priority, port, relport;
   int ret;

   if (stream == NULL || candidate == NULL)
      return -1; 

   session = stream->session;
   if (session == NULL)
      return -2; 
   log = session->ice_ctx->log;

   if (strstr(candidate, "candidate:") == candidate) {
      candidate += strlen("candidate:");
   }   

   /* format: foundation component tranpsort priority ip port type ??? ??? ??? ??? */
   ret = sscanf(candidate, "%15s %30u %3s %30u %31s %30u typ %5s %*s %31s %*s %30u",
                           foundation, &component_id, transport, &priority,
                           ip, &port, type, relip, &relport);

   DEBUG(log, "parsing result, ret=%u, cid:%d sid:%d, type:%s, transport=%s, refaddr=%s:%d, addr=%s:%d",
         ret, component_id, stream->stream_id, type, transport, relip, relport, ip, port);

   if (ret >= 7) {
      component = snw_component_find(&stream->components, component_id);
      if (component == NULL) {
         ERROR(log, "component not found, cid=%u, sid=%u", component_id, stream->stream_id);
         return -3; 
      }   
         DEBUG(log, "component found, cid=%u, sid=%u", component_id, stream->stream_id);
      c = snw_ice_remote_candidate_new(type,transport);
      if (c != NULL) {
         DEBUG(log, "new candidate, cid=%u, sid=%u", component_id, stream->stream_id);
         c->component_id = component_id;
         c->stream_id = stream->stream_id;

         if (!strcasecmp(transport, "udp")) {
            c->transport = ICE_CANDIDATE_TRANSPORT_UDP;
         } else {
            /* FIXME: support other transport, see secion-4.5 in rfc6544 */
            candidate_free(c);
            return -4;
         }

         strncpy(c->foundation, foundation, ICE_CANDIDATE_MAX_FOUNDATION);
         c->priority = priority;
         address_set_from_string(&c->addr, ip);
         address_set_port(&c->addr, port);
         c->username = strdup(stream->ruser);
         c->password = strdup(stream->rpass);
         address_set_from_string(&c->base_addr, relip);
         address_set_port(&c->base_addr, relport);

         snw_ice_try_start_component(session,stream,component,c);
      }
   } else {
      ERROR(log, "failed to parse candidate, ret=%d, s=%s", ret, candidate);
      return ret;
   }
   return 0;
}

int 
snw_ice_process_new_candidate(snw_ice_session_t *session, Json::Value &candidate) {
   snw_log_t *log = 0;
   Json::Value mid, mline, rc, done;
   snw_ice_stream_t *stream = 0;
   int video = 0;
   int ret = 0;

   if (!session) return -1;
   log = session->ice_ctx->log;

   done = candidate["done"];
   if (!done.isNull()) {
      DEBUG(log, "No more remote candidates");
      SET_FLAG(session, WEBRTC_GATHER_DONE);
      return 0;
   }

   mid = candidate["id"];
   if (mid.isNull() || !mid.isString()) {
      return -2;
   }

   mline = candidate["label"];
   if (mline.isNull()|| !mline.isInt() || mline.asInt() < 0) {
      return -3;
   }

   rc = candidate["candidate"];
   if (rc.isNull() || !rc.isString()) {
      return -4;
   }

   DEBUG(log, "remote candidate, mid=%s, candidate=%s", mid.asString().c_str(), rc.asString().c_str());
   if ( !strncasecmp(mid.asString().c_str(),"video",5) ) {
      video = 1;
   }

   stream = video ? session->video_stream : session->audio_stream;
   if(stream == NULL) {
      return -5;
   }

   ret = ice_sdp_handle_candidate(stream, rc.asString().c_str());
   if(ret != 0) {
      ERROR(log, "failed to handle candidate, ret=%d)", ret);
      return -6;
   }

   return 0;
}


void
snw_ice_candidate_msg(snw_ice_context_t *ice_ctx, Json::Value &root, uint32_t flowid) {
   snw_context_t *ctx = (snw_context_t*)ice_ctx->ctx;
   snw_log_t *log = ice_ctx->log;
   snw_ice_session_t *session;
   Json::Value candidate;
   Json::FastWriter writer;
   std::string output;

   session = (snw_ice_session_t*)snw_ice_session_search(ice_ctx, flowid);
   if (!session) {
      DEBUG(log, "ice session is NULL");
      return;
   }

   try {
      candidate = root["candidate"];

      output = writer.write(candidate);
      DEBUG(log, "receive candidate, s=%s",output.c_str());

      if (!IS_FLAG(session, WEBRTC_TRICKLE)) {
         DEBUG(log, "supports trickle even if it didn't negotiate it");
         SET_FLAG(session, WEBRTC_TRICKLE);
      }    
     
      if (!session->audio_stream && !session->video_stream) {
         /* FIXME: save trickle candidate. */
         return;
      }    
 
      if ( !candidate.isNull() ) {
         int ret = 0; 
         if ((ret = snw_ice_process_new_candidate(session, candidate)) != 0) { 
            DEBUG(log, "got error, ret=%d", ret);
            return;
         }    
      } else {
         ERROR(log, "candidate is null");
      }    


      root["rc"] = 0; 
      output = writer.write(root);
      //enqueue_msg_to_mcd(output.c_str(),output.size(),flowid);
      snw_shmmq_enqueue(ctx->snw_ice2core_mq,0,output.c_str(),output.size(),flowid);

   } catch (...) {
      root["rc"] = -1;
      output = writer.write(root);
      DEBUG(log, "json format error, root=%s",output.c_str());
      //enqueue_msg_to_mcd(output.c_str(),output.size(),flowid);
      snw_shmmq_enqueue(ctx->snw_ice2core_mq,0,output.c_str(),output.size(),flowid);
   }



   return;
}

void
snw_ice_publish_msg(snw_ice_context_t *ice_ctx, Json::Value &root, uint32_t flowid) {
   snw_log_t *log = 0;
   snw_ice_session_t *session = 0;

   if (!ice_ctx) return;
   log = ice_ctx->log;

   // get session
   session = (snw_ice_session_t*)snw_ice_session_search(ice_ctx, flowid);
   if (!session) return;
   
   // update session
   DEBUG(log, "channel is published, flowid=%u, channelid=%u", 
         flowid, session->channelid);
   SET_FLAG(session,ICE_PUBLISHER);

   // start broadcasting session
   snw_print_channel_info(ice_ctx,session->channel); 
   
   return;
}

void
snw_ice_play_msg(snw_ice_context_t *ice_ctx, Json::Value &root, uint32_t flowid) {
   snw_log_t *log = 0;
   snw_ice_session_t *session = 0;
   uint32_t channelid = 0;

   if (!ice_ctx) return;
   log = ice_ctx->log;

   session = (snw_ice_session_t*)snw_ice_session_search(ice_ctx, flowid);
   if (!session) return;
   SET_FLAG(session,ICE_SUBSCRIBER);
   
   try {
      channelid = root["channelid"].asUInt();
   } catch (...) {
      ERROR(log, "json format error");
   }
   snw_channel_add_subscriber(ice_ctx, channelid, flowid);

  
   return;
}

void
snw_ice_fir_msg(snw_ice_context_t *ice_ctx, Json::Value &root, uint32_t flowid) {
   snw_log_t *log = 0;
   log = ice_ctx->log;
   DEBUG(log, "FIXME fir msg");
   return;
}

void
snw_ice_process_msg(snw_ice_context_t *ice_ctx, char *data, uint32_t len, uint32_t flowid) {
   snw_log_t *log = ice_ctx->log;
   Json::Value root;
   Json::Reader reader;
   Json::FastWriter writer;
   std::string output;
   uint32_t msgtype = 0, api = 0;
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
   } catch (...) {
      ERROR(log, "json format error, data=%s", data);
   }

   switch(api) {
      case SNW_ICE_CREATE:
         snw_ice_create_msg(ice_ctx,root,flowid);
         break;
      case SNW_ICE_CONNECT:
         snw_ice_connect_msg(ice_ctx,root,flowid);
         break;
      case SNW_ICE_STOP:
         snw_ice_stop_msg(ice_ctx,root,flowid);
         break;
      case SNW_ICE_SDP:
         snw_ice_sdp_msg(ice_ctx,root,flowid);
         break;
      case SNW_ICE_CANDIDATE:
         snw_ice_candidate_msg(ice_ctx,root,flowid);
         break;
      case SNW_ICE_PUBLISH:
         snw_ice_publish_msg(ice_ctx,root,flowid);
         break;
      case SNW_ICE_PLAY:
         snw_ice_play_msg(ice_ctx,root,flowid);
         break;
      case SNW_ICE_FIR:
         snw_ice_fir_msg(ice_ctx,root,flowid);
         break;

      default:
         ERROR(log, "unknow api, api=%u", api);
         break;
   }

   return;
}


