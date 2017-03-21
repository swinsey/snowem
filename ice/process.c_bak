#include <climits>

#include "flow.h"
#include "log.h"
#include "linux_list.h"
#include "ice.h"
#include <json/json.h>
#include "process.h"
#include "sdp.h"
#include "session.h"
#include "stream.h"
#include "rtp.h"
#include "utils.h"

int
handle_sdp(ice_session_t *session, const char* sdp) {
   int ret = 0;

   ICE_DEBUG2("handle sdp, sdp=%s",sdp);

   //FIXME: 'offer' argument should be set to 1?
   //FIXME: uncomment
   //ret = ice_session_setup(session, 0, (char *)sdp);
   if( ret < 0) {
      ICE_ERROR2("Error setting ICE locally, ret=%d",ret);
      return -4;
   }

   return 0;
}

int
process_pending_trickles(ice_session_t *handle) {

   ICE_DEBUG2("FIXME: Processing pending trickle candidates");
   //FIXME: for each pending trickle, call ice_trickle_parse
 
   return 0;
}

static int
replay_offer_sdp(ice_session_t *session, uint32_t flowid, int sendonly) {
   char sdptemp[1024], audio_mline[256], video_mline[512];

   ICE_DEBUG2("sendonly=%u",sendonly);

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
   handle_sdp(session,sdptemp);

   return CCD_OK;
}


int handle_peer_data_from_mcd(uint32_t flowid,Json::Value &root) {
	ice_session_t *session = NULL;
	std::string data = root["data"].asString();
	std::string media_type = root["media_type"].asString();
   int pkg_type = root["pkg_type"].asUInt();


   //FIXME: uncomment
	//session = (ice_session_t*)cache_handle_search(flowid);
	if ( !session )
   {
      ICE_ERROR2("flow does not exist, flowid=%u", flowid);   
	  return CCD_ERR;
   }

   if (!IS_FLAG(session, WEBRTC_READY)) {
      ICE_ERROR2("webrtc not ready, flowid=%u", flowid);   
      return CCD_OK;
   }

   if ( session->ready == 0 )
      return CCD_OK;

   rtp_header *rtp = (rtp_header *)data.c_str();
   if ((!pkg_type) && (media_type == "v"))
      rtp->type = VP8_PT;
   else if ((!pkg_type) && (media_type == "a"))
      rtp->type = OPUS_PT;

	rtp_packet_t *pkt = (rtp_packet_t *)malloc(sizeof(rtp_packet_t));
	pkt->data = (char*)malloc(data.length());
	memcpy(pkt->data, data.c_str(), data.length());
	pkt->length = data.length();
	pkt->type = (media_type == "v") ? RTP_PACKET_VIDEO : RTP_PACKET_AUDIO;
   pkt->control = (pkg_type == 0) ? 0: 1;
	pkt->encrypted = 0;

   ICE_DEBUG2("relay rtp packets, flowid=%u, len=%u, type=%u, control=%u, encrypted=%u, ssrc: %u, seq: %u",
         flowid, pkt->length, pkt->type, pkt->control, pkt->encrypted, rtp->ssrc, ntohs(rtp->seq_number));

   //FIXME: uncomment
   //send_rtp_pkt(session,pkt);

	return CCD_OK;
}

int
generate_sdp(ice_session_t *session) {
   ice_sdp_attr_t sdp_attr;
   sdp_parser_t *sdp_parser = NULL;
   char *sdp_merged;
   char *sdp;

   if (session == NULL)
      return -1;

   sdp = session->tempsdp;

   ICE_DEBUG2("sdp info, sdp=%s",sdp);
   sdp_parser = ice_sdp_get_parser(sdp);
   if (!sdp_parser) {
      return -3;
   }
   ice_get_sdp_attr(sdp_parser,&sdp_attr);
   sdp_parser_free(sdp_parser);

   /* Add our details */
   sdp_merged = ice_sdp_merge(session, sdp);
   if (sdp_merged == NULL) {
      //free(sdp_stripped);
      return -4;
   }

   /* FIXME Any disabled m-line? */
   if (strstr(sdp_merged, "m=audio 0")) {
      if(!IS_FLAG(session, WEBRTC_BUNDLE) || !sdp_attr.video) {
         ice_stream_t *stream = stream_find(&session->streams, session->audio_id);
         if (stream) {
            ICE_DEBUG2("disable audio stream, sid=%u",stream->stream_id);
            stream->disabled = 1;
         }
      }    
   }
   
   if (strstr(sdp_merged, "m=video 0")) {
      if (!IS_FLAG(session, WEBRTC_BUNDLE) || !sdp_attr.audio) {
         ice_stream_t *stream = NULL;
         if (!IS_FLAG(session, WEBRTC_BUNDLE)) {
            stream = stream_find(&session->streams, session->video_id);
         } else {
            uint32_t id = session->audio_id > 0 ? session->audio_id : session->video_id;
            stream = stream_find(&session->streams, id);
         }    
         if (stream) {
            ICE_DEBUG2("disable video stream, sid=%u",stream->stream_id);
            stream->disabled = 1;
         }
      }    
   }

   session->local_sdp = sdp_merged;
   //ICE_DEBUG2("generated sdp, local_sdp=%s",sdp_merged);

   return 0;
}


int
ice_merge_streams(ice_session_t *session, int audio, int video) {
   ICE_DEBUG2("remove unneccessary RTP components, audio=%u,video=%u",audio,video);
   if (audio) {
      if( !list_empty(&session->streams.list) && session->video_stream) {
         session->audio_stream->video_ssrc = session->video_stream->video_ssrc;
         session->audio_stream->video_ssrc_peer = session->video_stream->video_ssrc_peer;
         ice_agent_attach_recv(session->agent, session->video_stream->stream_id, 1, NULL, NULL);
         ice_agent_attach_recv(session->agent, session->video_stream->stream_id, 2, NULL, NULL);
         ice_agent_remove_stream(session->agent, session->video_stream->stream_id);
         ICE_DEBUG2("delete stream due to bundle, sid=%u",session->video_stream->stream_id);
         //FIXME: uncomment
         //ice_stream_free(&session->streams, session->video_stream);
      }
      session->video_stream = NULL;
      session->video_id = 0;
   } else if (video) {
      //FIXME: what to do?
   }

   return 0;
}

int
ice_merge_components(ice_session_t *session) {

   ICE_DEBUG2("removing unneccessary rtcp components");
   //FIXME: compare with pre_do_conncheck

   if(session->audio_stream && !list_empty(&session->audio_stream->components.list) ) {
      ice_agent_attach_recv(session->agent, session->audio_id, 2, NULL, NULL);
         //FIXME: uncomment
      //ice_component_free(&session->audio_stream->components, session->audio_stream->rtcp_component);
      session->audio_stream->rtcp_component = NULL;
      //FIXME: remove component from stream
   }
                  
   if(session->video_stream && !list_empty(&session->video_stream->components.list)) {
      ice_agent_attach_recv(session->agent, session->video_id, 2, NULL, NULL);
         //FIXME: uncomment
      //ice_component_free(&session->video_stream->components, session->video_stream->rtcp_component);
      session->video_stream->rtcp_component = NULL;
      //FIXME: remove component from stream
   }

   return 0;
}

int
verify_disabled_streams(ice_session_t *session, int audio, int video, const char *jsep_sdp) {

   /* FIXME Any disabled m-line? */
   if (strstr(jsep_sdp, "m=audio 0")) {
      if(!IS_FLAG(session, WEBRTC_BUNDLE) || !video) {
         ICE_DEBUG2("Marking audio stream as disabled");
         ice_stream_t *stream = stream_find(&session->streams, session->audio_id);
         if (stream) {
            ICE_DEBUG2("disable audio stream, sid=%u",stream->stream_id);
            stream->disabled = 1;
         }
      }
   }

   if (strstr(jsep_sdp, "m=video 0")) {
      if (!IS_FLAG(session, WEBRTC_BUNDLE) || !audio) {
         ice_stream_t *stream = NULL;
         if (!IS_FLAG(session, WEBRTC_BUNDLE)) {
            stream = stream_find(&session->streams, session->video_id);
         } else {
            uint32_t id = session->audio_id > 0 ? session->audio_id : session->video_id;
            stream = stream_find(&session->streams, id);
         }
         if (stream) {
            ICE_DEBUG2("disable video stream, sid=%u",stream->stream_id);
            stream->disabled = 1;
         }
      }
   }

   return 0;
}

int
try_ice_start(ice_session_t *session) {

   if (session == NULL)
      return -1;

   //process_pending_trickles(session);
  
   if (IS_FLAG(session, WEBRTC_TRICKLE) && !IS_FLAG(session, WEBRTC_GATHER_DONE)) {
      ICE_DEBUG2("webrtc start with trickle");
      SET_FLAG(session, WEBRTC_START);
   } else {
      /* FIXME: never reach here */
      ICE_DEBUG2("Sending connectivity checks, audio_id=%u,video_id=%u", 
             session->audio_id, session->video_id);
      if (session->audio_id > 0) {
         //FIXME: uncomment
         //ice_setup_remote_candidates(session, session->audio_id, 1);
         if(!IS_FLAG(session, WEBRTC_RTCPMUX)) {
            /* section-5.1.3 in rfc5761 */
         //FIXME: uncomment
            //ice_setup_remote_candidates(session, session->audio_id, 2);
         }
      }
      if (session->video_id > 0) {
         //FIXME: uncomment
         //ice_setup_remote_candidates(session, session->video_id, 1);
         if (!IS_FLAG(session, WEBRTC_RTCPMUX)) {
            /* section-5.1.3 in rfc5761 */
         //FIXME: uncomment
            //ice_setup_remote_candidates(session, session->video_id, 2);
         }
      }
   }

   return 0;
}

static int
video_sdp_handler(uint32_t flowid, Json::Value &root) {
   ice_sdp_attr_t sdp_attr;
   Json::Value type,jsep,jsep_trickle,sdp;
   Json::FastWriter writer;
   ice_session_t *session = NULL;
   sdp_parser_t *sdp_parser = NULL;
   const char *jsep_type = NULL;
   char *jsep_sdp = NULL; 
   std::string output;
   int ret = 0;

   //FIXME: uncomment
   //session = (ice_session_t*)cache_handle_search(flowid);
   if ( session == NULL ) {
      ICE_ERROR2("failed to malloc");
      return CCD_ERR;
   }

   try {

      jsep = root["sdp"];
      if ( !jsep.isNull() ) {
         type = jsep["type"];
         jsep_type = type.asString().c_str();
         ICE_DEBUG2("get sdp type, type=%s",jsep_type);
      } else {
         output = writer.write(root);
         ICE_ERROR2("failed to get sdp type, root=%s",output.c_str());
         goto jsondone;
      }

      if (!strcasecmp(jsep_type, "answer")) {
         // only handle answer
         ICE_DEBUG2("got sdp answer, answer=%s",jsep_type);
      } else if(!strcasecmp(jsep_type, "offer")) {
         ICE_ERROR2("not handling offer, type=%s", jsep_type);
         goto jsondone;
      } else {
         ICE_ERROR2("unknown message type, type=%s", jsep_type);
         goto jsondone;
      }

      sdp = jsep["sdp"];
      if (sdp.isNull() || !sdp.isString() ) {
         ICE_ERROR2("sdp not found");
         goto jsondone;
      }

      jsep_sdp = strdup(sdp.asString().c_str()); //FIXME: don't use strdup
      ICE_DEBUG2("Remote SDP, trickle=%u, s=%s", sdp_attr.trickle, jsep_sdp);

      sdp_parser = ice_sdp_get_parser(jsep_sdp);
      if (sdp_parser == NULL) {
         ICE_ERROR2("invalid sdp, sdp=%s",jsep_sdp);
         goto jsondone;
      }
      ret = ice_get_sdp_attr(sdp_parser,&sdp_attr);
      if (ret < 0) {
         ICE_ERROR2("invalid sdp, sdp=%s",jsep_sdp);
         goto jsondone;
      }

      /*ICE_DEBUG2("stream info, audio=%u, video=%u, bundle=%u, rtcpmux=%u, trickle=%u",
            sdp_attr.audio, 
            sdp_attr.video, 
            sdp_attr.bundle, 
            sdp_attr.rtcpmux, 
            sdp_attr.trickle);*/
      /*if (sdp_attr.audio > 1 || sdp_attr.video > 1 ) {
         ICE_DEBUG2("stream not supported more than one, audio=%u, video=%u", 
               sdp_attr.audio, sdp_attr.video);
      }*/
         
      if (!IS_FLAG(session, WEBRTC_READY)) {

         ice_sdp_handle_answer(session, sdp_parser);
         sdp_parser_free(sdp_parser);

         ICE_DEBUG2("setting webrtc flags, bundle=%u,rtcpmux=%u,trickle=%u",
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
         ICE_ERROR2("state error, flags=%u",session->flags);
         goto jsondone;
      }
      session->remote_sdp = strdup(jsep_sdp);

      root["rc"] = 0;
      output = writer.write(root);
      ICE_DEBUG2("Sending result to client, result=%s",output.c_str());
      //FIXME: uncomment
      //enqueue_msg_to_mcd(output.c_str(),output.size(),flowid);
   } catch (...) {
      root["rc"] = -1;
      output = writer.write(root);
      ICE_DEBUG2("json format error, root=%s",output.c_str());
      //FIXME: uncomment
      //enqueue_msg_to_mcd(output.c_str(),output.size(),flowid);
   }

jsondone:
   if (jsep_sdp) 
      free(jsep_sdp);

   return CCD_OK;
}

static int
video_offer_sdp(ice_session_t *session, uint32_t flowid, int sendonly) {
   char sdptemp[1024], audio_mline[256], video_mline[512];

   ICE_DEBUG2("sendonly=%u",sendonly);

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
   handle_sdp(session,sdptemp);

   return CCD_OK;
}

static int
video_start_handler(uint32_t flowid, Json::Value &root, int is_sender) {
   Json::FastWriter writer;
   ice_session_t *session = NULL;
   //uint32_t isNew = 0;

#ifdef DEBUG_ENABLE   
   {//print debug
      std::string output;
      Json::FastWriter writer;
      root["rc"] = 0;
      output = writer.write(root);
      ICE_DEBUG2("starting video, s=%s",output.c_str());
   }
   ICE_DEBUG2("get ice handle, flowid=%u",flowid);
#endif
   try {
      //std::string client_type;
      //client_type = root[];

   } catch (...) {
      std::string output;
      root["rc"] = -1;
      output = writer.write(root);
      ICE_DEBUG2("json format error, root=%s",output.c_str());
      //FIXME: uncomment
      //enqueue_msg_to_mcd(output.c_str(),output.size(),flowid);
   }

   //FIXME: uncomment
   //session = (ice_session_t*)cache_handle_get(flowid,isNew);
   if ( session == NULL ) {
      ICE_ERROR2("failed to malloc, flowid=%u",flowid);
      return CCD_ERR;
   }
   memset(session,0,sizeof(ice_session_t));
   session->controlling = 0;
   session->flowid = flowid;
   //FIXME: uncomment
   //session->base = g_event_base;
   session->ready = 0;
   session->flags = 0;
   if ( is_sender ) {
      SET_FLAG(session,ICE_SENDER);
   } else {
      SET_FLAG(session,ICE_RECEIVER);
   }

   INIT_LIST_HEAD(&session->streams.list);

   ICE_DEBUG2("FIXME: verify request having authorization");
   //sleep(1);
   video_offer_sdp(session,flowid,0);

   return CCD_OK;
}

static int
video_candidate_handler(uint32_t flowid,Json::Value &root) {
   ice_session_t *handle = NULL;
   Json::Value candidate;
   Json::FastWriter writer;
   std::string output;

   //FIXME: uncomment 
   //handle = (ice_session_t*)cache_handle_search(flowid);
   if ( handle == NULL ) {
      ICE_DEBUG2("ice handle is NULL");
      return CCD_ERR;
   }

   try {
      candidate = root["candidate"];

      output = writer.write(candidate);
      ICE_DEBUG2("receive candidate, s=%s",output.c_str());

      if (!IS_FLAG(handle, WEBRTC_TRICKLE)) {
         ICE_DEBUG2("supports trickle even if it didn't negotiate it");
         SET_FLAG(handle, WEBRTC_TRICKLE);
      }    
      
      if ( handle->audio_stream == NULL && handle->video_stream == NULL ) {
         /* FIXME: save trickle candidate. */
         return CCD_ERR;
      }    
 
      if ( !candidate.isNull() ) {
         //FIXME: uncomment 
         /*int ret = 0;
         if ((ret = ice_process_new_candidate(handle, candidate)) != 0) {
            ICE_DEBUG2("got error, ret=%d", ret);
            return CCD_ERR;
         }*/
      } else {
         ICE_ERROR2("candidate is null");
      }


      root["rc"] = 0;
      output = writer.write(root);
      //FIXME: uncomment 
      //enqueue_msg_to_mcd(output.c_str(),output.size(),flowid);

   } catch (...) {
      root["rc"] = -1;
      output = writer.write(root);
      ICE_DEBUG2("json format error, root=%s",output.c_str());
      //FIXME: uncomment 
      //enqueue_msg_to_mcd(output.c_str(),output.size(),flowid);
   }

   return CCD_OK;
}


static int
video_stop_handler(uint32_t flowid,Json::Value &root) {
   ice_session_t *session = NULL;
 
   //FIXME: uncomment 
   //session = (ice_session_t*)cache_handle_search(flowid);
   if ( session == NULL ) {
      ICE_ERROR2("No handle found, flowid=%u",flowid);
      return CCD_ERR;
   }

   ICE_DEBUG2("stop recording");
   //session->active = FALSE;
   // FIXME: uncomment
   /*if(session->a_recorder) {
      recorder_close(session->a_recorder);
      ICE_DEBUG2("Closed audio recording %s", session->a_recorder->filename ? session->a_recorder->filename : "??");
      recorder_free(session->a_recorder);
   }
   session->a_recorder = NULL;
   if(session->v_recorder) {
      recorder_close(session->v_recorder);
      ICE_DEBUG2("Closed video recording %s\n", session->v_recorder->filename ? session->v_recorder->filename : "??");
      recorder_free(session->v_recorder);
   }*/ 

   ICE_DEBUG2("FIXME: cleanup session, flowid=%u",flowid);
  
   //FIXME: uncomment 
   //cache_handle_remove(flowid);
    
   return CCD_OK;
}

static int
video_fir_handler(uint32_t flowid, Json::Value &root) {
   ice_session_t *handle = NULL;
   ice_stream_t *stream = NULL;
   ice_component_t *component = NULL;
   struct list_head *n,*p;
 
   //FIXME: uncomment 
   //handle = (ice_session_t*)cache_handle_search(flowid);
   if ( handle == NULL ) {
      ICE_ERROR2("No handle found, flowid=%u",flowid);
      return CCD_ERR;
   }

   list_for_each(n,&handle->streams.list) {
      stream = (ice_stream_t *)list_entry(n,ice_stream_t,list);
      list_for_each(p,&stream->components.list) {
         component = (ice_component_t *)list_entry(p,ice_component_t,list);
         ICE_DEBUG2("forcing to send fir req, flowid=%u, cid=%u, sid=%u",
                flowid,stream->stream_id, component->component_id);
         //FIXME: uncomment
         //ice_send_fir(handle,component,1);

         // send cached rtp packets
         if ( rtp_list_size(&component->rtplist) != 0 ) {
            struct list_head *h;
            ICE_DEBUG2("kickstart rtp packet list, sid=%u, cid=%u, size=%u",
                  stream->stream_id, component->component_id,rtp_list_size(&component->rtplist));
            list_for_each(h,&component->rtplist.list) {
               rtp_packet_t *p = list_entry(h,rtp_packet_t,list);
               ICE_DEBUG2("quick push frame, is_keyframe: %u", p->keyframe);
               ice_handle_incoming_rtp(handle,p->control,1,p->data,p->length);
            }
         }

      }
   }

   return CCD_OK;
}



int
process_msg(char *data, int len, uint32_t flow) {
   Json::Value root,cmd,subcmd;
   Json::Reader reader;
   Json::FastWriter writer;
   std::string output;
   bool parsedSuccess = false;

   //HEXDUMP(data,len,"data");

   parsedSuccess = reader.parse(data,data+len,root,false);
   if ( !parsedSuccess ) { 
      ICE_ERROR2("error json format,len=%u,text=%s",len,data);
      return CCD_ERR;
   }   

   try {
      cmd = root["cmd"];

      if (cmd.asUInt() == SGN_INTERNAL) {
    	  subcmd = root["subcmd"];
    	  switch(subcmd.asUInt()) {
    	  case SGN_INTERNAL_PEER_DATA:
    	  	handle_peer_data_from_mcd(flow,root);
    	  	break;
    	  default:
    		  ICE_DEBUG2("Unknown request, cmd=%u, subcmd=%u", cmd.asUInt(), subcmd.asUInt());
    		  break;
    	  }
      } 
      else if (cmd.asUInt() == SGN_VIDEO)
      {
    	  subcmd = root["subcmd"];
    	  switch(subcmd.asUInt()) {
			 case SGN_VIDEO_START:
            // send sdp offer to client, including list of ips 
            // and setup callbacks for ice protocol
            video_start_handler(flow,root,1);
				break;

			 case SGN_VIDEO_VIEW:
            // send sdp offer to client, including list of ips 
            // and setup callbacks for ice protocol
            //video_view_handler(flow,root);
            video_start_handler(flow,root,0);
				break;

			 case SGN_VIDEO_SDP:
            // recv sdp answer from client
            video_sdp_handler(flow,root);
				break;

			 case SGN_VIDEO_CANDIDATE:
            // recv ip candidate from client
            video_candidate_handler(flow,root); 
				break;

          case SGN_VIDEO_STOP:
            video_stop_handler(flow,root);
            break;

          case SGN_VIDEO_FIR:
            video_fir_handler(flow,root);
            break;

			 default:
				ICE_DEBUG2("Unknown request, cmd=%u, subcmd=%u", cmd.asUInt(), subcmd.asUInt());
				break;
        }
      }
      else {
    	  return CCD_OK;
      }


   } catch (...) {
      ICE_ERROR2("json error");
   }

   return 0;
}



