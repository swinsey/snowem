
#include <sofia-sip/sdp.h>

#include "log.h"
#include "ice_types.h"
#include "ice_session.h"
#include "ice_stream.h"
#include "sdp.h"
#include "utils.h"

static su_home_t *g_home = NULL;

int
ice_sdp_init(snw_ice_context_t *ctx) {

   DEBUG(ctx->log,"sdp initialization");
   g_home = (su_home_t*)su_home_new(sizeof(su_home_t));
   if(su_home_init(g_home) < 0) {
      ERROR(ctx->log,"Ops, error setting up sofia-sdp?");
      return -1; 
   }   
   return 0;
}

void ice_sdp_deinit(void) {
   su_home_deinit(g_home);
   su_home_unref(g_home);
   g_home = NULL;
}

sdp_parser_t *ice_sdp_get_parser(snw_ice_context_t *ctx, const char *sdp) {
   sdp_parser_t *parser = NULL;

   if (!sdp) {
      ERROR(ctx->log,"sdp is null, sdp=%p",sdp);
      return NULL;
   }   

   parser = sdp_parse(g_home, sdp, strlen(sdp), 0); 
   return parser;
}

int ice_get_sdp_attr(sdp_parser_t *parser, ice_sdp_attr_t *sdp_attr) {
   sdp_session_t *parsed_sdp = NULL;
   sdp_media_t *m = NULL;
   sdp_attribute_t *a;

   if (!parser || !sdp_attr) {
      ICE_ERROR2("null pointer");
      return -1;
   }

   parsed_sdp = sdp_session(parser);
   if (!parsed_sdp) {
      ICE_ERROR2("Error parsing SDP, err=%s", sdp_parsing_error(parser));
      sdp_parser_free(parser);
      return -2;
   } 

   m = parsed_sdp->sdp_media;
   memset(sdp_attr,0,sizeof(*sdp_attr));
   ICE_DEBUG2("sdp attribute, audio=%u, video=%u, bundle=%u, trickle=%u, rtcpmux=%u", 
         sdp_attr->audio, 
         sdp_attr->video, 
         sdp_attr->bundle, 
         sdp_attr->trickle,
         sdp_attr->rtcpmux);
   while (m) {
      if (m->m_type == sdp_media_audio && m->m_port > 0) {
         sdp_attr->audio = sdp_attr->audio + 1;
         a = m->m_attributes;
         while (a) {
            ICE_DEBUG2("audio attr, num=%u, name=%s, value=%s",
                   sdp_attr->audio, a->a_name, a->a_value);
            if (strcasecmp(a->a_name,"rtcp-mux")) {
               sdp_attr->rtcpmux = 1;
            } else if (strcasecmp(a->a_name,"ice-options")) {
               //get trickle info
            }
            a = a->a_next;
         }
      } else if (m->m_type == sdp_media_video && m->m_port > 0) {
         sdp_attr->video = sdp_attr->video + 1;
         a = m->m_attributes;
         while (a) {
            ICE_DEBUG2("audio attr, num=%u, name=%s, value=%s",
                   sdp_attr->video, a->a_name, a->a_value);
            if (strcasecmp(a->a_name,"rtcp-mux")) {
               sdp_attr->rtcpmux = 1;
            } else if (strcasecmp(a->a_name,"ice-options")) {
               //get trickle info
            }
            a = a->a_next;
         }
      }
      m = m->m_next;
   }  

   a = parsed_sdp->sdp_attributes;
   while (a) {
      ICE_DEBUG2("global attr, name=%s, value=%s",a->a_name, a->a_value);
      if (!strcasecmp(a->a_name,"group") && strstr(a->a_value,"BUNDLE") ) {
         sdp_attr->bundle = 1;
      } else {
         //get other info
      }
      a = a->a_next;
   }

   sdp_attr->trickle = 1;
   ICE_DEBUG2("sdp attribute, audio=%u, video=%u, bundle=%u, trickle=%u, rtcpmux=%u", 
         sdp_attr->audio, 
         sdp_attr->video, 
         sdp_attr->bundle, 
         sdp_attr->trickle,
         sdp_attr->rtcpmux);

   return 0;
}

void ice_sdp_add_global_attrs(snw_ice_session_t *session, sdp_session_t *orig_sdp, const char* sdpstr, char* sdp) {
   char wms[ICE_BUFSIZE];
   char buffer[512];

   /* Version v= */
   strncat(sdp, "v=0\r\n", ICE_BUFSIZE);

   /* Origin o= */
   if (orig_sdp->sdp_origin) {
      snprintf(buffer, 512, "o=%s %lu %lu IN IP4 127.0.0.1\r\n",
            orig_sdp->sdp_origin->o_username ? orig_sdp->sdp_origin->o_username : "-",
            orig_sdp->sdp_origin->o_id, orig_sdp->sdp_origin->o_version);
      strncat(sdp, buffer, ICE_BUFSIZE);
   } else {
      int64_t sessid = get_real_time();
      snprintf(buffer, 512, "o=%s %lu  %lu IN IP4 0.0.0.0\r\n", "-", sessid, sessid/*version*/);
      strncat(sdp, buffer, ICE_BUFSIZE);
   }

   /* session name s= */
   if (orig_sdp->sdp_subject && strlen(orig_sdp->sdp_subject) > 0) {
      snprintf(buffer, 512, "s=%s\r\n", orig_sdp->sdp_subject);
   } else {
      snprintf(buffer, 512, "s=%s\r\n", "PeerCall");
   }
   strncat(sdp, buffer, ICE_BUFSIZE);

   /* timing t= */
   snprintf(buffer, 512, "t=%lu %lu\r\n", orig_sdp->sdp_time ? orig_sdp->sdp_time->t_start : 0, 
                                          orig_sdp->sdp_time ? orig_sdp->sdp_time->t_stop : 0);
   strncat(sdp, buffer, ICE_BUFSIZE);

   /* lite ice a= */
   strncat(sdp, "a=ice-lite\r\n", ICE_BUFSIZE);

   /* bundle: add new global attribute */
   int audio = (strstr(sdpstr, "m=audio") != NULL);
   int video = (strstr(sdpstr, "m=video") != NULL);
   strncat(sdp, "a=group:BUNDLE", ICE_BUFSIZE);
   if (audio) {
      snprintf(buffer, 512, " %s", session->audio_mid ? session->audio_mid : "audio");
      strncat(sdp, buffer, ICE_BUFSIZE);
   }
   if (video) {
      snprintf(buffer, 512, " %s", session->video_mid ? session->video_mid : "video");
      strncat(sdp, buffer, ICE_BUFSIZE);
   }
   strncat(sdp, "\r\n", ICE_BUFSIZE);

   /* msid-semantic: add new global attribute */
   strncat(sdp, "a=msid-semantic: WMS peercall\r\n", ICE_BUFSIZE);
   memset(wms, 0, ICE_BUFSIZE);
   strncat(wms, "WMS", ICE_BUFSIZE);
   if (orig_sdp->sdp_attributes) {
      sdp_attribute_t *a = orig_sdp->sdp_attributes;
      while(a) {
         if(a->a_value == NULL) {
            snprintf(buffer, 512, "a=%s\r\n", a->a_name);
            strncat(sdp, buffer, ICE_BUFSIZE);
         } else {
            snprintf(buffer, 512, "a=%s:%s\r\n", a->a_name, a->a_value);
            strncat(sdp, buffer, ICE_BUFSIZE);
         }
         a = a->a_next;
      }
   }

   return;
}

void ice_sdp_add_media_application(snw_ice_session_t *session, sdp_media_t *m, char* sdp) {
   char buffer[512];

   if (m->m_type != sdp_media_application) {
      switch(m->m_mode) {
         case sdp_sendonly:
            strncat(sdp, "a=sendonly\r\n", ICE_BUFSIZE);
            break;
         case sdp_recvonly:
            strncat(sdp, "a=recvonly\r\n", ICE_BUFSIZE);
            break;
         case sdp_inactive:
            strncat(sdp, "a=inactive\r\n", ICE_BUFSIZE);
            break;
         case sdp_sendrecv:
         default:
            strncat(sdp, "a=sendrecv\r\n", ICE_BUFSIZE);
            break;
      }
      /* rtcp-mux */
      snprintf(buffer, 512, "a=rtcp-mux\r\n");
      strncat(sdp, buffer, ICE_BUFSIZE);
      /* RTP maps */
      if (m->m_rtpmaps) {
         sdp_rtpmap_t *rm = NULL;
         for (rm = m->m_rtpmaps; rm; rm = rm->rm_next) {
            snprintf(buffer, 512, "a=rtpmap:%u %s/%lu%s%s\r\n",
               rm->rm_pt, rm->rm_encoding, rm->rm_rate,
               rm->rm_params ? "/" : "",
               rm->rm_params ? rm->rm_params : "");
            strncat(sdp, buffer, ICE_BUFSIZE);
         }
         for (rm = m->m_rtpmaps; rm; rm = rm->rm_next) {
            if (rm->rm_fmtp) {
               snprintf(buffer, 512, "a=fmtp:%u %s\r\n", rm->rm_pt, rm->rm_fmtp);
               strncat(sdp, buffer, ICE_BUFSIZE);
            }
         }
      }
   }

   return;
}

void ice_sdp_add_credentials(snw_ice_session_t *session, sdp_media_t *m, int video, char* sdp) {
   snw_ice_stream_t *stream = NULL;
   char buffer[512];
   char *ufrag = NULL;
   char *password = NULL;
   const char *dtls_role = NULL;

   if ( video ) {
      uint32_t id = session->video_id;

      ICE_DEBUG2("add credentials, id=%u, bundle=%u",id,IS_FLAG(session, WEBRTC_BUNDLE));

      if (id == 0 && IS_FLAG(session, WEBRTC_BUNDLE))
          id = session->audio_id > 0 ? session->audio_id : session->video_id;

      stream = snw_stream_find(&session->streams, id);
   } else {
      stream = snw_stream_find(&session->streams, session->audio_id);
   }

   if ( stream == NULL )
      return;

   ice_agent_get_local_credentials(session->agent, stream->stream_id, &ufrag, &password);
   memset(buffer, 0, 512);

   switch(stream->dtls_role) {
      case DTLS_ROLE_ACTPASS:
         dtls_role = "actpass";
         break;
      case DTLS_ROLE_SERVER:
         dtls_role = "passive";
         break;
      case DTLS_ROLE_CLIENT:
         dtls_role = "active";
         break;
      default:
         dtls_role = NULL;
         break;
   }

   snprintf(buffer, 512,
      "a=ice-ufrag:%s\r\n"
      "a=ice-pwd:%s\r\n"
      "a=ice-options:trickle\r\n"
      "a=fingerprint:sha-256 %s\r\n"
      "a=setup:%s\r\n"
      "a=connection:new\r\n",
      ufrag, password,
      srtp_get_local_fingerprint(),
      dtls_role);
   strncat(sdp, buffer, ICE_BUFSIZE);

   if (ufrag != NULL) free(ufrag);
   if (password != NULL) free(password);

   return;
}

void ice_sdp_copy_attributes(snw_ice_session_t *session, sdp_media_t *m, char *sdp) {
   char buffer[512];

   if (m && m->m_attributes) {
      sdp_attribute_t *a = m->m_attributes;
      while (a) {
         if (a->a_value == NULL) {
            snprintf(buffer, 512, "a=%s\r\n", a->a_name);
            strncat(sdp, buffer, ICE_BUFSIZE);
         } else {
            snprintf(buffer, 512, "a=%s:%s\r\n", a->a_name, a->a_value);
            strncat(sdp, buffer, ICE_BUFSIZE);
         }
         a = a->a_next;
      }
   }

   return;
}

void ice_sdp_add_single_ssrc(snw_ice_session_t *session, sdp_media_t *m, int video, char *sdp) {
   snw_ice_stream_t *stream = NULL;
   char buffer[512];

   if ( m == NULL )
      return;

   if ( video ) {
      uint32_t id = session->video_id;

      ICE_DEBUG2("add credentials, id=%u, bundle=%u",id,IS_FLAG(session, WEBRTC_BUNDLE));

      if (id == 0 && IS_FLAG(session, WEBRTC_BUNDLE))
          id = session->audio_id > 0 ? session->audio_id : session->video_id;

      stream = snw_stream_find(&session->streams, id);
   } else {
      stream = snw_stream_find(&session->streams, session->audio_id);
   }

   if ( stream == NULL )
      return;


   ICE_DEBUG2("add single ssrc");
   if (m->m_type == sdp_media_audio && m->m_mode != sdp_inactive && m->m_mode != sdp_recvonly) {
      snprintf(buffer, 512,
         "a=ssrc:%u cname:peercallaudio\r\n"
         "a=ssrc:%u msid:peercall peercalla0\r\n"
         "a=ssrc:%u mslabel:peercall\r\n"
         "a=ssrc:%u label:peercalla0\r\n",
         stream->audio_ssrc, stream->audio_ssrc, stream->audio_ssrc, stream->audio_ssrc);
      strncat(sdp, buffer, ICE_BUFSIZE);
   } else if (m->m_type == sdp_media_video && m->m_mode != sdp_inactive && m->m_mode != sdp_recvonly) {
      snprintf(buffer, 512,
         "a=ssrc:%u cname:peercallvideo\r\n"
         "a=ssrc:%u msid:peercall peercallv0\r\n"
         "a=ssrc:%u mslabel:peercall\r\n"
         "a=ssrc:%u label:peercallv0\r\n",
         stream->video_ssrc, stream->video_ssrc, stream->video_ssrc, stream->video_ssrc);
      strncat(sdp, buffer, ICE_BUFSIZE);
   }

   return;
}

void ice_sdp_add_candidates(snw_ice_session_t *session, sdp_media_t *m, int video, char *sdp) {
   snw_ice_stream_t *stream = NULL;

   if ( m == NULL )
      return;

   if ( video ) {
      uint32_t id = session->video_id;
      if (id == 0 && IS_FLAG(session, WEBRTC_BUNDLE))
          id = session->audio_id > 0 ? session->audio_id : session->video_id;
      stream = snw_stream_find(&session->streams, id);
   } else {
      stream = snw_stream_find(&session->streams, session->audio_id);
   }

   if ( stream == NULL )
      return;

   //FIXME: uncomment
   /*ice_generate_candidate_attribute(session, sdp, stream->stream_id, 1);
   if(!SET_FLAG(session, WEBRTC_RTCPMUX) && m->m_type != sdp_media_application)
      ice_generate_candidate_attribute(session, sdp, stream->stream_id, 2);*/

   return;
}

void ice_sdp_send_candidates(snw_ice_session_t *session, int video) {
   snw_ice_stream_t *stream = NULL;

   if ( video ) {
      uint32_t id = session->video_id;
      if (id == 0 && IS_FLAG(session, WEBRTC_BUNDLE))
          id = session->audio_id > 0 ? session->audio_id : session->video_id;
      stream = snw_stream_find(&session->streams, id);
   } else {
      stream = snw_stream_find(&session->streams, session->audio_id);
   }

   if ( stream == NULL )
      return;

   //FIXME: uncomment
   /*ice_send_local_candidate(session, video, stream->stream_id, 1);
   if(!SET_FLAG(session, WEBRTC_RTCPMUX))
      ice_send_local_candidate(session, video, stream->stream_id, 2);*/

   return;
}


void ice_sdp_add_mline(snw_ice_session_t *session, sdp_media_t *m, int inactive, int video, char* sdp) {
   char buffer[512];
   int ipv6 = 0; //ipv6 not support now

   if (inactive) {
      snprintf(buffer, 512, "m=%s 0 %s 0\r\n", video ? "video" : "audio", RTP_PROFILE);
      strncat(sdp, buffer, ICE_BUFSIZE);
      snprintf(buffer, 512, "c=IN %s 0.0.0.0\r\n", ipv6 ? "IP6" : "IP4");
      strncat(sdp, buffer, ICE_BUFSIZE);
      strncat(sdp, "a=inactive\r\n", ICE_BUFSIZE);
   } 

   snprintf(buffer, 512, "m=%s 1 %s", video ? "video" : "audio", RTP_PROFILE);
   strncat(sdp, buffer, ICE_BUFSIZE);

   /* Add media format*/
   if (!m->m_rtpmaps) {
      if (!m->m_format) {
         //add defaul no_format
         snprintf(buffer, 512, " %s", NO_FORMAT);
         strncat(sdp, buffer, ICE_BUFSIZE);
      } else {
         sdp_list_t *fmt = m->m_format;
         while(fmt) {
            snprintf(buffer, 512, " %s", fmt->l_text);
            strncat(sdp, buffer, ICE_BUFSIZE);
            fmt = fmt->l_next;
         }
      }
   } else {
      sdp_rtpmap_t *r = m->m_rtpmaps;
      while(r) {
         ICE_DEBUG2("rtp format, rm_pt=%d, sdp=%s",r->rm_pt,sdp);
         snprintf(buffer, 512, " %d", r->rm_pt);
         strncat(sdp, buffer, ICE_BUFSIZE);
         r = r->rm_next;
      }
   }
   strncat(sdp, "\r\n", ICE_BUFSIZE);

   /* Media connection c= */
   snprintf(buffer, 512, "c=IN %s 0.0.0.0\r\n", ipv6 ? "IP6" : "IP4");
   strncat(sdp, buffer, ICE_BUFSIZE);

   /* a=mid:(audio|video) */
   switch (m->m_type) {
      case sdp_media_audio:
         snprintf(buffer, 512, "a=mid:%s\r\n", session->audio_mid ? session->audio_mid : "audio");
         break;
      case sdp_media_video:
         snprintf(buffer, 512, "a=mid:%s\r\n", session->video_mid ? session->video_mid : "video");
         break;
      default:
         break;
   }
   strncat(sdp, buffer, ICE_BUFSIZE);
   
   /* ICE rtcpmux and related stuff */
   ice_sdp_add_media_application(session,m,sdp);
   
   /* ICE ufrag and pwd, and related stuff */
   ice_sdp_add_credentials(session,m,video,sdp);

   /* copy attributes */
   ice_sdp_copy_attributes(session,m,sdp);

   /* add single ssrc, not support multi-ssrc by now */
   ice_sdp_add_single_ssrc(session,m,video,sdp);

   /* add candidates */
   //ice_sdp_add_candidates(session,m,video,sdp);

   return;
}

char *ice_sdp_merge(snw_ice_session_t *session, const char *sdpstr) {
   char wms[ICE_BUFSIZE];
   sdp_session_t *orig_sdp = NULL;
   sdp_parser_t *parser = NULL;
   char *sdp = NULL;

   if (session == NULL || sdpstr == NULL)
      return NULL;

   memset(wms, 0, ICE_BUFSIZE);

   parser = sdp_parse(g_home, sdpstr, strlen(sdpstr), 0);
   if (!(orig_sdp = sdp_session(parser))) {
      ICE_ERROR2("failed to parse sdp, err=%s", sdp_parsing_error(parser));
      sdp_parser_free(parser);
      return NULL;
   }

   sdp = (char*)malloc(ICE_BUFSIZE);
   if(sdp == NULL) {
      ICE_ERROR2("Memory error!");
      sdp_parser_free(parser);
      return NULL;
   }
   sdp[0] = '\0';

   ice_sdp_add_global_attrs(session,orig_sdp,sdpstr,sdp);
   if (orig_sdp->sdp_media) {
      int audio = 0, video = 0;
      sdp_media_t *m = orig_sdp->sdp_media;
      while (m) {
         if (m->m_type == sdp_media_audio && m->m_port > 0) {
            audio++;
            if(audio > 1 || !session->audio_id) {
               ICE_ERROR2("skipping audio, audio=%u, id=%u", audio, session->audio_id);
               ice_sdp_add_mline(session,m,1,0,sdp);
            } else {
               ice_sdp_add_mline(session,m,0,0,sdp);
            }
         } else if (m->m_type == sdp_media_video && m->m_port > 0) {
            video++;
            uint32_t id = session->video_id;
            if (id == 0 && IS_FLAG(session, WEBRTC_BUNDLE))
                id = session->audio_id > 0 ? session->audio_id : session->video_id;

            if (video > 1 || !id) {
               ICE_ERROR2("skipping video line, video=%u, id=%u", video, id);
               ice_sdp_add_mline(session,m,1,1,sdp);
            } else {
               ice_sdp_add_mline(session,m,0,1,sdp);
            }
         } 
         m = m->m_next;
      }
   }

   sdp_parser_free(parser);
   ICE_DEBUG2("Merged, old_len=%u, new_len=%u, sdp=%s", 
         strlen(sdpstr), strlen(sdp),sdp);

   return sdp;
}

void ice_try_start_component(snw_ice_session_t *session, snw_ice_stream_t *stream, ice_component_t *component, candidate_t *candidate) {
   candidate_t candidates;
   candidate_t *c = NULL;
   int added = 0;

   if (!session || !stream || !component || !candidate)
      return;

   ICE_DEBUG2("add candidate, sid=%u, cid=%u, flag=%u, started=%u", 
         stream->stream_id, component->component_id,
         IS_FLAG(session, WEBRTC_START), component->is_started);

   list_add(&candidate->list,&component->candidates.list);
   if (!IS_FLAG(session, WEBRTC_START)) {
      SET_FLAG(session, WEBRTC_START);
   }

   if (!component->is_started) {
      //FIXME: uncomment
      //ice_setup_remote_candidates(session, component->stream_id, component->component_id);
   } else {
      c = candidate_copy(candidate);
      memset(&candidates,0,sizeof(candidate_t));
      INIT_LIST_HEAD(&candidates.list);
      list_add(&c->list,&candidates.list);
      added = ice_agent_set_remote_candidates(session->agent,stream->stream_id,
                                              component->component_id,&candidates); 
      if ( added < 1) {
         ICE_ERROR2("failed to add candidate, added=%u",added);
      } else {
         ICE_DEBUG2("candidate added, added=%u",added);
      }
      /* clean resources */
      INIT_LIST_HEAD(&candidates.list);
      candidate_free(c);
   }

   return;
}

candidate_t*
ice_remote_candidate_new(char *type, char *transport) {
   candidate_t* c = NULL;

   if(strcasecmp(transport, "udp")) {
      ICE_ERROR2("skipping unsupported transport, s=%s", transport);
      return NULL;
   }

   if(!strcasecmp(type, "host")) {
      c = candidate_new(ICE_CANDIDATE_TYPE_HOST);
   } else if (!strcasecmp(type, "srflx")) {
      c = candidate_new(ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE);
   } else if(!strcasecmp(type, "prflx")) {
      c = candidate_new(ICE_CANDIDATE_TYPE_PEER_REFLEXIVE);
   } else if(!strcasecmp(type, "relay")) {
      //c = candidate_new(ICE_CANDIDATE_TYPE_RELAYED);
      ICE_DEBUG2("relay candidate not supported, type:%s", type);
   } else {
      ICE_DEBUG2("Unknown remote candidate, type:%s", type);
   }

   return c;
}

int ice_sdp_handle_candidate(snw_ice_stream_t *stream, const char *candidate) {
   snw_ice_session_t *session = NULL;
   ice_component_t *component = NULL;
   candidate_t *c = NULL;
   char foundation[16], transport[4], type[6]; 
   char ip[32], relip[32];
   uint32_t component_id, priority, port, relport;
   int ret;

   if (stream == NULL || candidate == NULL)
      return -1;

   session = stream->session;
   if (session == NULL)
      return -2;

   if (strstr(candidate, "candidate:") == candidate) {
      candidate += strlen("candidate:");
   }

   /* format: foundation component tranpsort priority ip port type ??? ??? ??? ??? */
   ret = sscanf(candidate, "%15s %30u %3s %30u %31s %30u typ %5s %*s %31s %*s %30u",
                           foundation, &component_id, transport, &priority,
                           ip, &port, type, relip, &relport);

   ICE_DEBUG2("parsing result, ret=%u, cid:%d sid:%d, type:%s, transport=%s, refaddr=%s:%d, addr=%s:%d",
         ret, component_id, stream->stream_id, type, transport, relip, relport, ip, port);

   if (ret >= 7) {
      component = snw_component_find(&stream->components, component_id);
      if (component == NULL) {
         ICE_ERROR2("component not found, cid=%u, sid=%u", component_id, stream->stream_id);
         return -3;
      } 

      c = ice_remote_candidate_new(type,transport);
      if (c != NULL) {
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

         ice_try_start_component(session,stream,component,c);
      }
   } else {
      ICE_ERROR2("failed to parse candidate, ret=%d, s=%s", ret, candidate);
      return ret;
   }
   return 0;
}

int sdp_stream_update_ssrc(snw_ice_stream_t *stream, const char *ssrc_attr, int video) {
   int64_t ssrc;

   if (stream == NULL || ssrc_attr == NULL)
      return -1;

   ssrc = atoll(ssrc_attr);
   if (ssrc == 0)
      return -2;

   if (video) {
      if ( stream->video_ssrc_peer == 0 ) {
         stream->video_ssrc_peer = ssrc;
         ICE_DEBUG2("peer video ssrc, ssrc=%u", stream->video_ssrc_peer);
      } else {
         ICE_ERROR2("video ssrc updated, ssrc=%u, new_ssrc=%u", 
               stream->video_ssrc_peer,ssrc);
      }
   } else {
      if(stream->audio_ssrc_peer == 0) {
         stream->audio_ssrc_peer = ssrc;
         ICE_DEBUG2("peer audio ssrc, ssrc=%u", stream->audio_ssrc_peer);
      } else {
         ICE_ERROR2("audio ssrc update, ssrc=%u, new_ssrc=%u", 
               stream->audio_ssrc_peer,ssrc);
      }
   }

   return 0;
}

int
ice_sdp_get_local_credentials(snw_ice_session_t *session, snw_ice_stream_t *stream, sdp_media_t *m) {
   sdp_attribute_t *a;
   const char *ruser = NULL, *rpass = NULL, *rhashing = NULL, *rfingerprint = NULL;
   
   if ( stream == NULL || m == NULL )
      return -1;

   a = m->m_attributes;
   while(a) {
      if(a->a_name) {
         if(!strcasecmp(a->a_name, "mid")) {
            if(m->m_type == sdp_media_audio && m->m_port > 0) {
               ICE_DEBUG2("Audio mid: %s", a->a_value);
               session->audio_mid = strdup(a->a_value);
            } else if(m->m_type == sdp_media_video && m->m_port > 0) {
               ICE_DEBUG2("Video mid: %s", a->a_value);
               session->video_mid = strdup(a->a_value);
            } else if(m->m_type == sdp_media_application) {
               ICE_ERROR2("data channel not supported, mid=%s", a->a_value);
            }
         } else if(!strcasecmp(a->a_name, "fingerprint")) {
            ICE_DEBUG2("Fingerprint (local) : %s", a->a_value);
            if(strcasestr(a->a_value, "sha-256 ") == a->a_value) {
               rhashing = "sha-256";
               rfingerprint = a->a_value + strlen("sha-256 ");
            } else if(strcasestr(a->a_value, "sha-1 ") == a->a_value) {
               rhashing = "sha-1";
               rfingerprint = a->a_value + strlen("sha-1 ");
            } else {
               //FIXME
            }
         } else if(!strcasecmp(a->a_name, "setup")) {
            ICE_DEBUG2("DTLS setup (local):  %s", a->a_value);
            if(!strcasecmp(a->a_value, "actpass") || !strcasecmp(a->a_value, "passive"))
               stream->dtls_role = DTLS_ROLE_CLIENT;
            else if(!strcasecmp(a->a_value, "active"))
               stream->dtls_role = DTLS_ROLE_SERVER;
         } else if(!strcasecmp(a->a_name, "ice-ufrag")) {
            ICE_DEBUG2("ICE ufrag (local):   %s", a->a_value);
            ruser = a->a_value;
         } else if(!strcasecmp(a->a_name, "ice-pwd")) {
            ICE_DEBUG2("ICE pwd (local):     %s", a->a_value);
            rpass = a->a_value;
         }
      }
      a = a->a_next;
   }

   if (!ruser || !rpass || !rfingerprint || !rhashing) {
      return -2;
   }

   memcpy(stream->rhashing,rhashing,strlen(rhashing));
   memcpy(stream->rfingerprint,rfingerprint,strlen(rfingerprint));
   memcpy(stream->ruser,ruser,strlen(ruser));
   memcpy(stream->rpass,rpass,strlen(rpass));

   ICE_DEBUG2("stream info, stream=%p",stream);
   ICE_DEBUG2("stream info, rhash=%s",stream->rhashing);
   ICE_DEBUG2("stream info, rfingerprint=%s, len=%u",
         stream->rfingerprint, strlen(stream->rfingerprint));
   ICE_DEBUG2("stream info, ruser=%s",stream->ruser);
   ICE_DEBUG2("stream info, rpass=%s",stream->rpass);

   return 0;
}

int ice_sdp_get_global_credentials(snw_ice_session_t *session, sdp_session_t *remote_sdp) {
   sdp_attribute_t *a = NULL;
   const char *ruser = NULL, *rpass = NULL, *rhashing = NULL, *rfingerprint = NULL;

   a = remote_sdp->sdp_attributes;
   while (a) {
      if (a->a_name) {
         if (!strcasecmp(a->a_name, "fingerprint")) {
            ICE_DEBUG2("global credentials, value=%s", a->a_value);
            if (strcasestr(a->a_value, "sha-256 ") == a->a_value) {
               rhashing = "sha-256";
               rfingerprint = a->a_value + strlen("sha-256 ");
            } else if (strcasestr(a->a_value, "sha-1 ") == a->a_value) {
               rhashing = "sha-1";
               rfingerprint = a->a_value + strlen("sha-1 ");
            } else {
               ICE_DEBUG2("unknown algorithm, s=%s",a->a_name);
            }    
         } else if(!strcasecmp(a->a_name, "ice-ufrag")) {
            ruser = a->a_value;
         } else if(!strcasecmp(a->a_name, "ice-pwd")) {
            rpass = a->a_value;
         }
      }
      a = a->a_next;
   }

   if (!ruser || !rpass || !rhashing || !rfingerprint) {
      ICE_ERROR2("global credentials not found");
      return -1;
   }

   memcpy(session->ruser,ruser,strlen(ruser));
   memcpy(session->rpass,rpass,strlen(rpass));
   memcpy(session->rhashing,rhashing,strlen(rhashing));
   memcpy(session->rfingerprint,rfingerprint,strlen(rfingerprint));

   ICE_DEBUG2("global credentials, ruser=%s, rpass=%s, rhashing=%s, rfingerprint=%s",
         session->ruser, session->rpass, session->rhashing, session->rfingerprint);

   return 0;
}

int ice_sdp_get_local_credentials(snw_ice_session_t *session, snw_ice_stream_t *stream, sdp_session_t *remote_sdp) {
   sdp_attribute_t *a = NULL;
   sdp_media_t *m = NULL;
   const char *ruser = NULL, *rpass = NULL, *rhashing = NULL, *rfingerprint = NULL;

   if (stream == NULL) 
      return -1;

   m = remote_sdp->sdp_media;
   a = m->m_attributes;
   while(a) {
      if(a->a_name) {
         if(!strcasecmp(a->a_name, "mid")) {
            if(m->m_type == sdp_media_audio && m->m_port > 0) {
               ICE_DEBUG2("Audio mid: %s", a->a_value);
               session->audio_mid = strdup(a->a_value);
            } else if(m->m_type == sdp_media_video && m->m_port > 0) {
               ICE_DEBUG2("Video mid: %s", a->a_value);
               session->video_mid = strdup(a->a_value);
            } else if(m->m_type == sdp_media_application) {
               //FIXME
            }
         } 
         else if(!strcasecmp(a->a_name, "fingerprint")) {
            if(strcasestr(a->a_value, "sha-256 ") == a->a_value) {
               rhashing = "sha-256";
               rfingerprint = a->a_value + strlen("sha-256 ");
            } else if(strcasestr(a->a_value, "sha-1 ") == a->a_value) {
               rhashing = "sha-1";
               rfingerprint = a->a_value + strlen("sha-1 ");
            } else {
               ICE_DEBUG2("unknown algorithm, a=%s",a->a_name);
            }
         } else if(!strcasecmp(a->a_name, "setup")) {
            if(!strcasecmp(a->a_value, "actpass") || !strcasecmp(a->a_value, "passive"))
               stream->dtls_role = DTLS_ROLE_CLIENT;
            else if(!strcasecmp(a->a_value, "active"))
               stream->dtls_role = DTLS_ROLE_SERVER;

         } else if(!strcasecmp(a->a_name, "ice-ufrag")) {
            ruser = a->a_value;
         } else if(!strcasecmp(a->a_name, "ice-pwd")) {
            rpass = a->a_value;
         }
      }
      a = a->a_next;
   }

   if (!ruser || !rpass || !rfingerprint || !rhashing) {
      return -2;
   }
   memcpy(stream->rhashing,rhashing,strlen(rhashing));
   memcpy(stream->rfingerprint,rfingerprint,strlen(rfingerprint));
   memcpy(stream->ruser,ruser,strlen(ruser));
   memcpy(stream->rpass,rpass,strlen(rpass));

   ICE_DEBUG2("stream info, rhashing=%s",stream->rhashing);
   ICE_DEBUG2("stream info, rfingerprint=%s, len=%u",stream->rfingerprint, strlen(stream->rfingerprint));
   ICE_DEBUG2("stream info, ruser=%s",stream->ruser);
   ICE_DEBUG2("stream info, rpass=%s",stream->rpass);

   return 0;
}

int ice_sdp_get_candidate(snw_ice_session_t *session, snw_ice_stream_t *stream, sdp_media_t *m) {
   sdp_attribute_t *a = NULL;

   a = m->m_attributes;
   while (a) {
      if (a->a_name) {
         if (!strcasecmp(a->a_name, "candidate")) {
            int ret = ice_sdp_handle_candidate(stream, (const char *)a->a_value);
            if (ret != 0) {
               ICE_DEBUG2("failed to parse candidate, ret=%d", ret);
            }
         }

         if (!strcasecmp(a->a_name, "ssrc")) {
            int video = m->m_type == sdp_media_video;
            int ret = sdp_stream_update_ssrc(stream, (const char *)a->a_value, video);
            if (ret != 0) {
               ICE_DEBUG2("failed to update SSRC, ret=%d", ret);
            }
         }
      }
      a = a->a_next;
   }

   return 0;
}

int ice_sdp_handle_answer(snw_ice_session_t *session, sdp_parser_t *parser) {
   snw_ice_stream_t *stream = NULL;
   sdp_session_t *remote_sdp = NULL;
   sdp_media_t *m = NULL;
   int audio = 0, video = 0; 

   if (!session || !parser)
      return -1;

   remote_sdp = sdp_session(parser);
   if (!remote_sdp)
      return -1;

   ice_sdp_get_global_credentials(session,remote_sdp);

   m = remote_sdp->sdp_media;
   while (m) {
      if (m->m_type == sdp_media_audio) {
         if (session->rtp_profile == NULL && m->m_proto_name != NULL)
            session->rtp_profile = strdup(m->m_proto_name);

         if (m->m_port > 0) {
            audio++;
            if(audio > 1) {
               m = m->m_next;
               continue;
            }
            stream = snw_stream_find(&session->streams, session->audio_id);
         } else {
            CLEAR_FLAG(session, WEBRTC_AUDIO);
         }
      } else if(m->m_type == sdp_media_video) {
         if (session->rtp_profile == NULL && m->m_proto_name != NULL)
            session->rtp_profile = strdup(m->m_proto_name);
         
         if (m->m_port > 0) {
            video++;
            if (video > 1) {
               m = m->m_next;
               continue;
            }
            if(!IS_FLAG(session, WEBRTC_BUNDLE)) {
               stream = snw_stream_find(&session->streams, session->video_id);
            } else {
               uint32_t id = session->audio_id > 0 ? session->audio_id : session->video_id;
               stream = snw_stream_find(&session->streams, id);
            }
         } else {
            CLEAR_FLAG(session, WEBRTC_VIDEO);
         }
      } else if(m->m_type == sdp_media_application) {
         /* TODO: support data channel */

      } else {
         ICE_DEBUG2("Skipping disabled/unsupported media line");
         m = m->m_next;
         continue;
      }
      
      ice_sdp_get_local_credentials(session,stream,m);
      ice_sdp_get_candidate(session,stream,m);
      m = m->m_next;
   }

   return 0;
}


