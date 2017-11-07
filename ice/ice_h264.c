
#include "ice_h264.h"
#include "ice_session.h"
#include "log.h"
#include "rtp.h"
#include "srs_librtmp.h"
#include "types.h"

int
ice_h264_rtmp_init(snw_ice_session *session, const char* rtmp_url) {
   snw_log_t *log;
   int ret;

   if (!session || !session->ice_ctx || !rtmp_url) {
      return -1;
   }
   log = session->ice_ctx->log;
 
    // connect rtmp context
   srs_rtmp_t rtmp = srs_rtmp_create(rtmp_url);
    
   if (srs_rtmp_handshake(rtmp) != 0) {
      DEBUG(log,"simple handshake failed.");
      goto rtmp_destroy;
   }
   DEBUG(log,"simple handshake success");
    
   if (srs_rtmp_connect_app(rtmp) != 0) {
      DEBUG(log,"connect vhost/app failed.");
      goto rtmp_destroy;
   }
   DEBUG(log,"connect vhost/app success");
    
   if (srs_rtmp_publish_stream(rtmp) != 0) {
      DEBUG(log,"publish stream failed.");
      goto rtmp_destroy;
   }
   DEBUG(log,"publish stream success");

   session->rtmp = rtmp;
   return 0;

rtmp_destroy:    
    srs_rtmp_destroy(rtmp);
    return -1;
}

//test_h264
int
ice_h264_rtmp_handler(snw_ice_session *session, int is_end_frame, int dts, int pts, char *buf, int buflen) {
   static char data[MAX_BUFFER_SIZE];
   static char sync_bytes[4] = { 0x00, 0x00, 0x00, 0x01};
   snw_log_t *log;
   int ret;

   if (!session || !session->ice_ctx || !buf || buflen <= 0) {
      return -1;
   }
   log = session->ice_ctx->log;

   memcpy(data,sync_bytes,4); 
   memcpy(data+4,buf,buflen);

   // send out the h264 packet over RTMP
   DEBUG(log, "send h264 frame, len=%u, dts=%u", buflen+4, dts);
   ret = srs_h264_write_raw_frames(session->rtmp, data, buflen+4, dts, pts);
   if (ret != 0) {
      if (srs_h264_is_dvbsp_error(ret)) {
         DEBUG(log, "rtmp: ignore drop video error, code=%d", ret);
      } else if (srs_h264_is_duplicated_sps_error(ret)) {
         DEBUG(log,"rtmp: ignore duplicated sps, code=%d", ret);
      } else if (srs_h264_is_duplicated_pps_error(ret)) {
         DEBUG(log,"rtmp: ignore duplicated pps, code=%d", ret);
      } else {
         ERROR(log,"rtmp: send h264 raw data failed. ret=%d", ret);
         return -2;
      }
   }

   /*{
      static FILE *fp = 0;
      if (fp == 0) {
         fp = fopen("h264.raw","w");
      }
      fwrite(data,buflen+4,1,fp);
   }*/

   return 0;
}

int
ice_h264_process_nal_unit(snw_ice_session_t *session, int is_end_frame, int dts, 
       int pts, char *buf, int buflen) {
   snw_log_t *log;
   uint8_t nal_unit_type;
   int len;

   if (!session || !session->ice_ctx || !buf || buflen <= 0) {
      return -1;
   }
   log = session->ice_ctx->log;

   //HEXDUMP(log,buf,3,"h264");
   nal_unit_type = *buf & 0x1f;
   // 5bits, 7.3.1 NAL unit syntax,
   // H.264-AVC-ISO_IEC_14496-10.pdf, page 44.
   //  7: SPS, 8: PPS, 5: I Frame, 1: P Frame, 9: AUD, 6: SEI
   DEBUG(log, "nal unit info, nal_unit_type=%u, buflen=%d, dts=%u, pts=%u", 
         nal_unit_type, buflen, dts, pts);
   
   ice_h264_rtmp_handler(session,is_end_frame,dts,pts,buf,buflen); 
   return 0;
}

int
ice_h264_process_stapa_unit(snw_ice_session_t *session, char *buf, int buflen) {
   snw_log_t *log;
   char *p;
   uint8_t nal_unit_type, fbit;
   int len;

   if (!session || !session->ice_ctx || !buf || buflen <= 0) {
      return -1;
   }
   log = session->ice_ctx->log;

   p = buf;
   len = buflen;
   nal_unit_type = *p & 0x1f;
   fbit = *p & 0x80;
   p++;
   len--;
   
   DEBUG(log, "stapa unit info, buflen=%d, len=%d", buflen, len);
   while(len > 2) {
      uint16_t nal_size = p[0] << 8 | p[1];

      p += nal_size + 2;
      len -= nal_size + 2;
      DEBUG(log, "stapa unit info, nal_size=%u, len=%d", nal_size, len);
   }
   
   return 0;
}

int
ice_h264_handler(snw_ice_session_t *session, char *buf, int buflen) {
   snw_log_t *log;
   rtp_hdr_t *hdr;
   char *p;
   int hdrlen = 0;
   int extlen = 0;
   int ret = 0;
   int dts = 0;
   int pts = 0;

   if (!session || !session->ice_ctx || !buf || buflen <= 0) {
      return -1;
   }
   log = session->ice_ctx->log;
   
   //parsing rtp header
   hdr = (rtp_hdr_t*)buf;
   hdrlen = MIN_RTP_HEADER_SIZE + 4*hdr->cc;
   if (hdr->x) {
      uint16_t id, len;
      p = buf + hdrlen; 
      id = ntohs(*((uint16_t*)p));
      len = ntohs(*((uint16_t*)(p+2)));
      extlen = 4 + 4*len;
      hdrlen += extlen;
   }

   if (!session->rtmp_inited) {
      ret = ice_h264_rtmp_init(session,"rtmp://49.213.76.92:1935/live/livestream");
      if (ret < 0) return -1;
      session->rtmp_inited = 1;
      session->first_video_ts = ntohl(hdr->ts);
      DEBUG(log,"rtmp inited, first_video_ts=%llu", session->first_video_ts);
   }
   session->current_ts = ntohl(hdr->ts);
   pts = (session->current_ts - session->first_video_ts)/90;
   dts = pts;

   DEBUG(log, "rtp info, seq=%u, start_ts=%llu, cur_ts=%llu, hdrlen=%u, extlen=%u, v=%u, x=%u, cc=%u, pt=%u, m=%u", 
         htons(hdr->seq), session->first_video_ts, session->current_ts, hdrlen, extlen, hdr->v, hdr->x, hdr->cc, hdr->pt, hdr->m);

   //parsing h264 header
   p = buf + hdrlen;
   {
      uint8_t nal_unit_type = *p & 0x1f;

      //DEBUG(log,"h264 header info, nal_unit_type=%u", nal_unit_type);
      switch(nal_unit_type) {
         case H264_PT_RSV0:
         case H264_PT_RSV1:
         case H264_PT_RSV2:
            DEBUG(log,"reserved nal unit type, nal_unit_type=%u", nal_unit_type);
            break;
         case H264_PT_STAPA:
            DEBUG(log,"stapa nal unit type, nal_unit_type=%u", nal_unit_type);
            ice_h264_process_stapa_unit(session,p,buflen - hdrlen);
            break;
         case H264_PT_STAPB:
            DEBUG(log,"stapb nal unit type, nal_unit_type=%u", nal_unit_type);
            break;
         case H264_PT_MTAP16:
            DEBUG(log,"mtap16 nal unit type, nal_unit_type=%u", nal_unit_type);
            break;
         case H264_PT_MTAP24:
            DEBUG(log,"mtap24 nal unit type, nal_unit_type=%u", nal_unit_type);
            break;
         case H264_PT_FUA:
            DEBUG(log,"fua nal unit type, nal_unit_type=%u", nal_unit_type);
            break;
         case H264_PT_FUB:
            DEBUG(log,"fub nal unit type, nal_unit_type=%u", nal_unit_type);
            break;

         default:
            DEBUG(log,"single nal unit type, nal_unit_type=%u", nal_unit_type);
            ice_h264_process_nal_unit(session,hdr->m,dts,pts,p,buflen - hdrlen);
            break;
      }
   }
   return 0;
}


