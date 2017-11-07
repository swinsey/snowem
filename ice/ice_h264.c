#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "ice_h264.h"
#include "ice_session.h"
#include "log.h"
#include "rtp.h"
#include "srs_librtmp.h"
#include "types.h"

//test_aac
int
read_audio_frame(char* data, int size, char** pp, char** frame, int* frame_size) 
{
    char* p = *pp;
    
    // @remark, for this demo, to publish aac raw file to SRS,
    // we search the adts frame from the buffer which cached the aac data.
    // please get aac adts raw data from device, it always a encoded frame.
    if (!srs_aac_is_adts(p, size - (p - data))) {
        //srs_human_trace("aac adts raw data invalid.");
        return -1;
    }
    
    // @see srs_audio_write_raw_frame
    // each frame prefixed aac adts header, '1111 1111 1111'B, that is 0xFFF., 
    // for instance, frame = FF F1 5C 80 13 A0 FC 00 D0 33 83 E8 5B
    *frame = p;
    // skip some data. 
    // @remark, user donot need to do this.
    p += srs_aac_adts_frame_size(p, size - (p - data));
    
    *pp = p;
    *frame_size = p - *frame;
    if (*frame_size <= 0) {
        //srs_human_trace("aac adts raw data invalid.");
        return -1;
    }
    
    return 0;
}


int
ice_aac_rtmp_send_audio_frame(snw_ice_session *session) {
   snw_log_t *log;
   char sound_format = 10;
   // 0 = Linear PCM, platform endian
   // 1 = ADPCM
   // 2 = MP3
   // 7 = G.711 A-law logarithmic PCM
   // 8 = G.711 mu-law logarithmic PCM
   // 10 = AAC
   // 11 = Speex
   char sound_rate = 2; // 2 = 22 kHz
   char sound_size = 1; // 1 = 16-bit samples
   char sound_type = 1; // 1 = Stereo sound
   int ret = 0;

   if (!session || !session->ice_ctx) {
      return -1;
   }
   log = session->ice_ctx->log;
  
   while (session->audio_ts < session->pts) { 
      if (session->audio_pos < session->audio_raw + session->file_size) {
        char* data = NULL;
        int size = 0;
        if (read_audio_frame(session->audio_raw, session->file_size, 
               &session->audio_pos, &data, &size) < 0) {
            ERROR(log, "read a frame from file buffer failed.");
            return -2;
        }
        
        session->audio_ts += session->delta_ts;
        
        if ((ret = srs_audio_write_raw_frame(session->rtmp, 
            sound_format, sound_rate, sound_size, sound_type,
            data, size, session->audio_ts)) != 0
        ) {
            ERROR(log, "send audio raw data failed. ret=%d", ret);
            return -3;
        }
        
        DEBUG(log, "sent packet: type=%s, time=%d, size=%d, codec=%d, rate=%d, sample=%d, channel=%d", 
            srs_human_flv_tag_type2string(SRS_RTMP_TYPE_AUDIO), session->audio_ts, size, 
            sound_format, sound_rate, sound_size, sound_type);
        
      }
   }
 
   if (session->audio_pos >= session->audio_raw + session->file_size) {
      session->audio_pos = session->audio_raw;
   }

   return 0;
}
int
ice_aac_rtmp_init(snw_ice_session *session, const char* raw_file) {
   snw_log_t *log;
   int raw_fd = -1;
   off_t file_size = 0;
   int ret;

   if (!session || !session->ice_ctx || !raw_file) {
      return -1;
   }
   log = session->ice_ctx->log;
 
   raw_fd = open(raw_file, O_RDONLY);
   if (raw_fd < 0) {
      ERROR(log, "open audio raw file %s failed.", raw_file);
      return -2;
   }
    
   file_size = lseek(raw_fd, 0, SEEK_END);
   if (file_size <= 0) {
      ERROR(log, "audio raw file %s empty.", raw_file);
      close(raw_fd);
      return -3;
   }
   DEBUG(log,"read entirely audio raw file, size=%dKB", (int)(file_size / 1024));
    
   session->audio_raw = (char*)malloc(file_size);
   if (!session->audio_raw) {
      ERROR(log, "alloc raw buffer failed for file %s.", raw_file);
      close(raw_fd);
      return -4;
   }
   session->file_size = file_size;
   session->audio_pos = session->audio_raw;
   session->delta_ts = 45; //ms
   session->audio_ts = 45; //ms
    
   lseek(raw_fd, 0, SEEK_SET);
   ssize_t nb_read = 0;
   if ((nb_read = read(raw_fd, session->audio_raw, session->file_size)) != session->file_size) {
      ERROR(log, "buffer %s failed, expect=%dKB, actual=%dKB.", 
            raw_file, (int)(file_size / 1024), (int)(nb_read / 1024));
      close(raw_fd);
      return -5;
   }

   close(raw_fd); 
   return ret;
}

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
   
   ice_aac_rtmp_send_audio_frame(session);
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
      //ret = ice_h264_rtmp_init(session,"rtmp://live-api.facebook.com:80/rtmp/2046979208865329?ds=1&a=ATiX-nwt4dhs30Ue");
      if (ret < 0) {
         ERROR(log, "failed to init rtmp, ret=%d", ret);
         return -1;
      }

      ret = ice_aac_rtmp_init(session,"sample/audio.raw.aac");
      if (ret < 0) return -1;

      session->rtmp_inited = 1;
      session->first_video_ts = ntohl(hdr->ts);
      DEBUG(log,"rtmp inited, first_video_ts=%llu", session->first_video_ts);
   }
   session->current_ts = ntohl(hdr->ts);
   pts = (session->current_ts - session->first_video_ts)/90;
   dts = pts;
   session->pts = pts;

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


