#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "core/log.h"
#include "rtp/rtp_h264.h"
#include "rtp/rtp_rtmp.h"

#define USE_MODULE_H264
snw_rtp_module_t *g_rtp_h264_modules[] = {
   #include "rtp_module_dec.h"
   0
};
#undef USE_MODULE_H264

int
snw_rtp_h264_init(void *c) {
   snw_ice_context_t *ctx = (snw_ice_context_t*)c;
   snw_log_t *log = 0;
   snw_rtp_module_t *prev = &g_rtp_h264_module;
   int i = 0;
   
   if (!ctx) return -1;
   log = ctx->log;
   
   if (MODULE_IS_FLAG(g_rtp_h264_module,M_FLAGS_INIT)) {
      WARN(log,"rtp h264 aready init");
      return -1;
   }

   DEBUG(log,"init rtp h264");
    
   for (i=0; ; i++) {
      snw_rtp_module_t *m = g_rtp_h264_modules[i];
      if (!m) break;

      DEBUG(log,"init module, name=%s",m->name);
      m->init(ctx);
   }

   MODULE_SET_FLAG(g_rtp_h264_module,M_FLAGS_INIT);

   return 0;
}

int
ice_h264_rtmp_init(snw_rtp_ctx_t *ctx, const char* rtmp_url) {
   snw_log_t *log;
   int ret;

   if (!ctx  || !rtmp_url) {
      return -1;
   }
   log = ctx->log;
 
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

   ctx->rtmp = rtmp;
   return 0;

rtmp_destroy:    
    srs_rtmp_destroy(rtmp);
    return -1;
}

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
ice_aac_rtmp_send_audio_frame(snw_rtp_ctx_t *ctx) {
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

   if (!ctx) {
      return -1;
   }
   log = ctx->log;
  
   while (ctx->audio_ts < ctx->pts) { 
      if (ctx->audio_pos < ctx->audio_raw + ctx->file_size) {
        char* data = NULL;
        int size = 0;
        if (read_audio_frame(ctx->audio_raw, ctx->file_size, 
               &ctx->audio_pos, &data, &size) < 0) {
            ERROR(log, "read a frame from file buffer failed.");
            return -2;
        }
        
        ctx->audio_ts += ctx->delta_ts;
        
        if ((ret = srs_audio_write_raw_frame(ctx->rtmp, 
            sound_format, sound_rate, sound_size, sound_type,
            data, size, ctx->audio_ts)) != 0
        ) {
            ERROR(log, "send audio raw data failed. ret=%d", ret);
            return -3;
        }
        
        DEBUG(log, "sent packet: type=%s, time=%d, size=%d, codec=%d, rate=%d, sample=%d, channel=%d", 
            srs_human_flv_tag_type2string(SRS_RTMP_TYPE_AUDIO), ctx->audio_ts, size, 
            sound_format, sound_rate, sound_size, sound_type);
        
      }
   }
 
   if (ctx->audio_pos >= ctx->audio_raw + ctx->file_size) {
      ctx->audio_pos = ctx->audio_raw;
   }

   return 0;
}

int
ice_h264_rtmp_handler(snw_rtp_ctx_t *ctx, int is_end_frame, 
      int dts, int pts, char *buf, int buflen) {
   static char data[MAX_BUFFER_SIZE];
   static char sync_bytes[4] = { 0x00, 0x00, 0x00, 0x01};
   snw_log_t *log;
   int ret;

   if (!ctx || !buf || buflen <= 0) {
      return -1;
   }
   log = ctx->log;

   memcpy(data,sync_bytes,4); 
   memcpy(data+4,buf,buflen);

   // send out the h264 packet over RTMP
   DEBUG(log, "send h264 frame, len=%u, dts=%u", buflen+4, dts);
   ret = srs_h264_write_raw_frames(ctx->rtmp, data, buflen+4, dts, pts);
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
   
   ice_aac_rtmp_send_audio_frame(ctx);
   //{
   //   static FILE *fp = 0;
   //   if (fp == 0) {
   //      fp = fopen("h264.raw","w");
   //   }
   //   fwrite(data,buflen+4,1,fp);
   //}

   return 0;
}


int
ice_h264_process_nal_unit(snw_rtp_ctx_t *ctx, int is_end_frame, int dts, 
       int pts, char *buf, int buflen) {
   snw_log_t *log;
   uint8_t nal_unit_type;
   int len;

   if (!ctx || !buf || buflen <= 0) {
      return -1;
   }
   log = ctx->log;

   //HEXDUMP(log,buf,3,"h264");
   nal_unit_type = *buf & 0x1f;
   // 5bits, 7.3.1 NAL unit syntax,
   // H.264-AVC-ISO_IEC_14496-10.pdf, page 44.
   //  7: SPS, 8: PPS, 5: I Frame, 1: P Frame, 9: AUD, 6: SEI
   //DEBUG(log, "nal unit info, nal_unit_type=%u, buflen=%d, dts=%u, pts=%u", 
   //      nal_unit_type, buflen, dts, pts);

   //FIXME: move code from ice_h264_rtmp_handler() here.   
   ice_h264_rtmp_handler(ctx,is_end_frame,dts,pts,buf,buflen); 
   return 0;
}


int
ice_h264_process_stapa_unit(snw_rtp_ctx_t *ctx, int is_end_frame, int dts, 
       int pts, char *buf, int buflen) {
   snw_log_t *log;
   char *p;
   uint8_t nal_unit_type, fbit;
   int nal_size;
   int len;

   if (!ctx || !buf || buflen <= 0) {
      return -1;
   }
   log = ctx->log;

   p = buf;
   len = buflen;
   nal_unit_type = *p & 0x1f;
   fbit = *p & 0x80;
   p++;
   len--;
   
   DEBUG(log, "stapa unit info, buflen=%d, len=%d", buflen, len);

   while(len > 2) {
      //FIXME: p[1] not working
      //nal_size = p[0] << 8 | p[1];
      
      //HEXDUMP(log,(char*)p,2,"stata");
      nal_size = ntohs(*((short*)p));
      DEBUG(log, "stapa unit info, nal_size=%u, len=%d, p0=%u, p1=%u", 
                 nal_size, len, *p, *(((char*)p)+1)); 
      //TODO: set stricter condition on nal_size
      if (nal_size == 0) {
         ERROR(log,"wrong nal_size, nal_size=%u", nal_size);
         return -1;
      }
      ice_h264_process_nal_unit(ctx,is_end_frame,dts,pts,p+2, nal_size);
      
      p += nal_size + 2;
      len -= nal_size + 2;
   }
   
   return 0;
}

int
ice_h264_process_fua_unit(snw_rtp_ctx_t *ctx, int is_end_frame, int dts, 
       int pts, char *buf, int buflen) {
   static char data[MAX_BUFFER_SIZE];
   static int len;
   snw_log_t *log;
   fua_indicator_t *indicator;
   fua_hdr_t *hdr;

   if (!ctx || !buf || buflen <= 0) {
      return -1;
   }
   log = ctx->log;


   //HEXDUMP(log,buf,2,"fua");
   indicator = (fua_indicator_t*)buf;
   hdr = (fua_hdr_t*)(buf+1);
  
   DEBUG(log, "fua indicator info, buflen=%u, f=%u, nir=%u, type=%u, size=%u", 
         buflen, indicator->f, indicator->nir, indicator->type, sizeof(fua_indicator_t));
   DEBUG(log, "fua hdr info, buflen=%u, s=%u, e=%u, r=%u, type=%u, size=%u", 
         buflen, hdr->s, hdr->e, hdr->r, hdr->type, sizeof(fua_hdr_t));
   
   if (hdr->s) {
      fua_indicator_t ind;
      ind.f = indicator->f;
      ind.nir = indicator->nir;
      ind.type = hdr->type;
      memcpy(data,&ind,sizeof(ind));
      len = sizeof(ind);
      //HEXDUMP(log,(char*)&ind,sizeof(ind),"fua");
   }

   memcpy(data+len, buf+2, buflen-2);
   len += buflen-2;
  
   if (hdr->e) {
      DEBUG(log, "complete fua unit, len=%u",len);
      ice_h264_process_nal_unit(ctx,is_end_frame,dts,pts,data,len);
   }

   return 0;
}

int
ice_aac_rtmp_init(snw_rtp_ctx_t *ctx, const char* raw_file) {
   snw_log_t *log;
   int raw_fd = -1;
   off_t file_size = 0;
   int ret;

   if (!ctx || !raw_file) {
      return -1;
   }
   log = ctx->log;
 
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
    
   ctx->audio_raw = (char*)malloc(file_size);
   if (!ctx->audio_raw) {
      ERROR(log, "alloc raw buffer failed for file %s.", raw_file);
      close(raw_fd);
      return -4;
   }
   ctx->file_size = file_size;
   ctx->audio_pos = ctx->audio_raw;
   ctx->delta_ts = 45; //ms
   ctx->audio_ts = 45; //ms
    
   lseek(raw_fd, 0, SEEK_SET);
   ssize_t nb_read = 0;
   if ((nb_read = read(raw_fd, ctx->audio_raw, ctx->file_size)) != ctx->file_size) {
      ERROR(log, "buffer %s failed, expect=%dKB, actual=%dKB.", 
            raw_file, (int)(file_size / 1024), (int)(nb_read / 1024));
      close(raw_fd);
      return -5;
   }

   close(raw_fd); 
   return ret;
}



int
snw_rtp_h264_handle_pkg(void *data, char *buf, int buflen) {
   snw_rtp_ctx_t *ctx = (snw_rtp_ctx_t*)data;
   snw_log_t *log;
   rtp_hdr_t *hdr;
   char *p;
   int hdrlen = 0;
   int extlen = 0;
   int ret = 0;
   int dts = 0;
   int pts = 0;

   if (!ctx || !buf || buflen <= 0) {
      return -1;
   }
   log = ctx->log;

   if (ctx->pkt_type != RTP_VIDEO)
      return 0;   

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

   if (!ctx->rtmp_inited) {
      ret = ice_h264_rtmp_init(ctx,"rtmp://49.213.76.92:1935/live/livestream");
      //ret = ice_h264_rtmp_init(ctx,"rtmp://live-api.facebook.com:80/rtmp/2048813932015190?ds=1&a=ATiH7SKrqDT6Z8eE");

      if (ret < 0) {
         ERROR(log, "failed to init rtmp, ret=%d", ret);
         return -1;
      }

      ret = ice_aac_rtmp_init(ctx,"sample/audio.raw.aac");
      if (ret < 0) return -1;

      ctx->rtmp_inited = 1;
      ctx->first_video_ts = ntohl(hdr->ts);
      DEBUG(log,"rtmp inited, first_video_ts=%llu", ctx->first_video_ts);
   }
   ctx->current_ts = ntohl(hdr->ts);
   pts = (ctx->current_ts - ctx->first_video_ts)/90;
   dts = pts;
   ctx->pts = pts;


   DEBUG(log, "rtp info, seq=%u, start_ts=%llu, cur_ts=%llu, hdrlen=%u, extlen=%u, v=%u, x=%u, cc=%u, pt=%u, m=%u", 
         htons(hdr->seq), ctx->first_video_ts, ctx->current_ts, hdrlen, extlen, hdr->v, hdr->x, hdr->cc, hdr->pt, hdr->m);
   
   //HEXDUMP(log,(char*)buf,buflen,"rtp");
   //parsing h264 header
   p = buf + hdrlen;
   {
      uint8_t nal_unit_type = *p & 0x1f;
      // 5bits, 7.3.1 NAL unit syntax,
      // H.264-AVC-ISO_IEC_14496-10.pdf, page 44.
      //  7: SPS, 8: PPS, 5: I Frame, 1: P Frame, 9: AUD, 6: SEI
      //DEBUG(log,"h264 header info, nal_unit_type=%u", nal_unit_type);

      switch(nal_unit_type) {
         case H264_PT_RSV0:
         case H264_PT_RSV1:
         case H264_PT_RSV2:
            DEBUG(log,"reserved nal unit type, nal_unit_type=%u", nal_unit_type);
            break;
         case H264_PT_STAPA:
            DEBUG(log,"stapa nal unit type, nal_unit_type=%u", nal_unit_type);
            ice_h264_process_stapa_unit(ctx,hdr->m,dts,pts,p,buflen - hdrlen);
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
            ice_h264_process_fua_unit(ctx,hdr->m,dts,pts,p,buflen - hdrlen);
            break;
         case H264_PT_FUB:
            DEBUG(log,"fub nal unit type, nal_unit_type=%u", nal_unit_type);
            break;

         default:
            DEBUG(log,"single nal unit type, nal_unit_type=%u", nal_unit_type);
            ice_h264_process_nal_unit(ctx,hdr->m,dts,pts,p,buflen - hdrlen);
            break;
      }
   }
   return 0;
}

int
snw_rtp_h264_fini() {
   return 0;
}

snw_rtp_module_t g_rtp_h264_module = { 
   "h264",
   0,/*ctx*/
   RTP_VIDEO,
   0,
   snw_rtp_h264_init, 
   snw_rtp_h264_handle_pkg, 
   snw_rtp_h264_fini,
   0 /*next*/
};


