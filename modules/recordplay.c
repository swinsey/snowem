#include "recordplay.h"
#include "log.h"
#include "rtp.h"
#include "record.h"
#include "ice.h"
#include <unistd.h>
#include "utils.h"


static volatile int initialized = 1, stopping = 0;

typedef struct janus_recordplay_frame_packet {
	uint16_t seq;	/* RTP Sequence number */
	uint64_t ts;	/* RTP Timestamp */
	int len;  	   /* Length of the data */
	long offset;	/* Offset of the data in the file */
	struct janus_recordplay_frame_packet *next;
	struct janus_recordplay_frame_packet *prev;
} janus_recordplay_frame_packet;
janus_recordplay_frame_packet *janus_recordplay_get_frames(const char *dir, const char *filename);

typedef struct janus_recordplay_recording {
	uint64_t id;			/* Recording unique ID */
	char *name;			/* Name of the recording */
	char *date;			/* Time of the recording */
	char *arc_file;		/* Audio file name */
	char *vrc_file;		/* Video file name */
	int64_t destroyed;	/* Lazy timestamp to mark recordings as destroyed */
} janus_recordplay_recording;

typedef struct janus_recordplay_session {
	ice_session_t *handle;
	bool active;
	bool recorder;		/* Whether this session is used to record or to replay a WebRTC session */
	bool firefox;	/* We send Firefox users a different kind of FIR */
	janus_recordplay_recording *recording;
	recorder_t *arc;	/* Audio recorder */
	recorder_t *vrc;	/* Video recorder */
	janus_recordplay_frame_packet *aframes;	/* Audio frames (for playout) */
	janus_recordplay_frame_packet *vframes;	/* Video frames (for playout) */
	unsigned int video_remb_startup;
	uint64_t video_remb_last;
	uint64_t video_bitrate;
	unsigned int video_keyframe_interval; /* keyframe request interval (ms) */
	uint64_t video_keyframe_request_last; /* timestamp of last keyframe request sent */
	int video_fir_seq;
	volatile int hangingup;
	int64_t destroyed;	/* Time at which this session was marked as destroyed */
} janus_recordplay_session;

void janus_ice_relay_rtp(ice_session_t *handle, int video, char *buf, int len) {
   if(!handle || buf == NULL || len < 1) 
      return;
   if((!video && !IS_FLAG(handle, WEBRTC_AUDIO))
         || (video && !IS_FLAG(handle, WEBRTC_VIDEO)))
      return;
   /* Queue this packet */
   rtp_packet_t *pkt = (rtp_packet_t *)malloc(sizeof(rtp_packet_t));
   pkt->data = (char*)malloc(len);
   memcpy(pkt->data, buf, len);
   pkt->length = len; 
   pkt->type = video ? RTP_PACKET_VIDEO : RTP_PACKET_AUDIO;
   pkt->control = 0;
   pkt->encrypted = 0;

   MODULE_DEBUG("relay rtp packets, type=%u, len-%u",pkt->type,pkt->length);
   //send_rtp_pkt(handle, pkt);//FIXME: uncomment
}


static void *janus_recordplay_playout_thread(void *data) {
	janus_recordplay_session *session = (janus_recordplay_session *)data;
	if(!session) {
		MODULE_ERROR("Invalid session, can't start playout thread");
		//g_thread_unref(g_thread_self());
		return NULL;
	}
	if(session->recorder) {
		MODULE_ERROR("This is a recorder, can't start playout thread");
		//g_thread_unref(g_thread_self());
		return NULL;
	}
	if(!session->aframes && !session->vframes) {
		MODULE_ERROR("No audio and no video frames, can't start playout thread");
		//g_thread_unref(g_thread_self());
		return NULL;
	}
	MODULE_DEBUG("Joining playout thread");
	/* Open the files */
	FILE *afile = NULL, *vfile = NULL;
   const char *recordings_path = "/home/tuyettt/record_video/";
   const char *arc_file = "0_1482292194_audio.mjr";
   const char *vrc_file = "0_1482292194_video.mjr";
	if(session->aframes) {
		char source[1024];
	   MODULE_DEBUG("Get rtp audio stream, file=%s",arc_file);
		if(strstr(arc_file, ".mjr"))
			snprintf(source, 1024, "%s/%s", recordings_path, arc_file);
		else
			snprintf(source, 1024, "%s/%s.mjr", recordings_path, arc_file);
		afile = fopen(source, "rb");
		if(afile == NULL) {
			MODULE_DEBUG("Could not open audio file %s, can't start playout thread", source);
			//g_thread_unref(g_thread_self());
			return NULL;
		}
	}
	if(session->vframes) {
		char source[1024];
	   MODULE_DEBUG("Get rtp video stream, file=%s",vrc_file);
		if(strstr(vrc_file, ".mjr"))
			snprintf(source, 1024, "%s/%s", recordings_path, vrc_file);
		else
			snprintf(source, 1024, "%s/%s.mjr", recordings_path, vrc_file);
		vfile = fopen(source, "rb");
		if(vfile == NULL) {
			MODULE_DEBUG("Could not open video file %s, can't start playout thread...", source);
			if(afile)
				fclose(afile);
			afile = NULL;
			//g_thread_unref(g_thread_self());
			return NULL;
		}
	}
	
	/* Timer */
	bool asent = FALSE, vsent = FALSE;
	struct timeval now, abefore, vbefore;
	time_t d_s, d_us;
	gettimeofday(&now, NULL);
	gettimeofday(&abefore, NULL);
	gettimeofday(&vbefore, NULL);

	janus_recordplay_frame_packet *audio = session->aframes, *video = session->vframes;
	char *buffer = (char *)malloc(1500);
	memset(buffer, 0, 1500);
	int bytes = 0;
	int64_t ts_diff = 0, passed = 0;

   MODULE_DEBUG("start relaying: destroyed=%u,active=%u",session->destroyed,session->active);	
   session->active = 1;
	while(!session->destroyed && session->active /*&& !session->recording->destroyed*/ && (audio || video)) {
		if(!asent && !vsent) {
			/* We skipped the last round, so sleep a bit (5ms) */
			usleep(5000);
		}
		asent = FALSE;
		vsent = FALSE;
		if(audio) {
			if(audio == session->aframes) {
				/* First packet, send now */
				fseek(afile, audio->offset, SEEK_SET);
				bytes = fread(buffer, sizeof(char), audio->len, afile);
				if(bytes != audio->len)
					MODULE_DEBUG("Didn't manage to read all the bytes we needed (%d < %d)", bytes, audio->len);
				/* Update payload type */
				rtp_header *rtp = (rtp_header *)buffer;
				rtp->type = OPUS_PT;	/* FIXME We assume it's Opus */
				MODULE_DEBUG("FIXME relay");
				//if(gateway != NULL)
				//	gateway->relay_rtp(session->handle, 0, (char *)buffer, bytes); //call: janus_plugin_relay_rtp
            janus_ice_relay_rtp(session->handle,0,(char *)buffer, bytes);
				gettimeofday(&now, NULL);
				abefore.tv_sec = now.tv_sec;
				abefore.tv_usec = now.tv_usec;
				asent = TRUE;
				audio = audio->next;
			} else {
				/* What's the timestamp skip from the previous packet? */
				ts_diff = audio->ts - audio->prev->ts;
				ts_diff = (ts_diff*1000)/48;	/* FIXME Again, we're assuming Opus and it's 48khz */
				/* Check if it's time to send */
				gettimeofday(&now, NULL);
				d_s = now.tv_sec - abefore.tv_sec;
				d_us = now.tv_usec - abefore.tv_usec;
				if(d_us < 0) {
					d_us += 1000000;
					--d_s;
				}
				passed = d_s*1000000 + d_us;
				if(passed < (ts_diff-5000)) {
					asent = FALSE;
				} else {
					/* Update the reference time */
					abefore.tv_usec += ts_diff%1000000;
					if(abefore.tv_usec > 1000000) {
						abefore.tv_sec++;
						abefore.tv_usec -= 1000000;
					}
					if(ts_diff/1000000 > 0) {
						abefore.tv_sec += ts_diff/1000000;
						abefore.tv_usec -= ts_diff/1000000;
					}
					/* Send now */
					fseek(afile, audio->offset, SEEK_SET);
					bytes = fread(buffer, sizeof(char), audio->len, afile);
					if(bytes != audio->len)
						MODULE_DEBUG("Didn't manage to read all the bytes we needed (%d < %d)", bytes, audio->len);
					/* Update payload type */
					rtp_header *rtp = (rtp_header *)buffer;
					rtp->type = OPUS_PT;	/* FIXME We assume it's Opus */
					//if(gateway != NULL)
					//	gateway->relay_rtp(session->handle, 0, (char *)buffer, bytes);
               janus_ice_relay_rtp(session->handle,0,(char *)buffer, bytes);
					asent = TRUE;
					audio = audio->next;
				}
			}
		}
		if(video) {
			if(video == session->vframes) {
				/* First packets: there may be many of them with the same timestamp, send them all */
				uint64_t ts = video->ts;
				while(video && video->ts == ts) {
					fseek(vfile, video->offset, SEEK_SET);
					bytes = fread(buffer, sizeof(char), video->len, vfile);
					if(bytes != video->len)
						MODULE_DEBUG("Didn't manage to read all the bytes we needed (%d < %d)", bytes, video->len);
					/* Update payload type */
					rtp_header *rtp = (rtp_header *)buffer;
					rtp->type = VP8_PT;	/* FIXME We assume it's VP8 */
					//if(gateway != NULL)
					//	gateway->relay_rtp(session->handle, 1, (char *)buffer, bytes);
               janus_ice_relay_rtp(session->handle,1,(char *)buffer, bytes);
					video = video->next;
				}
				vsent = TRUE;
				gettimeofday(&now, NULL);
				vbefore.tv_sec = now.tv_sec;
				vbefore.tv_usec = now.tv_usec;
			} else {
				/* What's the timestamp skip from the previous packet? */
				ts_diff = video->ts - video->prev->ts;
				ts_diff = (ts_diff*1000)/90;
				/* Check if it's time to send */
				gettimeofday(&now, NULL);
				d_s = now.tv_sec - vbefore.tv_sec;
				d_us = now.tv_usec - vbefore.tv_usec;
				if(d_us < 0) {
					d_us += 1000000;
					--d_s;
				}
				passed = d_s*1000000 + d_us;
				if(passed < (ts_diff-5000)) {
					vsent = FALSE;
				} else {
					/* Update the reference time */
					vbefore.tv_usec += ts_diff%1000000;
					if(vbefore.tv_usec > 1000000) {
						vbefore.tv_sec++;
						vbefore.tv_usec -= 1000000;
					}
					if(ts_diff/1000000 > 0) {
						vbefore.tv_sec += ts_diff/1000000;
						vbefore.tv_usec -= ts_diff/1000000;
					}
					/* There may be multiple packets with the same timestamp, send them all */
					uint64_t ts = video->ts;
					while(video && video->ts == ts) {
						/* Send now */
						fseek(vfile, video->offset, SEEK_SET);
						bytes = fread(buffer, sizeof(char), video->len, vfile);
						if(bytes != video->len)
							MODULE_DEBUG("Didn't manage to read all the bytes we needed (%d < %d)", bytes, video->len);
						/* Update payload type */
						rtp_header *rtp = (rtp_header *)buffer;
						rtp->type = VP8_PT;	/* FIXME We assume it's VP8 */
						//if(gateway != NULL)
						//	gateway->relay_rtp(session->handle, 1, (char *)buffer, bytes);
                  janus_ice_relay_rtp(session->handle,1,(char *)buffer, bytes);
						video = video->next;
					}
					vsent = TRUE;
				}
			}
		}
	}
	
	free(buffer);

	/* Get rid of the indexes */
	janus_recordplay_frame_packet *tmp = NULL;
	audio = session->aframes;
	while(audio) {
		tmp = audio->next;
		free(audio);
		audio = tmp;
	}
	session->aframes = NULL;
	video = session->vframes;
	while(video) {
		tmp = video->next;
		free(video);
		video = tmp;
	}
	session->vframes = NULL;

	if(afile)
		fclose(afile);
	afile = NULL;
	if(vfile)
		fclose(vfile);
	vfile = NULL;

	MODULE_DEBUG("Stop relaying");

	/*if(session->recording->destroyed) {
		// Remove from the list of viewers
		janus_mutex_lock(&session->recording->mutex);
		session->recording->viewers = g_list_remove(session->recording->viewers, session);
		if(session->recording->viewers == NULL) {
			// This was the last viewer, destroying the recording
			MODULE_DEBUG("Last viewer stopped playout of recording %u, destroying it now", session->recording->id);
			janus_mutex_unlock(&session->recording->mutex);
			g_free(session->recording->name);
			g_free(session->recording->date);
			g_free(session->recording->arc_file);
			g_free(session->recording->vrc_file);
			g_free(session->recording);
			session->recording = NULL;
		} else {
			// Other viewers still on, don't do anything
			MODULE_DEBUG("Recording %u still has viewers, delaying its destruction", session->recording->id);
			janus_mutex_unlock(&session->recording->mutex);
		}
	}*/

	/* Tell the core to tear down the PeerConnection, hangup_media will do the rest */
	//gateway->close_pc(session->handle);

   //close_peerconnection(session->handle);//FIXME: uncomment
	
	MODULE_DEBUG("Leaving playout thread");
	//g_thread_unref(g_thread_self());
	return NULL;
}

janus_recordplay_session *
janus_recordplay_create_session(ice_session_t *handle) {
   MODULE_DEBUG("janus recordplay create session");
	//if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
   if(stopping || !initialized) {
		MODULE_DEBUG("session is stopped or not init");
		return NULL;
	}	
	janus_recordplay_session *session = (janus_recordplay_session *)malloc(sizeof(janus_recordplay_session));
	if(session == NULL) {
		MODULE_DEBUG("Memory error");
		return NULL;
	}
	session->active = FALSE;
	session->recorder = FALSE;
	session->firefox = FALSE;
	session->arc = NULL;
	session->vrc = NULL;
	session->destroyed = 0;
	//g_atomic_int_set(&session->hangingup, 0);
   session->hangingup = 0;
	session->video_remb_startup = 4;
	session->video_remb_last = get_monotonic_time();
	session->video_bitrate = 1024 * 1024; 		/* This is 1mbps by default */
	session->video_keyframe_request_last = 0;
	session->video_keyframe_interval = 15000; 	/* 15 seconds by default */
	session->video_fir_seq = 0;

	session->handle = handle;

	//handle->plugin_handle = session;
	//janus_mutex_lock(&sessions_mutex);
	//g_hash_table_insert(sessions, handle, session);
	//janus_mutex_unlock(&sessions_mutex);

	return session;
}

janus_recordplay_frame_packet *
janus_recordplay_get_frames(const char *dir, const char *filename) {
	if(!dir || !filename)
		return NULL;
	/* Open the file */
	char source[1024];
	if(strstr(filename, ".mjr"))
		snprintf(source, 1024, "%s/%s", dir, filename);
	else
		snprintf(source, 1024, "%s/%s.mjr", dir, filename);
	FILE *file = fopen(source, "rb");
	if(file == NULL) {
		MODULE_ERROR("Could not open file %s", source);
		return NULL;
	}
	fseek(file, 0L, SEEK_END);
	long fsize = ftell(file);
	fseek(file, 0L, SEEK_SET);
	MODULE_DEBUG("File is %zu bytes", fsize);

	/* Pre-parse */
	MODULE_DEBUG("Pre-parsing file %s to generate ordered index", source);
	bool parsed_header = FALSE;
	int bytes = 0;
	long offset = 0;
	uint16_t len = 0, count = 0;
	uint32_t first_ts = 0, last_ts = 0, reset = 0;	/* To handle whether there's a timestamp reset in the recording */
	char prebuffer[1500];
	memset(prebuffer, 0, 1500);
	/* Let's look for timestamp resets first */
	while(offset < fsize) {
		/* Read frame header */
		fseek(file, offset, SEEK_SET);
		bytes = fread(prebuffer, sizeof(char), 8, file);
		if(bytes != 8 || prebuffer[0] != 'M') {
			MODULE_DEBUG("Invalid header...");
			fclose(file);
			return NULL;
		}
		if(prebuffer[1] == 'E') {
			/* Either the old .mjr format header ('MEETECHO' header followed by 'audio' or 'video'), or a frame */
			offset += 8;
			bytes = fread(&len, sizeof(uint16_t), 1, file);
			len = ntohs(len);
			offset += 2;
			if(len == 5 && !parsed_header) {
				/* This is the main header */
				parsed_header = TRUE;
				MODULE_DEBUG("Old .mjr header format");
				bytes = fread(prebuffer, sizeof(char), 5, file);
				if(prebuffer[0] == 'v') {
					MODULE_DEBUG("This is a video recording, assuming VP8");
				} else if(prebuffer[0] == 'a') {
					MODULE_DEBUG("This is an audio recording, assuming Opus");
				} else {
					MODULE_DEBUG("Unsupported recording media type...");
					fclose(file);
					return NULL;
				}
				offset += len;
				continue;
			} else if(len < 12) {
				/* Not RTP, skip */
				MODULE_DEBUG("Skipping packet (not RTP?)");
				offset += len;
				continue;
			}
		} else if(prebuffer[1] == 'J') {
			/* New .mjr format, the header may contain useful info */
			offset += 8;
			bytes = fread(&len, sizeof(uint16_t), 1, file);
			len = ntohs(len);
			offset += 2;
			if(len > 0 && !parsed_header) {
				/* This is the info header */
				MODULE_DEBUG("New .mjr header format");
				bytes = fread(prebuffer, sizeof(char), len, file);
				parsed_header = TRUE;
				prebuffer[len] = '\0';
				json_error_t error;
				json_t *info = json_loads(prebuffer, 0, &error);
				if(!info) {
					MODULE_DEBUG("JSON error: on line %d: %s", error.line, error.text);
					MODULE_DEBUG("Error parsing info header...");
					fclose(file);
					return NULL;
				}
				/* Is it audio or video? */
				json_t *type = json_object_get(info, "t");
				if(!type || !json_is_string(type)) {
					MODULE_DEBUG("Missing/invalid recording type in info header...");
					fclose(file);
					return NULL;
				}
				const char *t = json_string_value(type);
				int video = 0;
				int64_t c_time = 0, w_time = 0;
				if(!strcasecmp(t, "v")) {
					video = 1;
				} else if(!strcasecmp(t, "a")) {
					video = 0;
				} else {
					MODULE_DEBUG("Unsupported recording type '%s' in info header...", t);
					fclose(file);
					return NULL;
				}
				/* What codec was used? */
				json_t *codec = json_object_get(info, "c");
				if(!codec || !json_is_string(codec)) {
					MODULE_DEBUG("Missing recording codec in info header...");
					fclose(file);
					return NULL;
				}
				const char *c = json_string_value(codec);
				if(video && strcasecmp(c, "vp8")) {
					MODULE_DEBUG("The post-processor only suupports VP8 video for now (was '%s')...", c);
					fclose(file);
					return NULL;
				} else if(!video && strcasecmp(c, "opus")) {
					MODULE_DEBUG("The post-processor only suupports Opus audio for now (was '%s')...", c);
					fclose(file);
					return NULL;
				}
				/* When was the file created? */
				json_t *created = json_object_get(info, "s");
				if(!created || !json_is_integer(created)) {
					MODULE_DEBUG("Missing recording created time in info header...");
					fclose(file);
					return NULL;
				}
				c_time = json_integer_value(created); (void)c_time;
				/* When was the first frame written? */
				json_t *written = json_object_get(info, "u");
				if(!written || !json_is_integer(written)) {
					MODULE_DEBUG("Missing recording written time in info header...");
					fclose(file);
					return NULL;
				}
				w_time = json_integer_value(created);(void)w_time;
				/* Summary */
				MODULE_DEBUG("This is %s recording:", video ? "a video" : "an audio");
				MODULE_DEBUG("  -- Codec:   %s", c);
				MODULE_DEBUG("  -- Created: %u", c_time);
				MODULE_DEBUG("  -- Written: %u", w_time);
			}
		} else {
			MODULE_DEBUG("Invalid header...");
			fclose(file);
			return NULL;
		}
		/* Only read RTP header */
		bytes = fread(prebuffer, sizeof(char), 16, file);
		rtp_header *rtp = (rtp_header *)prebuffer;
		if(last_ts == 0) {
			first_ts = ntohl(rtp->timestamp);
			if(first_ts > 1000*1000)	/* Just used to check whether a packet is pre- or post-reset */
				first_ts -= 1000*1000;
		} else {
			if(ntohl(rtp->timestamp) < last_ts) {
				/* The new timestamp is smaller than the next one, is it a timestamp reset or simply out of order? */
				if(last_ts-ntohl(rtp->timestamp) > 2*1000*1000*1000) {
					reset = ntohl(rtp->timestamp);
					MODULE_DEBUG("Timestamp reset: %u", reset);
				}
			} else if(ntohl(rtp->timestamp) < reset) {
				MODULE_DEBUG("Updating timestamp reset: %u (was %u)", ntohl(rtp->timestamp), reset);
				reset = ntohl(rtp->timestamp);
			}
		}
		last_ts = ntohl(rtp->timestamp);
		/* Skip data for now */
		offset += len;
	}
	/* Now let's parse the frames and order them */
	offset = 0;
	janus_recordplay_frame_packet *list = NULL, *last = NULL;
	while(offset < fsize) {
		/* Read frame header */
		fseek(file, offset, SEEK_SET);
		bytes = fread(prebuffer, sizeof(char), 8, file);
		prebuffer[8] = '\0';
		MODULE_DEBUG("Header: %s", prebuffer);
		offset += 8;
		bytes = fread(&len, sizeof(uint16_t), 1, file);
		len = ntohs(len);
		MODULE_DEBUG("  -- Length: %u", len);
		offset += 2;
		if(prebuffer[1] == 'J' || len < 12) {
			/* Not RTP, skip */
			MODULE_DEBUG("  -- Not RTP, skipping");
			offset += len;
			continue;
		}
		/* Only read RTP header */
		bytes = fread(prebuffer, sizeof(char), 16, file);
		rtp_header *rtp = (rtp_header *)prebuffer;
		MODULE_ERROR("  -- RTP packet (ssrc=%u, pt=%u, ext=%u, seq=%u, ts=%u)",
				ntohl(rtp->ssrc), rtp->type, rtp->extension, ntohs(rtp->seq_number), ntohl(rtp->timestamp));
		/* Generate frame packet and insert in the ordered list */
		janus_recordplay_frame_packet *p = (janus_recordplay_frame_packet *)
         malloc(sizeof(janus_recordplay_frame_packet));
		if(p == NULL) {
			MODULE_ERROR("Memory error");
			fclose(file);
			return NULL;
		}
		p->seq = ntohs(rtp->seq_number);
		if(reset == 0) {
			/* Simple enough... */
			p->ts = ntohl(rtp->timestamp);
		} else {
			/* Is this packet pre- or post-reset? */
			if(ntohl(rtp->timestamp) > first_ts) {
				/* Pre-reset... */
				p->ts = ntohl(rtp->timestamp);
			} else {
				/* Post-reset... */
				uint64_t max32 = UINT32_MAX;
				max32++;
				p->ts = max32+ntohl(rtp->timestamp);
			}
		}
		p->len = len;
		p->offset = offset;
		p->next = NULL;
		p->prev = NULL;
		if(list == NULL) {
			/* First element becomes the list itself (and the last item), at least for now */
			list = p;
			last = p;
		} else {
			/* Check where we should insert this, starting from the end */
			int added = 0;
			janus_recordplay_frame_packet *tmp = last;
			while(tmp) {
				if(tmp->ts < p->ts) {
					/* The new timestamp is greater than the last one we have, append */
					added = 1;
					if(tmp->next != NULL) {
						/* We're inserting */
						tmp->next->prev = p;
						p->next = tmp->next;
					} else {
						/* Update the last packet */
						last = p;
					}
					tmp->next = p;
					p->prev = tmp;
					break;
				} else if(tmp->ts == p->ts) {
					/* Same timestamp, check the sequence number */
					if(tmp->seq < p->seq && (abs(tmp->seq - p->seq) < 10000)) {
						/* The new sequence number is greater than the last one we have, append */
						added = 1;
						if(tmp->next != NULL) {
							/* We're inserting */
							tmp->next->prev = p;
							p->next = tmp->next;
						} else {
							/* Update the last packet */
							last = p;
						}
						tmp->next = p;
						p->prev = tmp;
						break;
					} else if(tmp->seq > p->seq && (abs(tmp->seq - p->seq) > 10000)) {
						/* The new sequence number (resetted) is greater than the last one we have, append */
						added = 1;
						if(tmp->next != NULL) {
							/* We're inserting */
							tmp->next->prev = p;
							p->next = tmp->next;
						} else {
							/* Update the last packet */
							last = p;
						}
						tmp->next = p;
						p->prev = tmp;
						break;
					}
				}
				/* If either the timestamp ot the sequence number we just got is smaller, keep going back */
				tmp = tmp->prev;
			}
			if(!added) {
				/* We reached the start */
				p->next = list;
				list->prev = p;
				list = p;
			}
		}
		/* Skip data for now */
		offset += len;
		count++;
	}
	
	MODULE_DEBUG("Counted %u RTP packets", count);
	janus_recordplay_frame_packet *tmp = list;
	count = 0;
	while(tmp) {
		count++;
		MODULE_DEBUG("[%10lu][%4d] seq=%u, ts=%lu", tmp->offset, tmp->len, tmp->seq, tmp->ts);
		tmp = tmp->next;
	}
	MODULE_DEBUG("Counted %u frame packets", count);
	
	/* Done! */
	fclose(file);
	return list;
}

void
record_start(ice_session_t *handle) {
   janus_recordplay_session *session = NULL;

   session = janus_recordplay_create_session(handle);
   if ( session == NULL ) {
      MODULE_ERROR("Failed to create record session");
      return;
   }

   //const char *recordings_path = "/home/tuyettt/janus/share/janus/recordings";
   //const char *arc_file = "rec-458861550-audio.mjr";
   //const char *vrc_file = "rec-458861550-video.mjr";
   const char *recordings_path = "/home/tuyettt/record_video";
   const char *arc_file = "0_1482292194_audio.mjr";
   const char *vrc_file = "0_1482292194_video.mjr";
   MODULE_DEBUG("get audio file");
   session->aframes = janus_recordplay_get_frames(recordings_path, arc_file);
   if ( session->aframes == NULL ) {
      MODULE_ERROR("Failed to get audio file");
      return;
   }

   session->vframes = janus_recordplay_get_frames(recordings_path, vrc_file);
   if ( session->vframes == NULL ) {
      MODULE_ERROR("Failed to get video file");
      return;
   }


   //g_thread_try_new("recordplay playout thread", &janus_recordplay_playout_thread, session, &error);
   janus_recordplay_playout_thread(session);
}



