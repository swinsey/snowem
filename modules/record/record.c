#include <arpa/inet.h>
#include <sys/stat.h>
#include <errno.h>

#include <jansson.h>

#include "record.h"
#include "ice.h"
#include "log.h"
#include <string>
#include <iostream>
#include "utils.h"
#include "process.h"
#include "rtp.h"

/* Info header in the structured recording */
static const char *header = "MJR00001";
/* Frame header in the structured recording */
static const char *frame_header = "MEETECHO";

char decrypted_frame[1024*1024];
unsigned int frame_len;

recorder_t *recorder_create(const char *dir, int video, const char *filename) {
	recorder_t *rc = (recorder_t*)malloc(sizeof(recorder_t));
	if (rc == NULL) {
		MODULE_ERROR("Memory error!\n");
		return NULL;
	}
	rc->dir = NULL;
	rc->filename = NULL;
	rc->file = NULL;
	rc->created = get_real_time();
	if (dir != NULL) {
		/* Check if this directory exists, and create it if needed */
		struct stat s;
		int err = stat(dir, &s);
		if (err == -1) {
			if (ENOENT == errno) {
				/* Directory does not exist, try creating it */
				if (create_dir(dir, 0755) < 0) {
					MODULE_ERROR("mkdir error: %d\n", errno);
					return NULL;
				}
			} else {
				MODULE_ERROR("stat error: %d\n", errno);
				return NULL;
			}
		} else {
			if(S_ISDIR(s.st_mode)) {
				/* Directory exists */
				MODULE_DEBUG("Directory exists: %s\n", dir);
			} else {
				/* File exists but it's not a directory? */
				MODULE_ERROR("Not a directory? %s\n", dir);
				return NULL;
			}
		}
	}
	char newname[1024];
	memset(newname, 0, 1024);
	if(filename == NULL) {
		/* Choose a random username */
		snprintf(newname, 1024, "recording-%lu.mjr", random());
	} else {
		/* Just append the extension */
		snprintf(newname, 1024, "%s.mjr", filename);
	}
	/* Try opening the file now */
	if(dir == NULL) {
		rc->file = fopen(newname, "wb");
	} else {
		char path[1024];
		memset(path, 0, 1024);
		snprintf(path, 1024, "%s/%s", dir, newname);
		rc->file = fopen(path, "wb");
	}
	if(rc->file == NULL) {
		MODULE_ERROR("fopen error: %d\n", errno);
		return NULL;
	}
	if(dir)
		rc->dir = strdup(dir);
	rc->filename = strdup(newname);
	rc->video = video;
	/* Write the first part of the header */
	fwrite(header, sizeof(char), strlen(header), rc->file);
	rc->writable = 1;
	/* We still need to also write the info header first */
	rc->header = 0;
	return rc;
}

int recorder_save_frame(/*ice_session_t *handle, int type, int video*/recorder_t* recorder, char *buffer, int length) {
	int frame_len = 0;

	if(!recorder)
   {
      MODULE_ERROR("recorder_save_frame recorder is null");   
		return -1;
   }   
	if(!buffer || length < 1) {
      MODULE_ERROR("recorder_save_frame buffer: %d, length: %d", buffer, length);
		return -2;
	}
	if(!recorder->file) {
      MODULE_ERROR("recorder_save_frame recorder->file is null");
		return -3;
	}
	if(!recorder->writable) {
      MODULE_ERROR("recorder_save_frame recorder->writable: %i", recorder->writable);
		return -4;
	}

	if(!recorder->header) {
		// Write info header as a JSON formatted info
		json_t *info = json_object();
		// FIXME Codecs should be configurable in the future
		json_object_set_new(info, "t", json_string(recorder->video ? "v" : "a"));		// Audio/Video
		json_object_set_new(info, "c", json_string(recorder->video ? "vp8" : "opus"));	// Media codec
		json_object_set_new(info, "s", json_integer(time(NULL)));				// Created time
		json_object_set_new(info, "u", json_integer(get_real_time()));			// First frame written time
		char *info_text = json_dumps(info, JSON_PRESERVE_ORDER);
		json_decref(info);
		uint16_t info_bytes = htons(strlen(info_text));
		fwrite(&info_bytes, sizeof(uint16_t), 1, recorder->file);
		//memcpy(decrypted_frame, &info_bytes, sizeof(uint16_t));
		frame_len += sizeof(uint16_t);
		fwrite(info_text, sizeof(char), strlen(info_text), recorder->file);
		//memcpy(decrypted_frame, info_text, sizeof(char)*strlen(info_text));
		frame_len += sizeof(char)*strlen(info_text);
		// Done
		recorder->header = 1;
		MODULE_ERROR("recorder_save_frame writing recorder header...\n");
	}
   MODULE_DEBUG("recorder_save_frame, filename=%s\n",recorder->filename);
   //HEXDUMP(buffer,length,"frame")
	// Write frame header
	fwrite(frame_header, sizeof(char), strlen(frame_header), recorder->file);
   //memcpy(decrypted_frame, frame_header, strlen(frame_header));
   frame_len += strlen(frame_header);
	uint16_t header_bytes = htons(length);
	fwrite(&header_bytes, sizeof(uint16_t), 1, recorder->file);
	//memcpy(decrypted_frame, &header_bytes, sizeof(uint16_t));
	frame_len += sizeof(uint16_t);
	// Save packet on file 
	int temp = 0, tot = length;
	while(tot > 0) {
		temp = fwrite(buffer+length-tot, sizeof(char), tot, recorder->file);
		//memcpy(decrypted_frame, buffer+length-tot, tot);
		frame_len += tot;
		if(temp <= 0) {
			MODULE_ERROR("recorder_save_frame Error saving frame...\n");
			return -5;
		}
		tot -= temp;
	}
	// Done

	//if(handle->queued_packets != NULL) {
	//  MODULE_DEBUG("hande_peer_data_from_mcd relay rtp packets, type=%u, len=%u",pkt->type,pkt->length);
	//  g_async_queue_push(handle->queued_packets, pkt);
   //}
   
    
	return 0;
}

int recorder_close(recorder_t *recorder) {
	if(!recorder || !recorder->writable)
		return -1;

	recorder->writable = 0;
	if(recorder->file) {
		fseek(recorder->file, 0L, SEEK_END);
		size_t fsize = ftell(recorder->file);
		fseek(recorder->file, 0L, SEEK_SET);
		MODULE_DEBUG("File is %zu bytes: %s\n", fsize, recorder->filename); (void)fsize;
	}
	return 0;
}

int recorder_free(recorder_t *recorder) {

	if (!recorder)
		return -1;

	recorder_close(recorder);
	if(recorder->dir)
		free(recorder->dir);
	recorder->dir = NULL;
	if(recorder->filename)
		free(recorder->filename);
	recorder->filename = NULL;
	if(recorder->file)
		fclose(recorder->file);
	recorder->file = NULL;

	free(recorder);
	return 0;
}
