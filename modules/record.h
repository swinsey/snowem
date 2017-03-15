#ifndef _ICE_RECORD_H
#define _ICE_RECORD_H

#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

//#include "types.h"

#define MODULE_DEBUG(...) do {} while(0)
#define MODULE_ERROR(...) do {} while(0)

typedef struct recorder recorder_t;
struct recorder {
	char *dir;
	char *filename;
	FILE *file;
	uint64_t created;
	int video:1;
	int header:1;
	int writable:1;
};

recorder_t *recorder_create(const char *dir, int video, const char *filename);
int recorder_save_frame(/*ice_session_t *handle, int type, int video*/recorder_t *recorder, char *buffer, int length);
int recorder_close(recorder_t *recorder);
int recorder_free(recorder_t *recorder);

#endif
