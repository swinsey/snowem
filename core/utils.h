#ifndef _SNOW_CORE_UTILS_H_
#define _SNOW_CORE_UTILS_H_

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define CCD_OK (0)
#define CCD_ERR (-1)

#define CCD_MALLOC(_t) (_t*)malloc(sizeof(_t))
#define CCD_MEMZERO(p_,type_) memset(p_,0,sizeof(type_))
#define CCD_LWMALLOC(_l) malloc(LWS_SEND_BUFFER_PRE_PADDING+\
                             LWS_SEND_BUFFER_POST_PADDING+_l)
#define CCD_MEMSET(_s,_c,_n) memset(_s,_c,_n)
//#define CCD_FREE(_p) free(_p)
#define CCD_FREE(p_) { if (p_!=NULL) free(p_); }
#define CCD_MEMCPY(_dst,_src,_n) memcpy(_dst,_src,_n)
#define CCD_STRNCMP(_s,_t,_n) strncmp(_s,_t,_n)
#define CCD_STRLEN(_s) strlen(_s)
#define CCD_STRCPY(_dst,_src)      strcpy(_dst,_src)
#define CCD_OPEN(_f,_flags) open(_f,_flags)
#define CCD_READ(_f,_b,_c) read(_f,_b,_c)
#define CCD_CLOSE(_f) close(_f)
#define CCD_SEEK(_f,_offset,_whence) lseek(_f,_offset,_whence)


#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define HEXDUMP_OLD(_p,len,_type)\
{\
   char *p = (char*)_p;\
   char *type = (char*)_type;\
   char buf[256];\
   unsigned int i,j,k;\
   DEBUG("---- dump buffer (%s) ---- len=%d",type,len);\
   for (i = 0; i < (unsigned int)len; ) {\
      memset(buf, sizeof(buf), ' ');\
      sprintf(buf, "%5d: ", i);\
      k = i;\
      for (j=0; j < 16 && i < (unsigned int)len; i++, j++)\
         sprintf(buf+7+j*3, "%02x ", (uint8_t)(p[i]));\
      i = k;\
      for (j=0; j < 16 && i < (unsigned int)len; i++, j++)\
         sprintf(buf+7+j + 48, "%c",\
            isprint(p[i]) ? p[i] : '.');\
      DEBUG("%s: %s", type, buf);\
   }\
}

void print_buffer(char *p, int len, const char *prefix);
char* trimwhitespace(char *str);
void hexdump(char* p,int len, const char* type);
char* ip_to_str(unsigned int ip);
int64_t get_real_time(void);
int64_t get_monotonic_time(void);
int create_dir(const char *dir, mode_t mode);

#endif // _UTILS_H_







