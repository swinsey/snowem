/*
 * Copyright (c) 2015 Jackie Dinh <jackiedinh8@gmail.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *  1 Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  2 Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution.
 *  3 Neither the name of the <organization> nor the 
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY 
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @(#)mq.c
 */

#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#ifdef linux
#include <time.h>
#endif

#include "mq.h"
#include "log.h"

int 
snw_adapctl_init(snw_adapctl_t *ctl, 
      const time_t cur_time, 
      const uint32_t period_time) {
    ctl->period_time = period_time;
    ctl->msg_cnt = 0;
    ctl->last_time = cur_time;
    ctl->rate = 1;
    return 0;
}

int get_packet_rate(const uint32_t msg_cnt) {
  //TODO: a good estimate packet rate needed!
  if (msg_cnt <= 1000) {
    return 1;
  } else if (msg_cnt <= 10000) {
    return 7;
  } else if (msg_cnt <= 40000) {
    return 17;
  } else if (msg_cnt <= 70000) {
    return 37;
  } else if (msg_cnt <= 100000) {
    return 83;
  }
  return 100;
}

int 
snw_adapctl_addload(snw_adapctl_t *ctl,
      const time_t cur_time, const uint32_t msg_cnt) {
  if (cur_time < ctl->last_time + (int)ctl->period_time) {
    ctl->msg_cnt = ctl->msg_cnt + msg_cnt;
  } else {
    ctl->last_time = cur_time;
    ctl->rate = get_packet_rate(ctl->msg_cnt);
    ctl->msg_cnt = msg_cnt;
  }  
  return 0;
}

int 
snw_shmmq_init(snw_shmmq_t *mq, const char* fifo_path, 
      int32_t wait_sec, int32_t wait_usec, 
      int32_t shm_key, int32_t shm_size) {
  int ret = 0;
  int val;
  char *mem_addr = NULL;
  int mode = 0666 | O_NONBLOCK | O_NDELAY;

  if (mq == NULL) return -1;

  errno = 0;
  if ((mkfifo(fifo_path, mode)) < 0) {
    if (errno != EEXIST) {
      ret = -1;
      goto done;
    }
  }

  if ((mq->_fd = open(fifo_path, O_RDWR)) < 0) {
    ret = -2;
    goto done;
  }

  if (mq->_fd > 1024) {
    close(mq->_fd);
    ret = -3;
    goto done;
  }
    
  val = fcntl(mq->_fd, F_GETFL, 0);
  
  if (val == -1) {
    ret = errno ? -errno : val;
    goto done;
  }

  if (val & O_NONBLOCK) {
    ret = 0;
    goto done;
  }
  
  ret = fcntl(mq->_fd, F_SETFL, val | O_NONBLOCK | O_NDELAY);

  if (ret < 0) {
    ret = errno ? -errno : ret;
    goto done;
  } else {
    ret = 0;
  }

  assert(shm_size > SHM_HEAD_SIZE * 2 + (int32_t)sizeof(*mq->_adaptive_ctrl));

  mq->_shm = snw_shm_create(shm_key, shm_size);

  if ( mq->_shm == NULL ) {
    mq->_shm = snw_shm_open(shm_key, shm_size);
    if ( mq->_shm == NULL ) {
      ret = -1;
      goto done;
    }
    mem_addr = mq->_shm->addr;
    goto setup;
  } else {
    mem_addr = mq->_shm->addr;
  }

  // init head portion of shared meme.
  memset(mem_addr, 0, SHM_HEAD_SIZE * 2 + sizeof(*mq->_adaptive_ctrl));

  // init adaptive control.
  mq->_adaptive_ctrl = (snw_adapctl_t *)mem_addr;
  mq->_adaptive_ctrl->period_time = 1;
  mq->_adaptive_ctrl->msg_cnt = 0;
  mq->_adaptive_ctrl->last_time = time(NULL);
  mq->_adaptive_ctrl->rate = 1;

  mq->_wait_sec = wait_sec;
  mq->_wait_usec = wait_usec;
 
setup:
  mq->_adaptive_ctrl = (snw_adapctl_t *)mem_addr;
  mem_addr += sizeof(*mq->_adaptive_ctrl);
  mq->_enqueued_msg_cnt = (uint32_t*)mem_addr;
  mq->_dequeued_msg_cnt = (uint32_t*)mem_addr + 1;

  // set head and tail
  mq->_head = (uint32_t*)mem_addr + 2;
  mq->_tail = mq->_head+1;
  mq->_block = (char*) (mq->_tail+1);
  mq->_block_size = shm_size - (SHM_HEAD_SIZE * 2 + sizeof(*mq->_adaptive_ctrl));

  ret = 0;
done:
  return ret;
}

void 
snw_release_shmmq(snw_shmmq_t *mq) {
   // TODO
}

int
snw_write_mq(snw_shmmq_t *mq, const void* data, uint32_t data_len, uint32_t flow) {
  uint32_t head;
  uint32_t tail;
  uint32_t free_len;// = head>tail? head-tail: head+_block_size-tail;
  uint32_t tail_len;// = _block_size - tail;
  char sHead[SHM_HEAD_SIZE] = {0};
  uint32_t total_len;// = data_len+SHM_HEAD_SIZE;
  int ret = 0;

  if (mq == NULL) return -1;

  head = *mq->_head;
  tail = *mq->_tail;
  free_len = head>tail? head-tail : head + mq->_block_size - tail;
  tail_len = mq->_block_size - tail;
  total_len = data_len+SHM_HEAD_SIZE;

  // has enough space?
  if (free_len <= total_len) {
    ret = -1;
    goto done;
  }

  memcpy(sHead, &total_len, sizeof(uint32_t));
  memcpy(sHead+sizeof(uint32_t), &flow, sizeof(uint32_t));

  if (tail_len >= total_len) {
    // if tail space > 8+len, tail space can store a whole msg
    memcpy(mq->_block+tail, sHead, SHM_HEAD_SIZE);
    memcpy(mq->_block+tail+ SHM_HEAD_SIZE, data, data_len);
    *mq->_tail += data_len + SHM_HEAD_SIZE;
  } else if (tail_len >= SHM_HEAD_SIZE && tail_len < SHM_HEAD_SIZE+data_len) {
    // if tail space > 8 && < 8+len, msg will be split into 2 parts
    uint32_t first_len = 0;
    uint32_t second_len = 0;
    int32_t wrapped_tail = 0;
    memcpy(mq->_block+tail, sHead, SHM_HEAD_SIZE);
    first_len = tail_len - SHM_HEAD_SIZE;
    memcpy(mq->_block+tail+ SHM_HEAD_SIZE, data, first_len);
    second_len = data_len - first_len;
    memcpy(mq->_block, ((char*)data) + first_len, second_len);

    wrapped_tail = *mq->_tail + data_len + SHM_HEAD_SIZE - mq->_block_size;
    *mq->_tail = wrapped_tail;
  } else {
    uint32_t second_len = 0;
    memcpy(mq->_block+tail, sHead, tail_len);
    second_len = SHM_HEAD_SIZE - tail_len;
    memcpy(mq->_block, sHead + tail_len, second_len);
    memcpy(mq->_block + second_len, data, data_len);
    *mq->_tail = second_len + data_len;
  }

  (*mq->_enqueued_msg_cnt)++;
  if(free_len == mq->_block_size) 
    return 1;
  else
    return 0;
done:
   return ret;
}

int 
snw_shmmq_enqueue(snw_shmmq_t *mq, 
      const time_t cur_time, const void* data, 
      uint32_t data_len, uint32_t flow) {
  int ret = 0;

  if (mq == NULL) return -1;

  mq->_count++;

  ret = snw_write_mq(mq, data, data_len, flow);
  if (ret < 0) return ret;

  snw_adapctl_addload(mq->_adaptive_ctrl,cur_time, 1);

#ifdef USE_ADAPTIVE_CONTROL
  if (0 == mq->_count% mq->_adaptive_ctrl->rate)
#endif 
  {
     errno = 0;
     ret = write(mq->_fd, "\0", 1);
  }
  return 0;
}

int
snw_read_mq(snw_shmmq_t *mq, void* buf, uint32_t buf_size, 
     uint32_t *data_len, uint32_t *flow)
{
  int ret = 0;
  char sHead[SHM_HEAD_SIZE];
  uint32_t used_len;
  uint32_t total_len;
  uint32_t head = *mq->_head;
  uint32_t tail = *mq->_tail;

  if (head == tail) {
    *data_len = 0;
    ret = 0;
    goto done;
  }
  (*mq->_dequeued_msg_cnt)++;
  used_len = tail>head ? tail-head : tail+mq->_block_size-head;
  
  if (head+SHM_HEAD_SIZE > mq->_block_size) {
    uint32_t first_size = mq->_block_size - head;
    uint32_t second_size = SHM_HEAD_SIZE - first_size;
    memcpy(sHead, mq->_block + head, first_size);
    memcpy(sHead + first_size, mq->_block, second_size);
    head = second_size;
  } else {
    memcpy(sHead, mq->_block + head, SHM_HEAD_SIZE);
    head += SHM_HEAD_SIZE;
  }
  
  //  get meta data
  total_len  = *(uint32_t*) (sHead);
  *flow = *(uint32_t*) (sHead+sizeof(uint32_t));
  assert(total_len <= used_len);
  *data_len = total_len-SHM_HEAD_SIZE;

  if (*data_len > buf_size) {
    ret = -1;
    goto done;
  }
  if (head+*data_len > mq->_block_size) {
    uint32_t first_size = mq->_block_size - head;
    uint32_t second_size = *data_len - first_size;
    memcpy(buf, mq->_block + head, first_size);
    memcpy(((char*)buf) + first_size, mq->_block, second_size);
    *mq->_head = second_size;
  } else {
    memcpy(buf, mq->_block + head, *data_len);
    *mq->_head = head+*data_len;
  }
done:
  return ret;
};

int 
snw_shmmq_select_fifo(int _fd, unsigned _wait_sec, 
      unsigned _wait_usec) {
  fd_set readfd;
  FD_ZERO(&readfd);
  FD_SET(_fd, &readfd);
  struct timeval tv;
  tv.tv_sec = _wait_sec;
  tv.tv_usec = _wait_usec;
  errno = 0;
  int ret = 0; 

  ret = select(_fd+1, &readfd, NULL, NULL, &tv);
  if (ret > 0) {
    if(FD_ISSET(_fd, &readfd))
      return ret;
    else
      return -1;
  } else if (ret == 0) {
    return 0;
  } else {
    if (errno != EINTR) {
      close(_fd);
    }
    return -1;
  }
}

int 
snw_shmmq_dequeue(snw_shmmq_t *mq, void* buf, 
      uint32_t buf_size, uint32_t *data_len, uint32_t *flow) {
  int ret;

  if (mq == NULL) return -1;

  ret = snw_read_mq(mq, buf, buf_size, data_len, flow); 
  if (ret || *data_len) return ret;

  ret = snw_shmmq_select_fifo(mq->_fd, mq->_wait_sec, mq->_wait_usec);
  if (ret == 0) {
    data_len = 0;
    return ret;
  }
  else if (ret < 0) {
    return -1;
  }

  {
    static const int32_t buf_len = 1<<10;
    char buffer[buf_len];
    ret = read(mq->_fd, buffer, buf_len);
    if (ret < 0 && errno != EAGAIN) {
      return -1;
    }
  }  
  ret = snw_read_mq(mq, buf, buf_size, data_len, flow);

  return ret;
}


