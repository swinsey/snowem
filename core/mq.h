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
 * @(#)mq.h
 */

#ifndef _SNOW_CORE_MQ_H_
#define _SNOW_CORE_MQ_H_ 

#include "shm.h"

//static const int E_DEQUEUE_BUF_NOT_ENOUGH = -13001;

typedef struct snw_adapctl snw_adapctl_t;
struct snw_adapctl 
{
   unsigned int  m_uiCheckTimeSpan;
   unsigned int  m_uiMsgCount;
   unsigned int  m_uiLastMsgCount;
   unsigned int  m_uiFactor;
   unsigned int  m_uiLastFactor;
   time_t        m_uiLastCheckTime;
   unsigned int  m_uiSync;
}__attribute__((packed));

typedef struct snw_shmmq snw_shmmq_t;
struct snw_shmmq
{
	snw_shm_t* _shm;
   uint32_t        _fd;          //fifo file, used for notification.
   uint32_t        _wait_sec;
   uint32_t        _wait_usec;
   uint32_t        _count;
   snw_adapctl_t *_adaptive_ctrl;

	uint32_t*       _head;
	uint32_t*       _tail;
	char*           _block;
	uint32_t        _block_size;
   uint32_t*       _enqueued_msg_cnt;
   uint32_t*       _dequeued_msg_cnt;
#define SHM_HEAD_SIZE 8
}__attribute__((packed));

void 
print_shmmq(snw_shmmq_t *mq);

int 
snw_shmmq_init(snw_shmmq_t *mq, const char* fifo_path, 
      int32_t wait_sec, int32_t wait_usec, 
      int32_t shm_key, int32_t shm_size, int32_t sync);

void 
snw_shmmq_release(snw_shmmq_t *mq);

int 
snw_shmmq_enqueue(snw_shmmq_t *mq, 
      const time_t uiCurTime, const void* data, 
      uint32_t data_len, uint32_t flow);

int 
snw_shmmq_dequeue(snw_shmmq_t *mq, void* buf, 
      uint32_t buf_size, uint32_t *data_len, uint32_t *flow);

int 
snw_shmmq_dequeue_wait(snw_shmmq_t *mq, void* buf, 
      uint32_t buf_size, uint32_t *data_len, uint32_t *flow);

void 
snw_shmmq_clear_flag(uint32_t _fd);

	
#endif//_USNET_MQ_H_

