#ifndef _ICE_H264_H
#define _ICE_H264_H

#include "ice_types.h"
#include "packet.h"

/* h264 payload type */
#define H264_PT_RSV0        0
#define H264_PT_NAT_UNIT_1  1
#define H264_PT_NAT_UNIT_2  2
#define H264_PT_NAT_UNIT_3  3
#define H264_PT_NAT_UNIT_4  4
#define H264_PT_NAT_UNIT_5  5
#define H264_PT_NAT_UNIT_6  6
#define H264_PT_NAT_UNIT_7  7
#define H264_PT_NAT_UNIT_8  8
#define H264_PT_NAT_UNIT_9  9
#define H264_PT_NAT_UNIT_10 10
#define H264_PT_NAT_UNIT_11 11
#define H264_PT_NAT_UNIT_12 12
#define H264_PT_NAT_UNIT_13 13
#define H264_PT_NAT_UNIT_14 14
#define H264_PT_NAT_UNIT_15 15
#define H264_PT_NAT_UNIT_16 16
#define H264_PT_NAT_UNIT_17 17
#define H264_PT_NAT_UNIT_18 18
#define H264_PT_NAT_UNIT_19 19
#define H264_PT_NAT_UNIT_20 20
#define H264_PT_NAT_UNIT_21 21
#define H264_PT_NAT_UNIT_22 22
#define H264_PT_NAT_UNIT_23 23
#define H264_PT_STAPA       24
#define H264_PT_STAPB       25
#define H264_PT_MTAP16      26
#define H264_PT_MTAP24      27
#define H264_PT_FUA         28
#define H264_PT_FUB         29
#define H264_PT_RSV1        30
#define H264_PT_RSV2        31

int
ice_h264_handler(snw_ice_session_t *session, char *buf, int buflen);

#endif //_ICE_H264_H




