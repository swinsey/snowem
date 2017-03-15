#ifndef _PROCESS_H_
#define _PROCESS_H_

#include <event.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>
#include <jansson.h>
#include <json/json.h>

/*#include "config_file.h"
#include "base/base_str.h"
#include "net/ipc_mq.h"
#include "net/open_mq.h"
#include "libws/evws.h"
#include "ice.h"

extern struct event_base *g_event_base;

void message_handler(struct evwsconn* conn, enum evws_data_type data_type,
    const unsigned char* data, int len, void* user_data);

void done_handler(struct evwsconn* conn, void* user_data);

void new_wsconnection(struct evwsconnlistener *wslistener,
    struct evwsconn *conn, struct sockaddr *address, int socklen,
    void* user_data);

void init_ipc(struct event_base*, mqf::base::CFileConfig& page);

int enqueue_msg_to_mcd(const char* buf, int len, int flow);

int generate_sdp(ice_session_t *ice_handle);

int handle_sdp(ice_session_t *session, const char* sdp);

int ice_merge_streams(ice_session_t *session, int audio, int video);

int ice_merge_components(ice_session_t *session);

int verify_disabled_streams(ice_session_t *session, int audio, int video, const char *jsep_sdp);

int try_ice_start(ice_session_t *session);*/


#endif // _PROCESS_H_
