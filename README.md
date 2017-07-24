Snowem is a lightweight live streaming server, based on webrtc technology. Its design mainly focuses on simplicity, scalability and high performance.  
Visit official website [here](https://snowem.io).
### Prerequesite
Snowem depends on the following libraries to build:
* libopenssl.
* libevent with openssl support.
* libnettle.
* libjansson.
* libsofia-sip-ua.
* libsrtp.
* libconfig.


### Installation
```shell
git clone https://github.com/jackiedinh8/snowem.git
cd snowem
mkdir build
cd build
cmake ..
make
```

### Configuration & Run
The configuration file is written in format of libconfig. Basically, it looks like this:
```shell
# snowem.conf
# certificate used by built-in websocket server.
wss_cert_file = "<path-to>/wss_fullchain.pem"
wss_key_file = "<path-to>/wss_privkey.pem"
wss_bind_ip = "<ip_of_websocket_server>"
wss_bind_port = 443

ice_cert_file = "<path-to>/ice_fullchain.pem"
ice_key_file = "<path-to>/ice_privkey.pem"

// TRACE: 0, INFO: 1, DEBUG: 2, WARN: 3, ERROR: 4, FATAL: 5
log_level = 0
```
Snowem has built-in websocket server that exchange information between clients in order to setup video streams. To configure them, one needs provide certificates throught wss_cert_file and wss_key_file options. The ice_cert_file and ice_key_file options are used for establishing secure video streams.

To run Snowem:
```shell
snowem <path-to>/snowem.conf
```
