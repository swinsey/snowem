// SDK global constants
(function (window) {
   'use strict';
   function Globals() {
      this.SNW_ICE = 1;
      this.SNW_CORE = 2;
      this.SNW_EVENT = 3;

      // ICE PUBLIC API
      this.SNW_ICE_CREATE = 1;
      this.SNW_ICE_CONNECT = 2;
      this.SNW_ICE_PUBLISH = 3;
      this.SNW_ICE_PLAY = 4;
      this.SNW_ICE_STOP = 5;
      this.SNW_ICE_CONTROL = 6;
      this.SNW_ICE_AUTH = 7;

      // ICE INTERNAL API
      this.SNW_ICE_SDP = 128; 
      this.SNW_ICE_CANDIDATE = 129;
      this.SNW_ICE_FIR = 130;

      // EVENT API
      this.SNW_EVENT_ICE_CONNECTED = 1;

      this.MEDIA_IPADDR = "media.peercall.vn";
      this.MEDIA_PORT = 443;

      this.replay_constraints = { audio: true, 
                                video: {
                                  mandatory:{
                                     maxWidth: 480,
                                     maxHeight: 270,
                                     minWidth: 480,
                                     minHeight: 270
                              }}};

      this.pc_config = {'iceServers':[{'urls':'stun:peercall.vn:8478'},
                                      {'urls':'turn:peercall.vn:8479','credential':'webrtc', 'username':'webrtc'}],
                        'iceTransports': 'relay'};

      this.replay_pc_config = {'iceServers':[{'urls':'stun:peercall.vn:8478'},
                                             {'urls':'turn:peercall.vn:8479','credential':'webrtc', 'username':'webrtc'}],
                               'iceTransports': 'all'};

      this.pc_constraints = {
        'optional': [
          {'DtlsSrtpKeyAgreement': true},
          {'RtpDataChannels': true}
      ]};

      this.sdpConstraints = {'mandatory': {
         'OfferToReceiveAudio':true,
         'OfferToReceiveVideo':true }};

      this.video_sdpConstraints = {'mandatory': {
         'OfferToReceiveAudio':true,
         'OfferToReceiveVideo':true }}; 

      this.view_sdpConstraints = {'mandatory': {
         'OfferToReceiveAudio':true,
         'OfferToReceiveVideo':true }}; 

      function get_browser_info() {
         var unknown = '-';
         var screenSize = '';
         if (screen.width) {
             var width = (screen.width) ? screen.width : '';
             var height = (screen.height) ? screen.height : '';
             screenSize += '' + width + " x " + height;
         }

         var nVer = navigator.appVersion;
         var nAgt = navigator.userAgent;
         var browser = navigator.appName;
         var version = '' + parseFloat(navigator.appVersion);
         var majorVersion = parseInt(navigator.appVersion, 10);
         var nameOffset, verOffset, ix;

         if ((verOffset = nAgt.indexOf('Opera')) != -1) {
             browser = 'Opera';
             version = nAgt.substring(verOffset + 6);
             if ((verOffset = nAgt.indexOf('Version')) != -1) {
                 version = nAgt.substring(verOffset + 8);
             }
         }
         else if ((verOffset = nAgt.indexOf('MSIE')) != -1) {
             browser = 'Microsoft Internet Explorer';
             version = nAgt.substring(verOffset + 5);
         }
         else if ((verOffset = nAgt.indexOf('Chrome')) != -1) {
             browser = 'Chrome';
             version = nAgt.substring(verOffset + 7);
         }
         else if ((verOffset = nAgt.indexOf('Safari')) != -1) {
             browser = 'Safari';
             version = nAgt.substring(verOffset + 7);
             if ((verOffset = nAgt.indexOf('Version')) != -1) {
                 version = nAgt.substring(verOffset + 8);
             }
         }
         else if ((verOffset = nAgt.indexOf('Firefox')) != -1) {
             browser = 'Firefox';
             version = nAgt.substring(verOffset + 8);
         }
         else if (nAgt.indexOf('Trident/') != -1) {
             browser = 'Microsoft Internet Explorer';
             version = nAgt.substring(nAgt.indexOf('rv:') + 3);
         }
         else if ((nameOffset = nAgt.lastIndexOf(' ') + 1) < (verOffset = nAgt.lastIndexOf('/'))) {
             browser = nAgt.substring(nameOffset, verOffset);
             version = nAgt.substring(verOffset + 1);
             if (browser.toLowerCase() == browser.toUpperCase()) {
                 browser = navigator.appName;
             }
         }
         // trim the version string
         if ((ix = version.indexOf(';')) != -1) version = version.substring(0, ix);
         if ((ix = version.indexOf(' ')) != -1) version = version.substring(0, ix);
         if ((ix = version.indexOf(')')) != -1) version = version.substring(0, ix);

         majorVersion = parseInt('' + version, 10);
         if (isNaN(majorVersion)) {
             version = '' + parseFloat(navigator.appVersion);
             majorVersion = parseInt(navigator.appVersion, 10);
         }

         // mobile version
         var mobile = /Mobile|mini|Fennec|Android|iP(ad|od|hone)/.test(nVer);
         // cookie
         var cookieEnabled = (navigator.cookieEnabled) ? true : false;
         if (typeof navigator.cookieEnabled == 'undefined' && !cookieEnabled) {
             document.cookie = 'testcookie';
             cookieEnabled = (document.cookie.indexOf('testcookie') != -1) ? true : false;
         }

         // system
         var os = unknown;
         var clientStrings = [
             {s:'Windows 10', r:/(Windows 10.0|Windows NT 10.0)/},
             {s:'Windows 8.1', r:/(Windows 8.1|Windows NT 6.3)/},
             {s:'Windows 8', r:/(Windows 8|Windows NT 6.2)/},
             {s:'Windows 7', r:/(Windows 7|Windows NT 6.1)/},
             {s:'Windows Vista', r:/Windows NT 6.0/},
             {s:'Windows Server 2003', r:/Windows NT 5.2/},
             {s:'Windows XP', r:/(Windows NT 5.1|Windows XP)/},
             {s:'Windows 2000', r:/(Windows NT 5.0|Windows 2000)/},
             {s:'Windows ME', r:/(Win 9x 4.90|Windows ME)/},
             {s:'Windows 98', r:/(Windows 98|Win98)/},
             {s:'Windows 95', r:/(Windows 95|Win95|Windows_95)/},
             {s:'Windows NT 4.0', r:/(Windows NT 4.0|WinNT4.0|WinNT|Windows NT)/},
             {s:'Windows CE', r:/Windows CE/},
             {s:'Windows 3.11', r:/Win16/},
             {s:'Android', r:/Android/},
             {s:'Open BSD', r:/OpenBSD/},
             {s:'Sun OS', r:/SunOS/},
             {s:'Linux', r:/(Linux|X11)/},
             {s:'iOS', r:/(iPhone|iPad|iPod)/},
             {s:'Mac OS X', r:/Mac OS X/},
             {s:'Mac OS', r:/(MacPPC|MacIntel|Mac_PowerPC|Macintosh)/},
             {s:'QNX', r:/QNX/},
             {s:'UNIX', r:/UNIX/},
             {s:'BeOS', r:/BeOS/},
             {s:'OS/2', r:/OS\/2/},
             {s:'Search Bot', r:/(nuhk|Googlebot|Yammybot|Openbot|Slurp|MSNBot|Ask Jeeves\/Teoma|ia_archiver)/}
         ];
         for (var id in clientStrings) {
             var cs = clientStrings[id];
             if (cs.r.test(nAgt)) {
                 os = cs.s;
                 break;
             }
         }

         var osVersion = unknown;
         if (/Windows/.test(os)) {
             osVersion = /Windows (.*)/.exec(os)[1];
             os = 'Windows';
         }

         switch (os) {
             case 'Mac OS X':
                 osVersion = /Mac OS X (10[\.\_\d]+)/.exec(nAgt)[1];
                 break;

             case 'Android':
                 osVersion = /Android ([\.\_\d]+)/.exec(nAgt)[1];
                 break;

             case 'iOS':
                 osVersion = /OS (\d+)_(\d+)_?(\d+)?/.exec(nVer);
                 osVersion = osVersion[1] + '.' + osVersion[2] + '.' + (osVersion[3] | 0);
                 break;
         }

         return {
             screen: screenSize,
             browser: browser,
             browserVersion: version,
             browserMajorVersion: majorVersion,
             mobile: mobile,
             os: os,
             osVersion: osVersion,
             cookies: cookieEnabled
         };
      }

      this.mBrowserInfo = get_browser_info();
      this.getBrowserInfo = function() {
         return this.mBrowserInfo;
      }

      return this;
   }

   var SnowSDK = window.SnowSDK;
   SnowSDK.Globals = Globals;
})(this);

// SDK Utitlities
(function(window, undefined) {
   function uuid() {
     function s4() {
       return Math.floor((1 + Math.random()) * 0x10000)
         .toString(16)
         .substring(1);
     }
     return s4() + s4() + '-' + s4() + '-' + s4() + '-' +
       s4() + '-' + s4() + s4() + s4();
   }

   var SnowSDK = window.SnowSDK;
   SnowSDK.Utils = {};
   SnowSDK.Utils.uuid = uuid;
})(this);

// SDK configurations
(function(window, undefined) {
   function Config() {
      this.roomid = 0;
      this.name = "";
      this.email = "";
   }

   Config.prototype.init= function(config) {
   };
    
   var SnowSDK = window.SnowSDK;
   SnowSDK.Config = Config;
})(this);


// websocket service
(function(window, undefined) {
var wsClient = {};

wsClient.initWebSocket = function(ipaddr, port, onsuccess) {
   var websocket = null;
   if ("WebSocket" in window) {
      //console.log("WebSocket is supported by your Browser!");
      // Let us open a web socket
      websocket = new WebSocket("wss://"+ipaddr+":"+port,"default");
      websocket.binaryType = 'blob';
      websocket.onopen = function(e) {
         console.log("onopen: web socket is opened");
         if (onsuccess) onsuccess();
      };
      websocket.onmessage = function (evt) {
        wsClient.onMessage(evt);
      };
   }
   wsClient.websocket = websocket;
}

wsClient.onMessage = function(evt) {
   var msg = JSON.parse(evt.data);
   console.log("have not defined onmessage: ", evt.data);
   return;
}

wsClient.setOnMessageCB = function(callback) {
   wsClient.onMessage = callback;
}

wsClient.send = function(message) {
   if (wsClient.websocket) {
      console.log('[wss] sending message: ', message);
      if (typeof message === 'object') {
         message = JSON.stringify(message);
      }
      wsClient.websocket.send(message);
   } else {
      console.log("websocket not ready");
   }
}

var SnowSDK = window.SnowSDK;
SnowSDK.wsClient = wsClient;
})(this);

// peer agent
(function(window, undefined) {
   var SnowSDK = window.SnowSDK;
   var globals = SnowSDK.Globals();
   function PeerAgent(){
      this.peerId = 0; 
      this.name = "";
      this.roomId = 0; 
      this.localStream = {};
      this.remoteStream = {};
      this.localVideoEl = null;
      this.remoteVideoEl = null;
      this.pc = null;
      this.state = "disconnected";
      this.is_publisher = 0;
   }

   PeerAgent.prototype.init = function(config) {
      console.log("init peer agent, id=" + config.peerId);
      this.peerId = config.peerId;
      this.roomId = config.roomId;
      this.channelId = 0;
      this.localStream = config.localStream;
      this.remoteStream = config.remoteStream;
      this.localVideoElm = config.localVideoElm;
      this.remoteVideoElm = config.remoteVideoElm;
      this.state = "disconnected";
      this.pc = config.pc;
      this.send = config.send;
   }

   PeerAgent.prototype.do_answer = function(msg) {
      var self = this;
      function setLocalAndSendMessage(sessionDescription) {
        //sessionDescription.sdp = preferOpus(sessionDescription.sdp);
        console.log("setLocalAndSendMessage: " + self.pc);
        self.pc.setLocalDescription(sessionDescription);
        self.send({'msgtype':globals.SNW_ICE,'api':globals.SNW_ICE_SDP,
                   'roomid': 1443712566, 'sdp':sessionDescription});
      }   
      function onError(e) {
         console.log("failed to create sdp answer: " + e);
      }
      console.log("remote sdp: " + JSON.stringify(msg));
      this.pc.setRemoteDescription(new RTCSessionDescription(msg));
      console.log("create answer " + JSON.stringify(globals.video_sdpConstraints));
      this.pc.createAnswer(setLocalAndSendMessage, onError, globals.video_sdpConstraints);
   }

   PeerAgent.prototype.on_remote_sdp = function(msg) {
      if (msg.type === 'offer') {
         console.log("received offer: " + JSON.stringify(msg));
         this.do_answer(msg);
      } else if (msg.type === 'answer') {
         console.log("[ERROR] received answer, not handled");
      } else {
         console.log("[ERROR] unknown msg: " + JSON.stringify(msg));
      }
   }

   PeerAgent.prototype.on_remote_candidate = function(msg) {
      console.log("received candidate: " + JSON.stringify(msg));
      if (msg.type === 'candidate') {
         var candidate = new RTCIceCandidate({sdpMLineIndex:msg.label, candidate:msg.candidate});
         console.log("received candidate, label=" + msg.label);
         this.pc.addIceCandidate(candidate);
      } else {
         console.log("[ERROR] unknown candidate: " + JSON.stringify(msg));
      }
   }

   PeerAgent.prototype.receive = function(msg) {
      if (msg.rc != null) {
         console.log("response from server: " + JSON.stringify(msg));
         if (msg.msgtype == globals.SNW_ICE ) {
            if (msg.api == globals.SNW_ICE_CREATE) {
               this.peerId = msg.id;
               this.channelId = msg.channelid;
               SnowSDK.broadcast('onCreate',this);
               return;
            }
         }
         return;
      }
      if (msg.msgtype == globals.SNW_ICE ) {
         if (msg.api == globals.SNW_ICE_CANDIDATE) {
            this.on_remote_candidate(msg.candidate);
            return;
         }
         if (msg.api == globals.SNW_ICE_SDP) {
            this.on_remote_sdp(msg.sdp);
            return;
         }
         return;
      }
      if (msg.msgtype == globals.SNW_EVENT) {
         if (msg.api == globals.SNW_EVENT_ICE_CONNECTED) {
            this.state = 'connected';
            SnowSDK.broadcast('onIceConnected',this);
            return;
         }
         return;
      }

      /*if (msg.cmd == globals.SGN_VIDEO ) {
         if (msg.subcmd == globals.SGN_VIDEO_SDP) {
            this.on_remote_sdp(msg.sdp);
            return;
         }
         if (msg.subcmd == globals.SGN_VIDEO_CANDIDATE) {
            this.on_remote_candidate(msg.candidate);
            return;
         }
         console.log("[ERROR] unknown submsg: " + JSON.stringify(msg));
         return;
      }*/
      console.log("[ERROR] unknown msg: " + JSON.stringify(msg));
      return;
   }

   PeerAgent.prototype.start_stream = function(stream) {
      var self = this;
      this.pc = new RTCPeerConnection(globals.replay_pc_config, globals.pc_constraints)
      function onicecandidate(event) {
        console.log('onicecandidate event: ', event);
        if (event.candidate) {
           var candidate = event.candidate.candidate;
           console.log("send relay address, sdpMid=", event.candidate.sdpMid);
           console.log("send relay address, sdpMlineIndex=", event.candidate.sdpMLineIndex);

           self.send({'msgtype':globals.SNW_ICE,'api':globals.SNW_ICE_CANDIDATE,'roomid': 1443712566,
                        'callid':'xxxyyyzzz', 'candidate':{
                                    type: 'candidate',
                                    label: event.candidate.sdpMLineIndex,
                                    id: event.candidate.sdpMid,
                                    candidate: event.candidate.candidate}});
        } else {
           console.log('End of candidates.');
           self.send({'msgtype':globals.SNW_ICE,'api':globals.SNW_ICE_CANDIDATE,'roomid': 1443712566,
                       'callid':'xxxyyyzzz', 'candidate':{ done: true }});
        }
      }   

      function onaddstream(event) {
         console.log('Remote stream added');
         //attachMediaStream(mStream.peerVideo, event.stream);
         self.remoteVideoElm.srcObject = event.stream;
         self.remoteStream = event.stream;
      }   

      function onremovestream(event) {
         console.log('Remote stream removed. Event: ', event);
      }   

      this.pc.onicecandidate = onicecandidate;
      this.pc.onaddstream = onaddstream;
      this.pc.onremovestream = onremovestream;
      this.pc.addStream(stream); //FIXME
   }

   function getusermedia(agent) {
      navigator.getUserMedia(globals.replay_constraints, function(stream) {
         console.log("get media sucessfully, id=" + agent.peerId);
         if (!stream) {
            return;
         }
         agent.start_stream(stream);
         agent.localStream = stream;
         agent.localVideoElm.srcObject = stream;
         //XXX: temporarily mute
         //agent.localVideoElm.muted = false;
         agent.send({'msgtype':globals.SNW_ICE,'api':globals.SNW_ICE_CONNECT, 
                     'channelid': agent.channelId, 'publish': agent.is_publisher, 'name': agent.name,
                     'callid':"xxxyyyzzz", 'id': agent.peerId, 'roomid': agent.roomId});
         //onready();
         //subscribe();
      }, function(info) {
         console.log("failed to get media sucessfully");
         //debugcb(info);
         //return unablecb(info);
      });
   } 

   PeerAgent.prototype.connect = function(config) {
      console.log("publish config info, config="+JSON.stringify(config));
      this.is_publisher = 1; 
      this.name = config.name;
      this.roomId = this.peerId;//XXX: roomid is the same as peerid!
      getusermedia(this);
   }

   PeerAgent.prototype.publish = function(config) {
      console.log("publishing, config="+JSON.stringify(config));
      this.send({'msgtype':globals.SNW_ICE,'api':globals.SNW_ICE_PUBLISH, 
                 'channelid': this.channelId, 'id': this.peerId, 'roomid': this.roomId});
   }
   PeerAgent.prototype.play = function(config) {
      console.log("playing, config="+JSON.stringify(config));
      this.send({'msgtype':globals.SNW_ICE,'api':globals.SNW_ICE_PLAY, 
                 'channelid': config.channelid, 'id': this.peerId, 'roomid': this.roomId});
      //this.is_publisher = 0; 
      //this.name = config.name;
      //this.roomId = config.roomid
      //getusermedia(this);
   }

   SnowSDK.PeerAgent = PeerAgent;
})(this);
// end of peer agent

// SDK API implementation
(function(window, undefined) {
   var SnowSDK = window.SnowSDK;
   var globals = SnowSDK.Globals();
   var config = SnowSDK.Config();

   /* ---------------- SnowSDK events ---------------------------------------*/
   var listeners = {};
   SnowSDK.listen = function(eventName, handler) {
      if (typeof listeners[eventName] === 'undefined') {
         listeners[eventName] = [];
      }
      listeners[eventName].push(handler);
   }

   SnowSDK.unlisten = function(eventName, handler) {
      if (!listeners[eventName]) {
         return; 
      }
      for (var i = 0; i < listeners[eventName].length; i++) {
         if (listeners[eventName][i] === handler) {
            listeners[eventName].splice(i, 1);
            break; 
         }
      }
   };

   SnowSDK.broadcast = function(eventName,msg) {
      console.log("broadcast, event=" + eventName + ", msg=" + JSON.stringify(msg));
      if (!listeners[eventName]) {
         console.log("no handler for event, name=" + JSON.stringify(eventName));
         return; 
      }
      for (var i = 0; i < listeners[eventName].length; i++) {
         listeners[eventName][i](msg);
      } 
   }
   /* ----------------  end of SnowSDK events ---------------------------------*/

   /* ----------------  SnowSDK networking ------------------------------------*/
   var isWsReady = false;
   function onmessage(evt) {
      var msg = JSON.parse(evt.data);
      console.log("onmessage: ", evt.data);
      SnowSDK.broadcast("onmessage",msg);
      return;
   };
   SnowSDK.wsClient.setOnMessageCB(onmessage)
   SnowSDK.wsClient.initWebSocket(globals.MEDIA_IPADDR,globals.MEDIA_PORT, function() {
      console.log("wsclient is connected");
      isWsReady = true;
   });
   /* ----------------  end of SnowSDK networking ------------------------------*/

   /* ----------------  SnowSDK API --------------------------------------------*/
   var agents = {};
   SnowSDK.getAvailableChannel = function() {
      return 28093368;
   }

   function getPeerAgent(channel_id) {
      if ( channel_id === null )
         channel_id = 0;
      // check if agent exists, otherwise create one.
      var agent = agents[channel_id] || (function(channel_id) {
         var agent = new SnowSDK.PeerAgent();
         var config = {
            peerId : 0,
            roomId : 28093368,
            localStream : {},
            remoteStream : {},
            localVideoElm : document.getElementById('localVideo'),
            remoteVideoElm : document.getElementById('remoteVideo'),
            state : "disconnected",
            pc : null,
            send : function(msg) {
               SnowSDK.wsClient.send(msg);
            }
         };
         agent.init(config);
         SnowSDK.listen("onmessage",function(msg) {
            agent.receive(msg);
         });
         return agent;
      })(channel_id);
      return agent;
   }


   /*SnowSDK.publish = function(config) {
      console.log("publish: " + config.channel_id);
      console.log("uuid: " + SnowSDK.Utils.uuid());
      var agent = getPeerAgent(config.channel_id);
      console.log("agent=" + agent);
      agent.send({'msgtype':globals.SNW_VIDEOCALL,'api':globals.SNW_VIDEOCALL_CREATE, 'uuid': SnowSDK.Utils.uuid()});
      //getusermedia(agent);
   }*/

   // @config: {channel_id: channel_id, }
   SnowSDK.create = function(config) {
      var agent = getPeerAgent();
      console.log("creating agent=" + JSON.stringify(agent));
      agent.send({'msgtype':globals.SNW_ICE,
                  'api':globals.SNW_ICE_CREATE, 
                  'uuid': SnowSDK.Utils.uuid()});
   }

   /*SnowSDK.publish = function(agent) {
      console.log("agent=" + agent);
      //getusermedia(agent);
   }

   SnowSDK.subscribe = function(config) {
   }*/
   /* ----------------  end of SnowSDK API --------------------------------------*/

   // sdk initiatlized
   console.log("sdk initialized");

})(this);


