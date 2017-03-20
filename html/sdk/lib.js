// SDK global constants
(function (window) {
   'use strict';
   function Globals() {

        this.mIsOpera = false;
        this.mIsFirefox = false;
        this.mIsSafari = false;
        this.mIsChrome = false;
        this.mIsIE = false;
        this.mIsAndroid = false;
        this.mIsIphone = false;
        this.mBrowserName = 'Unknown';
        this.mBrowserInfo = {};

        // init
        this.isOnSupport = false;

        // USER_STATUS
        this.USER_STATUS_CONNECTED = 1;
        this.USER_STATUS_WAITING = 2;
        this.USER_STATUS_ONSUPPORT = 3;

        // USER_TYPE
        this.SGN_USER_TYPE_ANON = 0;
        this.SGN_USER_TYPE_NORMAL = 1;
        this.SGN_USER_TYPE_AGENT = 2;
        this.SGN_USER_TYPE_ADMIN = 3;

        //SNW_CMD
        this.SNW_ICE = 1;
        this.SNW_RTP = 2;
        this.SNW_RTCP = 3;
        this.SNW_RSTP = 4;
        this.SNW_VIDEOCALL = 5653571; //'VDC'

        //SNW_ICE SUBCMD
        this.SNW_ICE_START = 1;
        this.SNW_ICE_STOP = 2;
        this.SNW_ICE_VIEW = 3;
        this.SNW_ICE_SDP = 4;
        this.SNW_ICE_CANDIDATE = 5;

        //SNW_VIDEOCALL SUBCMD
        this.SNW_VIDEOCALL_CREATE = 1;

        // SGN CMD
        this.SGN_ROOM = 1;
        this.SGN_USER = 2;
        this.SGN_VIDEO = 8;

        // SGN_ROOM SUBCMD
        this.SGN_ROOM_CREATE = 1;
        this.SGN_ROOM_JOIN = 2;
        this.SGN_ROOM_OWNER = 3;
        this.SGN_ROOM_BCAST = 4;
        this.SGN_ROOM_LEAVE = 5;
        this.SGN_ROOM_CALL = 6;
        this.SGN_ROOM_ACCEPT_CALL = 7;
        this.SGN_ROOM_USERLIST = 8;
        this.SGN_ROOM_USERINFO = 9;
        this.SGN_ROOM_CHAT = 10;
        this.SGN_ROOM_ASK_SUPPORT = 11;
        this.SGN_ROOM_OFFER_SUPPORT = 12;
        this.SGN_ROOM_JOIN_ANON = 13;
        this.SGN_ROOM_CLOSE_CALL = 14;
        this.SGN_ROOM_CALL_SUMMARY = 15;
        this.SGN_ROOM_CALL_FEEDBACK = 16;
        this.SGN_ROOM_AGENTLIST = 17;
        this.SGN_ROOM_ADD_AGENT = 18;
        this.SGN_ROOM_REMOVE_AGENT = 19;
        this.SGN_ROOM_ENABLE_AGENT = 20;
        this.SGN_ROOM_DISABLE_AGENT = 21;
        this.SGN_ROOM_INFO = 22;
        this.SGN_ROOM_SEARCH = 23;
        this.SGN_ROOM_ASK_RATING = 24;
        this.SGN_ROOM_SET_RATING = 25;

        // SGN_VIDEO_SUBCMD
        this.SGN_VIDEO_START = 1;
        this.SGN_VIDEO_STOP = 2;
        this.SGN_VIDEO_VIEW = 3;
        this.SGN_VIDEO_SDP = 4;
        this.SGN_VIDEO_CANDIDATE = 5;
       
        
        // server config
        this.SGN_IPADDR = "sgn.peercall.vn";
        this.SGN_PORT = 80;

        this.MEDIA_IPADDR = "media.peercall.vn";
        this.MEDIA_PORT = 443;

        //this.replay_constraints = { audio: true };
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

            {
                var unknown = '-';

                // screen
                var screenSize = '';
                if (screen.width) {
                    var width = (screen.width) ? screen.width : '';
                    var height = (screen.height) ? screen.height : '';
                    screenSize += '' + width + " x " + height;
                }

                // browser
                var nVer = navigator.appVersion;
                var nAgt = navigator.userAgent;
                var browser = navigator.appName;
                var version = '' + parseFloat(navigator.appVersion);
                var majorVersion = parseInt(navigator.appVersion, 10);
                var nameOffset, verOffset, ix;

               // Opera
               if ((verOffset = nAgt.indexOf('Opera')) != -1) {
                   browser = 'Opera';
                   version = nAgt.substring(verOffset + 6);
                   if ((verOffset = nAgt.indexOf('Version')) != -1) {
                       version = nAgt.substring(verOffset + 8);
                   }
               }
               // Opera Next
               if ((verOffset = nAgt.indexOf('OPR')) != -1) {
                   browser = 'Opera';
                   version = nAgt.substring(verOffset + 4);
               }
               // MSIE
               else if ((verOffset = nAgt.indexOf('MSIE')) != -1) {
                   browser = 'Microsoft Internet Explorer';
                   version = nAgt.substring(verOffset + 5);
               }
               // Chrome
               else if ((verOffset = nAgt.indexOf('Chrome')) != -1) {
                   browser = 'Chrome';
                   version = nAgt.substring(verOffset + 7);
               }
               // Safari
               else if ((verOffset = nAgt.indexOf('Safari')) != -1) {
                   browser = 'Safari';
                   version = nAgt.substring(verOffset + 7);
                   if ((verOffset = nAgt.indexOf('Version')) != -1) {
                       version = nAgt.substring(verOffset + 8);
                   }
               }
               // Firefox
               else if ((verOffset = nAgt.indexOf('Firefox')) != -1) {
                   browser = 'Firefox';
                   version = nAgt.substring(verOffset + 8);
               }
               // MSIE 11+
               else if (nAgt.indexOf('Trident/') != -1) {
                   browser = 'Microsoft Internet Explorer';
                   version = nAgt.substring(nAgt.indexOf('rv:') + 3);
               }
               // Other browsers
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

               // flash (you'll need to include swfobject)
               /* script src="//ajax.googleapis.com/ajax/libs/swfobject/2.2/swfobject.js" */
               var flashVersion = 'no check';
               if (typeof swfobject != 'undefined') {
                   var fv = swfobject.getFlashPlayerVersion();
                   if (fv.major > 0) {
                       flashVersion = fv.major + '.' + fv.minor + ' r' + fv.release;
                   }
                   else  {
                       flashVersion = unknown;
                   }
               }
           }

           return {
               screen: screenSize,
               browser: browser,
               browserVersion: version,
               browserMajorVersion: majorVersion,
               mobile: mobile,
               os: os,
               osVersion: osVersion,
               cookies: cookieEnabled,
               flashVersion: flashVersion
           };
        }

        function browserDetection() {
            // Opera 8.0+ (UA detection to detect Blink/v8-powered Opera)
            mIsOpera = !!window.opera || navigator.userAgent.indexOf(' OPR/') >= 0;
            mIsFirefox = typeof InstallTrigger !== 'undefined';   // Firefox 1.0+
            mIsSafari = Object.prototype.toString.call(window.HTMLElement).indexOf('Constructor') > 0;
            // At least Safari 3+: "[object HTMLElementConstructor]"
            mIsChrome = !!window.chrome && ! mIsOpera;              // Chrome 1+
            mIsIE = /*@cc_on!@*/false || !!document.documentMode;   // At least IE6

            mBrowserInfo = get_browser_info();
        }
        browserDetection();

        this.getBrowserInfo = function() {
           return mBrowserInfo;
        }

        return this;
   }

   var PeerCall = window.PeerCall;
   PeerCall.Globals = Globals;
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

   var PeerCall = window.PeerCall;
   PeerCall.Utils = {};
   PeerCall.Utils.uuid = uuid;
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
    
   var PeerCall = window.PeerCall;
   PeerCall.Config = Config;
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

var PeerCall = window.PeerCall;
PeerCall.wsClient = wsClient;
})(this);

// peer agent
(function(window, undefined) {
   var PeerCall = window.PeerCall;
   var globals = PeerCall.Globals();
   function PeerAgent(){
      this.peerId = 0; 
      this.channelId = 0; 
      this.localStream = {};
      this.remoteStream = {};
      this.localVideoEl = null;
      this.remoteVideoEl = null;
      this.pc = null;
      this.state = "disconnected";
   }

   PeerAgent.prototype.init = function(config) {
      console.log("init peer agent");
      this.peerId = config.peerId;
      this.channelId = config.channelId;
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
        self.send({'cmd':globals.SGN_VIDEO,'subcmd':globals.SGN_VIDEO_SDP,
                   'roomid': 1443712566, 'sdp':sessionDescription});
      }   
      function onError(e) {
         console.log("failed to create sdp answer: " + e);
      }
      this.pc.setRemoteDescription(new RTCSessionDescription(msg));
      console.log("create answer " + JSON.stringify(globals.video_sdpConstraints));
      this.pc.createAnswer(setLocalAndSendMessage, onError, globals.video_sdpConstraints);
   }

   PeerAgent.prototype.on_remote_sdp = function(msg) {
      if (msg.type === 'offer') {
         console.log("received offer");
         this.do_answer(msg);
      } else if (msg.type === 'answer') {
         console.log("[ERROR] received answer, not handled");
      } else {
         console.log("[ERROR] unknown msg: " + JSON.stringify(msg));
      }
   }

   PeerAgent.prototype.on_remote_candidate = function(msg) {
      if (msg.type === 'candidate') {
         console.log("received candidate");
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
         return;
      }
      if (msg.cmd == globals.SGN_VIDEO ) {
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
      }
      console.log("[ERROR] unknown msg: " + JSON.stringify(msg));
      return;
   }

   PeerAgent.prototype.publish = function(stream) {
      var self = this;
      this.pc = new RTCPeerConnection(globals.replay_pc_config, globals.pc_constraints)
      function onicecandidate(event) {
        console.log('onicecandidate event: ', event);
        if (event.candidate) {
           var candidate = event.candidate.candidate;
           console.log("send relay address, sdpMid=", event.candidate.sdpMid);
           console.log("send relay address, sdpMlineIndex=", event.candidate.sdpMLineIndex);

           self.send({'cmd':globals.SGN_VIDEO,'subcmd':globals.SGN_VIDEO_CANDIDATE,'roomid': 1443712566,
                        'callid':'xxxyyyzzz', 'candidate':{
                                    type: 'candidate',
                                    label: event.candidate.sdpMLineIndex,
                                    id: event.candidate.sdpMid,
                                    candidate: event.candidate.candidate}});
        } else {
           console.log('End of candidates.');
           self.send({'cmd':globals.SGN_VIDEO,'subcmd':globals.SGN_VIDEO_CANDIDATE,'roomid': 1443712566,
                       'callid':'xxxyyyzzz', 'candidate':{ completed: true }});
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

   PeerCall.PeerAgent = PeerAgent;
})(this);
// end of peer agent

// SDK API implementation
(function(window, undefined) {
   var PeerCall = window.PeerCall;
   var globals = PeerCall.Globals();
   var config = PeerCall.Config();

   /* ---------------- PeerCall events ---------------------------------------*/
   var listeners = {};
   PeerCall.listen = function(eventName, handler) {
      if (typeof listeners[eventName] === 'undefined') {
         listeners[eventName] = [];
      }
      listeners[eventName].push(handler);
   }

   PeerCall.unlisten = function(eventName, handler) {
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

   function broadcast(eventName,msg) {
      console.log("broadcast " + eventName);
      if (!listeners[eventName]) {
         return; 
      }
      for (var i = 0; i < listeners[eventName].length; i++) {
         listeners[eventName][i](msg);
      } 
   }
   /* ----------------  end of PeerCall events ---------------------------------*/

   /* ----------------  PeerCall networking ------------------------------------*/
   var isWsReady = false;
   function onmessage(evt) {
      var msg = JSON.parse(evt.data);
      console.log("onmessage: ", evt.data);
      broadcast("onmessage",msg);
      return;
   };
   PeerCall.wsClient.setOnMessageCB(onmessage)
   PeerCall.wsClient.initWebSocket(globals.MEDIA_IPADDR,globals.MEDIA_PORT, function() {
      console.log("wsclient is connected");
      isWsReady = true;
   });
   /* ----------------  end of PeerCall networking ------------------------------*/

   /* ----------------  PeerCall API --------------------------------------------*/
   var agents = {};
   PeerCall.getAvailableChannel = function() {
      return 28093368;
   }

   function getPeerAgent(channel_id) {
      // check if agent exists, otherwise create one.
      var agent = agents[channel_id] || (function(channel_id) {
         var agent = new PeerCall.PeerAgent();
         var config = {
            peerId : 0,
            channelId : 28093368,
            localStream : {},
            remoteStream : {},
            localVideoElm : document.getElementById('localVideo'),
            remoteVideoElm : document.getElementById('remoteVideo'),
            state : "disconnected",
            pc : null,
            send : function(msg) {
               PeerCall.wsClient.send(msg);
            }
         };
         agent.init(config);
         PeerCall.listen("onmessage",function(msg) {
            agent.receive(msg);
         });
         return agent;
      })(channel_id);
      return agent;
   }

   function getusermedia(agent) {
      navigator.getUserMedia(globals.replay_constraints, function(stream) {
         console.log("get media sucessfully");
         if (!stream) {
            return;
         }
         agent.publish(stream);
         agent.localStream = stream;
         agent.localVideoElm.srcObject = stream;
         agent.send({'msgtype':globals.SNW_VIDEOCALL,'api':globals.SNW_VIDEOCALL_CREATE, 'uuid': PeerCall.Utils.uuid()});
         //agent.send({'cmd':globals.SNW_VIDEOCALL,'subcmd':globals.SNW_VIDEOCALL_CREATE,
         //             'callid':"xxxyyyzzz", 'id': 15081986, 'roomid': 1443712566});
         //onready();
         //subscribe();
      }, function(info) {
         console.log("failed to get media sucessfully");
         //debugcb(info);
         //return unablecb(info);
      });
   } 
   // @config: {channel_id: channel_id, }
   PeerCall.publish = function(config) {
      console.log("publish: " + config.channel_id);
      console.log("uuid: " + PeerCall.Utils.uuid());
      var agent = getPeerAgent(config.channel_id);
      console.log("agent=" + agent);
      getusermedia(agent);
   }

   PeerCall.subscribe = function(config) {
   }
   /* ----------------  end of PeerCall API --------------------------------------*/

   // sdk initiatlized
   console.log("sdk initialized");

})(this);


