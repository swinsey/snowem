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

        //SGN_CMD
        this.SGN_ROOM = 1;
        this.SGN_USER = 2;
        this.SGN_NEGOTIATION = 3;
        this.SGN_REPORT = 4;
        this.SGN_REPLAY = 7;
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

        // SGN_USER SUBMCD
        this.SGN_USER_IDENTITY = 1;
        this.SGN_USER_CALL = 2;
        this.SGN_USER_SDP = 3;
        this.SGN_USER_ICE = 4;
        this.SGN_USER_GET_INFO = 5;
        this.SGN_USER_RESET_PASSWORD = 6;
        this.SGN_USER_SAVE_INFO = 7;

        // SGN_NEGOTIATION
        this.SGN_NEGOTIATION_START = 1;
        this.SGN_NEGOTIATION_STOP = 2;
        this.SGN_NEGOTIATION_SDP = 3;
        this.SGN_NEGOTIATION_ICE = 4;

        // SGN_REPORT SUBCMD
        this.SGN_REPORT_ONLINE_METRICS = 1;
        this.SGN_REPORT_HISTORY_METRICS = 2;
        this.SGN_REPORT_RECENT_CALLS = 3;
        this.SGN_REPORT_CALL_GET = 4;
        this.SGN_REPORT_CALL_GETS = 5;
        this.SGN_REPORT_NEW_CALL = 6;

        // SGN_REPLAY_SUBCMD
        this.SGN_REPLAY_REQ = 1;
        this.SGN_REPLAY_SDP = 2;
        this.SGN_REPLAY_ICE = 3;
        this.SGN_REPLAY_CLOSE = 4;
        this.SGN_REPLAY_PAUSE = 5;

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

        this.replay_constraints = { audio: true, 
                                video: {
                                  mandatory:{
                                     maxWidth: 480,
                                     maxHeight: 270,
                                     minWidth: 480,
                                     minHeight: 270
                              }}};

        //this.replay_constraints = { audio: true };

        //this.pc_config = {'iceServers':[{'url':'stun:203.162.54.147:4478'},
        //                    {'url':'turn:webrtc@203.162.54.147:4479','credential':'webrtc'}]};
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

    window.Globals = Globals;
    
    var globals = window.Globals();
})(window);
