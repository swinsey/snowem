
(function(window) {

function Room() {
   // private vars
   var self = this;
   var globals = window.Globals();
   var mBrowser = globals.getBrowserInfo();

   var mId = 15081988;
   var mPrevId = 0;
   var mPeerId = 0;
   var mRoomId = 0;
   var mCallId = "xxxyyyzzz";
   var mEmail = "";
   var mToken = "";
   var mFullname = "";
   var mPhone = null;
   var mIsSetTimer = 0;
   var mStream = {};
   var mEnableAudio = true;
   var mEnableVideo = false;
   var IsInited = 0;
   var mIsVideo = 0;
   var mIsView = 0;
   var mUserType = globals.SGN_USER_TYPE_NORMAL;

   console.log("browser info hack: " + JSON.stringify(mBrowser)); 

   function sendMessage(message){
      console.log('Client sending message: ', message);
      if (typeof message === 'object') {
         message = JSON.stringify(message);
      }
      self.websocket.send(message);
   };

   // initialize net service
   function initnet(onsuccess) {
      if ("WebSocket" in window) {
         //console.log("WebSocket is supported by your Browser!");
         // Let us open a web socket
         self.websocket = new WebSocket("wss://"+globals.MEDIA_IPADDR+":"+globals.MEDIA_PORT,"default");
         self.websocket.binaryType = 'blob';
         self.websocket.onopen = function(e) {
            console.log("onopen: web socket is opened");
            self.IsInited = 1;
            if (onsuccess) onsuccess();
         };

         self.websocket.onmessage = function (evt) {
            var msg = JSON.parse(evt.data);
            console.log("onmessage: ", evt.data);

            if (msg.cmd == globals.SGN_USER ) {
               usercb(msg);
               return;
            }

            if (msg.cmd == globals.SGN_ROOM ) {
               roomcb(msg);
               return;
            }

            if (msg.cmd == globals.SGN_VIDEO ) {
               replaycb(msg);
               return;
            }

            console.log("[ERROR] unknown msg: " + JSON.stringify(msg));
            return;

         };

      }
   }

   this.init = function(roomid,previd,name,email,isVideo,isView) {
      console.log("init room");
      mRoomId = roomid;
      mPrevId = previd 
      mFullname = name;
      mEmail = email;
      mIsVideo = isVideo;
      mIsView = isView;

      initnet();

      function CheckNet() {
         if ( self.IsInited == 1 ) {
            startAgent(mId);
            if ( isView === 0 ) {
                sendMessage({'cmd':globals.SGN_VIDEO,'subcmd':globals.SGN_VIDEO_START,
                             'callid':mCallId, 'id': mId, 'roomid': mRoomId});
            } else {
                sendMessage({'cmd':globals.SGN_VIDEO,'subcmd':globals.SGN_VIDEO_VIEW,
                             'callid':mCallId, 'id': mId, 'roomid': mRoomId});
            }
            return;
         }
         else {
            console.log("Wait for net service");
            setTimeout(CheckNet,1000);
         }

      }
      CheckNet();

   }

   this.stop = function() {
      maybeStop();
      console.log("stop stream");
      sendMessage({'cmd':globals.SGN_VIDEO,'subcmd':globals.SGN_VIDEO_STOP,'roomid': mRoomId, 'callid':mCallId});
   }

   function doCall() {
      var constraints = {'optional': [], 'mandatory': {'MozDontOfferDataChannel': true}};
      
      function onCreateOfferError() {
         console.log("createOffer error!");
      }  
      
      function mergeConstraints(cons1, cons2) {
        var merged = cons1;
        for (var name in cons2.mandatory) {
          merged.mandatory[name] = cons2.mandatory[name];
        } 
        merged.optional.concat(cons2.optional);
        return merged;
      } 
      
      //console.log("doCall: " + mStream.pc);
      // temporary measure to remove Moz* constraints in Chrome
      if (webrtcDetectedBrowser === 'chrome') {
        for (var prop in constraints.mandatory) {
          if (prop.indexOf('Moz') !== -1) {
            delete constraints.mandatory[prop];
          } 
        } 
      } 
      constraints = mergeConstraints(constraints, globals.sdpConstraints);
      console.log('Sending offer to peer, with constraints: \n' +
                    '  \'' + JSON.stringify(constraints) + '\'.');
                    
      mStream.pc.createOffer().then(function(offer) {
         return mStream.pc.setLocalDescription(offer);
      }, onCreateOfferError)
      .then(function() {
         console.log("setLocalAndSendMessage: new api  " + JSON.stringify(mStream.pc.localDescription));
         sendMessage({'cmd':globals.SGN_VIDEO,'subcmd':globals.SGN_VIDEO_SDP,
                      'callid':mCallId, 'sdp':mStream.pc.localDescription,'roomid': mRoomId });
      });             
   }  

   function createPeerConnection() {

     function handleIceCandidate(event) {
       //console.log('handleIceCandidate event: ', event);
       if (event.candidate) {
         var candidate = event.candidate.candidate;
         console.log("send relay address, sdpMid=", event.candidate.sdpMid);
         console.log("send relay address, sdpMlineIndex=", event.candidate.sdpMLineIndex);

         sendMessage({'cmd':globals.SGN_VIDEO,'subcmd':globals.SGN_VIDEO_CANDIDATE,'roomid': mRoomId,
                      'callid':mCallId, 'candidate':{
                                   type: 'candidate',
                                   label: event.candidate.sdpMLineIndex,
                                   id: event.candidate.sdpMid,
                                   candidate: event.candidate.candidate}});
       } else {
         console.log('End of candidates.');
         sendMessage({'cmd':globals.SGN_VIDEO,'subcmd':globals.SGN_VIDEO_CANDIDATE,'roomid': mRoomId,
                      'callid':mCallId, 'candidate':{ completed: true }});
       }
     }

     function handleRemoteStreamAdded(event) {
       console.log('Remote stream added:' + mStream.remoteVideo);
       //attachMediaStream(mStream.peerVideo, event.stream);
       mStream.peerVideo.srcObject = event.stream;
       mStream.peerStream = event.stream;
     }

     function handleRemoteStreamRemoved(event) {
       //console.log('Remote stream removed. Event: ', event);
     }

     try {
       console.log("pc_config: " + JSON.stringify(globals.relay_pc_config));
       console.log("pc_constraints: " + JSON.stringify(globals.pc_constraints));
       mStream.pc = new RTCPeerConnection(globals.replay_pc_config, globals.pc_constraints);
       mStream.pc.onicecandidate = handleIceCandidate;
       mStream.isInitPC = true;

       console.log('Created RTCPeerConnnection with:\n' +
         '  config: \'' + JSON.stringify(globals.replay_pc_config) + '\';\n' +
         '  constraints: \'' + JSON.stringify(globals.pc_constraints) + '\'.');

     } catch (e) {
       console.log('Failed to create PeerConnection, exception: ' + e.message);
       return;
     }

     mStream.pc.onaddstream = handleRemoteStreamAdded;
     mStream.pc.onremovestream = handleRemoteStreamRemoved;

   }



   function maybeStart() {
      console.log("maybeStart isStarted: " + mStream.isStarted);
      console.log("maybeStart localStream: " + mStream.localStream);
      console.log("maybeStart isChannelReady: " + mStream.isChannelReady);
      console.log("maybeStart pc: " + mStream.pc);

      if (!mStream.isStarted && mStream.localStream && mStream.isChannelReady) {
         console.log("maybeStart started: " + JSON.stringify(mStream));
         createPeerConnection();
         mStream.pc.addStream(mStream.localStream);
         mStream.isStarted = true;
         if (mStream.isInitiator) {
            doCall();
         }   
      }   
   }   

   function handleUserMedia(stream) {

      //printStreamInfo(stream);

      console.log("got media stream");
      //got user media
      mStream.localStream = stream;
      //attachMediaStream(mStream.localVideo, stream);
      mStream.localVideo.srcObject = stream;
            
      //if (mStream.isInitiator) {
         maybeStart();
      //}   
   }   

   function handleUserMediaError(error){
      console.log('getUserMedia error: ', error);
   }   


   function startAgent(peerid) {
      console.log('start agent: ' + peerid);
      mStream.peerid = peerid;
      mStream.localVideo = document.getElementById('localVideo');
      mStream.localVideo.muted = 'muted';// just display video, mute audio
      mStream.peerVideo = document.getElementById('remoteVideo');
      mStream.isStarted = false; 
      mStream.isInitiator = false;
      mStream.isChannelReady = true;
      mStream.isInitPC = false;
      mStream.pc = {}; 
      //mStream.pc = new RTCPeerConnection(globals.replay_pc_config, globals.pc_constraints);

      console.log("localVideo: " + JSON.stringify(mStream.localVideo));
      navigator.getUserMedia(globals.replay_constraints, handleUserMedia, handleUserMediaError);

   }   

   function stopStream(stream) {
      var audioTrack = stream.getAudioTracks();
      console.log("audio track num: " + audioTrack.length);
      if (audioTrack.length > 0) {
         for (var i = 0; i < audioTrack.length; i++ ) {
            console.log("disable audio track " + i + " " + JSON.stringify(audioTrack[i]));
            audioTrack[i].stop();
         }
      }
      var videoTrack = stream.getVideoTracks();
      console.log("audio track num: " + audioTrack.length);
      if (videoTrack.length > 0) {
         for (var i = 0; i < audioTrack.length; i++ ) {
            console.log("disable video track " + i + " " + JSON.stringify(videoTrack[i]));
            videoTrack[i].stop();
         }
      }

   }


   function maybeStop() {
     console.log("maybeStop: " + mStream.isStarted);

     if ( mStream.isStarted == null || mStream.isStarted == false )
        return;

     mStream.isStarted = false;
     mStream.isInitiator = false;
     mStream.isAudioMuted = false;
     mStream.isVideoMuted = false;

     //if ( mStream.localStream.stop ) {
     //   console.log("stop local stream");
     //   mStream.localStream.stop();
     //}
     stopStream(mStream.localStream);
     stopStream(mStream.peerStream);

     mStream.pc.removeStream(mStream.localStream);
     mStream.pc.removeStream(mStream.peerStream);

     mStream.pc.close();
     mStream.pc = null;

     mStream.peerVideo.load();
     mStream.peerVideo.src = '';
     mStream.peerVideo.setAttribute('poster','images/avatar.png');

     mStream.localVideo.load();
     mStream.localVideo.src = '';


  }


   // network callbacks
   function replaycb(msg) {
      console.log("replaycb: " + JSON.stringify(msg));
      if (msg.cmd == globals.SGN_VIDEO ) {
         //console.log("video cmd");
         if ( msg.rc != null ) {
            if (msg.rc == 0 && msg.subcmd === globals.SGN_VIDEO_START ) {
               console.log("start ok");
            }
            if (msg.rc == 0 && msg.subcmd === globals.SGN_VIDEO_VIEW ) {
               console.log("view ok");
            }

         } else {
            if (msg.subcmd === globals.SGN_VIDEO_SDP ) {
               console.log("got offer");
               handleSDP(msg.sdp);
            }
            if (msg.subcmd === globals.SGN_VIDEO_CANDIDATE ) {
               console.log("got remote candidate");
               handleSDP(msg.candidate);
            }
            if (msg.subcmd === globals.SGN_VIDEO_STOP ) {
               console.log("close replay stream");
               maybeStop();
            }
         }

      } else {
         console.log("[ERROR] unknown msg: " + JSON.stringify(msg));
      }


   }

   function handleRemoteHangup() {
     //console.log('Session terminated.');
     maybeStop();
   }

   function doAnswer() {
      // Not implement
      function setLocalAndSendMessage(sessionDescription) {
        // Set Opus as the preferred codec in SDP if Opus is present.
        sessionDescription.sdp = preferOpus(sessionDescription.sdp);
        //console.log("setLocalAndSendMessage: " + mStream.pc);
        mStream.pc.setLocalDescription(sessionDescription);
        sendMessage({'cmd':globals.SGN_VIDEO,'subcmd':globals.SGN_VIDEO_SDP,'roomid': mRoomId,
                                'sdp':sessionDescription});
      }   

      function onError(e) {
         console.log("Failed to create sdp answer: " + JSON.stringify(e));
      }   

     //console.log('Sending answer to peer.');
     if ( mIsVideo == 1 ) {
        console.log('Will send video data');
        mStream.pc.createAnswer(setLocalAndSendMessage, onError, globals.video_sdpConstraints);
     } else {
        console.log('Will not send video data');
        mStream.pc.createAnswer(setLocalAndSendMessage, onError, globals.view_sdpConstraints);
     }
   } 

   function handleSDP(message) {
     console.log("handleSDP: started= " + mStream.isStarted +  ", msg=" + JSON.stringify(message));
     if (message.type === 'offer') {
       console.log("received offer");
       if (!mStream.isInitiator && !mStream.isStarted) {
         maybeStart();
       }
       //FIXME: wait until mStream.pc is created!
       function CheckPeerConnection() {
         if ( mStream.isInitPC && mStream.pc instanceof RTCPeerConnection ) {
            console.log("peerconnection service is ready");
            console.log("peerconnection service," + mStream.isInitPC);
            console.log("peerconnection service," + mStream.pc);
            mStream.pc.setRemoteDescription(new RTCSessionDescription(message));
            doAnswer();
            return;
         }
         else {
            console.log("Wait for peerconnection service," + mStream.isInitPC);
            console.log("Wait for peerconnection service," + mStream.pc);
            setTimeout(CheckPeerConnection,1000);
         }
       }
       CheckPeerConnection();

       //mStream.pc.setRemoteDescription(new RTCSessionDescription(message));
       //doAnswer();
     } else if (message.type === 'answer' && mStream.isStarted) {
       console.log("received answer");
       mStream.pc.setRemoteDescription(new RTCSessionDescription(message));
     } else if (message.type === 'candidate' && mStream.isStarted) {
       var candidate = new RTCIceCandidate({sdpMLineIndex:message.label,
         candidate:message.candidate});
       console.log("received candidate, label=" + message.label);
       mStream.pc.addIceCandidate(candidate);
     } else if (message === 'bye' && mStream.isStarted) {
       //console.log("received bye");
       handleRemoteHangup();
     } else {
       //console.log("received unknown");
     }
   }




   return this;
}

window.Room = Room;  

})(window);


