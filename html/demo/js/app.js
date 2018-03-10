// Code goes here

'use strict';
var MEDIA_IPADDR = "media.peercall.vn";
var MEDIA_PORT = 443;
var SNW_DEMO = 0x44454D4F;
var SNW_DEMO_CONNECT = 1;
var SNW_DEMO_JOIN_ROOM = 2;
var SNW_DEMO_ROOM_READY = 3;
var SNW_DEMO_ICE_START = 4;
var SNW_DEMO_ICE_SDP = 5;
var SNW_DEMO_ICE_CANDIDATE = 6;
var SNW_DEMO_MSG = 7;

var constraints = { audio: true,
                                video: {
                                  mandatory:{
                                     maxWidth: 480,
                                     maxHeight: 270,
                                     minWidth: 480,
                                     minHeight: 270 
                              }}};


var pcConfig = {'iceServers':[{'urls':'stun:peercall.vn:8478'},
                                {'urls':'turn:peercall.vn:8479','credential':'webrtc', 'username':'webrtc'}],
                'iceTransports': 'relay'};
/*var pcConstraints = {'mandatory': {
           'OfferToReceiveAudio':true,
           'OfferToReceiveVideo':true }}; */
var pcConstraints = { 
          'optional': [
            {'DtlsSrtpKeyAgreement': true},
            {'RtpDataChannels': true}
        ]}; 

var app = angular.module('demo-app', ['angular-websocket', 'app.controllers', 'app.services', 'ui.bootstrap']);

//Setting up the app
app.config([ '$routeProvider', function( $routeProvider ) {

    // routes
    $routeProvider.
        when('/', {
            templateUrl: 'room.html',
            controller: 'MainCtrl'
        }).
        when('/:roomid/:flowid', {
            templateUrl: 'call.html',
            controller: 'MainCtrl'}).
        otherwise({
            redirectTo: '/drinks', 
            templateUrl: 'drinks_list.html',
            controller: 'MainCtrl'
        });

}]);

app.directive('myEnter', function () {
    return function (scope, element, attrs) {
        element.bind("keydown keypress", function (event) {
            if(event.which === 13) {
                scope.$apply(function (){
                    scope.$eval(attrs.myEnter);
                });

                event.preventDefault();
            }
        });
    };
});

//Models
app.factory('Room', function($websocket) {
      var ws = $websocket('wss://'+ MEDIA_IPADDR + ':' + MEDIA_PORT + '/default');
      ws.onOpen(function(message) {
         console.log("websocket connected");
         ws.send({'msgtype': SNW_DEMO, 'api': SNW_DEMO_CONNECT});
      });

      ws.onMessage(function(evt) {
         //console.log("on message cb");
         if (room.OnMessageCB) room.OnMessageCB(evt);
      });

      var room = {};
      room.roomid = 0;
      room.flowid = 0;
      room.peerid = 0;
      room.OnMessageCB = null;
      room.ws = ws;
      room.send = function(msg) {
         console.log("Sending message: " + JSON.stringify(msg));
         if (typeof message === 'object') {
            msg = JSON.stringify(msg);
         }
         ws.send(msg);
      }


      room.isStarted = false;
      room.isChannelReady = false;
      room.isInitiator = false;
      room.localVideo = null;
      room.remoteVideo = null;
      room.localStream = null;
      room.remoteStream = null;
      room.pc = null;

function handleIceCandidate(event) {
  console.log('icecandidate event: ', event);
  if (event.candidate) {
    room.send({'msgtype':SNW_DEMO, 'api': SNW_DEMO_ICE_CANDIDATE,
      'flowid': room.flowid, 'peerid': room.peerid,
      'candidate': {
      type: 'candidate',
      label: event.candidate.sdpMLineIndex,
      id: event.candidate.sdpMid,
      candidate: event.candidate.candidate}
    });
  } else {
    console.log('End of candidates.');
  }
}

function handleRemoteStreamAdded(event) {
  console.log('Remote stream added.');
  room.remoteVideo.src = window.URL.createObjectURL(event.stream);
  room.remoteStream = event.stream;
}

function handleCreateOfferError(event) {
  console.log('createOffer() error: ', event);
}

function handleRemoteStreamRemoved(event) {
  console.log('Remote stream removed. Event: ', event);
}

function createPeerConnection() {
  try {
    //room.pc = new RTCPeerConnection(pcConfig, null);
    room.pc = new RTCPeerConnection(pcConfig,pcConstraints);
    room.pc.onicecandidate = handleIceCandidate;
    room.pc.onaddstream = handleRemoteStreamAdded;
    room.pc.onremovestream = handleRemoteStreamRemoved;
    console.log('Created RTCPeerConnnection');
  } catch (e) {
    console.log('Failed to create PeerConnection, exception: ' + e.message);
    alert('Cannot create RTCPeerConnection object.');
    return;
  }
}

function setLocalAndSendMessage(sessionDescription) {
  // Set Opus as the preferred codec in SDP if Opus is present.
  //  sessionDescription.sdp = preferOpus(sessionDescription.sdp);
  room.pc.setLocalDescription(sessionDescription);
  console.log('setLocalAndSendMessage sending message', sessionDescription);
  //sendMessage(sessionDescription);
  //room.send({'msgtype':SNW_DEMO,'api':SNW_DEMO_ICE_START,'roomid':room.roomid,
  //           'creatorid':room.flowid,'peerid':room.peerid});
  room.send({'msgtype':SNW_DEMO,'api':SNW_DEMO_ICE_SDP,'roomid':room.roomid,
             'creatorid':room.flowid,'peerid':room.peerid,'sdp':sessionDescription});
}

function doCall() {
  console.log('Sending offer to peer');
  room.pc.createOffer(setLocalAndSendMessage, handleCreateOfferError);
}

function maybeStart() {
  console.log('>>>>>>> maybeStart() ', room.isStarted, room.localStream, room.isChannelReady);
  if (!room.isStarted && room.localStream !== null && room.isChannelReady) {
    console.log('>>>>>> creating peer connection');
    createPeerConnection();
    console.log("log create");
    room.pc.addStream(room.localStream);
    room.isStarted = true;
    console.log("isInitiator: " + room.isInitiator);
    if (room.isInitiator) {
      console.log("isInitiator: " + room.isInitiator);
      doCall();
    }
  }
}

function gotStream(stream) {
  console.log('Adding local stream.');
  room.localVideo = document.querySelector('#localVideo');
  room.remoteVideo = document.querySelector('#remoteVideo');
  room.localVideo.src = window.URL.createObjectURL(stream);
  room.localStream = stream;
  //sendMessage('got user media');
  if (room.isInitiator) {
    console.log("room.isInitiator: " + room.isInitiator);
    maybeStart();
  }
}

function onCreateSessionDescriptionError(error) {
  trace('Failed to create session description: ' + error.toString());
}

function doAnswer() {
  console.log('Sending answer to peer.');
  room.pc.createAnswer().then(
    setLocalAndSendMessage,
    onCreateSessionDescriptionError
  );  
}

function handle_sdp(sdp) {
   console.log("sdp: " + JSON.stringify(sdp));
   if (sdp.type === 'offer') {
      if (!room.isInitiator && !room.isStarted) {
         console.log("maybe start");
         maybeStart();
      }
      room.pc.setRemoteDescription(new RTCSessionDescription(sdp));
      doAnswer();
   } else if (sdp.type === 'answer') {
      room.pc.setRemoteDescription(new RTCSessionDescription(sdp));
   } else if (sdp.type === 'candidate') {
      var candidate = new RTCIceCandidate({
                  sdpMLineIndex: sdp.label,
                  candidate: sdp.candidate
          });
      room.pc.addIceCandidate(candidate);
   } else {
   }
}

      room.startStream = function() {
         console.log("start stream");
         navigator.mediaDevices.getUserMedia({
            audio: true,
            //video: true
            video: {
              mandatory:{
                 maxWidth: 480,
                 maxHeight: 270,
                 minWidth: 480,
                 minHeight: 270 
              }}
         })
         .then(gotStream)
         .catch(function(e) {
           alert('getUserMedia() error: ' + e.name);
         });
      }


      room.setOnMessageCB = function(cb) {
         room.OnMessageCB = cb;
      }

      room.setOnMessageCB(function(evt) {
         var msg = JSON.parse(evt.data);
         console.log('Client received message:' + JSON.stringify(msg));
         if (msg.rc != null && msg.msgtype == SNW_DEMO ) {
            console.log('response message:' + JSON.stringify(msg));
            if (msg.rc != 0)
               return;
            if (msg.api == SNW_DEMO_CONNECT) {
               room.roomid = msg.room;
               room.flowid = msg.id;
               console.log("roomid:" + room.roomid);
               console.log("flowid:" + room.flowid);
            }
            if (msg.api == SNW_DEMO_JOIN_ROOM) {
               console.log("channel ready");
               room.isChannelReady = true;
            }
         } else if (msg.msgtype == SNW_DEMO) {
            if (msg.api == SNW_DEMO_ROOM_READY) {
               if (room.flowid == msg.creatorid ) {
                  console.log("creator room ready: " + JSON.stringify(msg));
                  room.isInitiator = true;
                  room.peerid = msg.peerid;
                  //room.startStream();
                  maybeStart();
               } else if (room.flowid == msg.peerid) {
                  console.log("peerid room ready");
                  room.peerid = msg.creatorid;
                  maybeStart();
               }
            }
            /*if (msg.api == SNW_DEMO_ICE_START) {
               console.log("ice start");
               room.creatorid = msg.creatorid;
               maybeStart();
            }*/
            if (msg.api == SNW_DEMO_ICE_SDP) {
               console.log("got sdp: " + JSON.stringify(msg.sdp));
               handle_sdp(msg.sdp);
            }
            if (msg.api == SNW_DEMO_ICE_CANDIDATE) {
               console.log("got candidate: " + JSON.stringify(msg.candidate));
               handle_sdp(msg.candidate);
            }
            if (msg.api == SNW_DEMO_MSG) {
               console.log("got msg: " + JSON.stringify(msg.candidate));
               handle_msg("Friend",msg.msg);
            }
         }

      });
      
      room.msgs = [];
      /*var msg = {};
      msg.name = "You";
      msg.msg = "Hello!";
      room.msgs.push(msg);
      msg = {};
      msg.name = "Peer";
      msg.msg = "Hi, how are you?";
      room.msgs.push(msg);
      console.log("msgs: " + JSON.stringify(room.msgs));*/
      room.getMsgs = function() {
         return room.msgs;
      }

      room.sendMsg = function() {
         var data = {};
         data.msgtype = SNW_DEMO;
         data.api = SNW_DEMO_MSG;
         data.msg = room.msg;
         data.peerid = room.peerid;
         ws.send(data);
         handle_msg("You",room.msg);
         room.msg = "";
      }
      function handle_msg(name,data) {
         var msg = {};
         msg.name = name;
         msg.msg = data;
         room.msgs.push(msg);
         var objDiv = document.getElementById("chat_msg_id");
         objDiv.scrollTop = objDiv.scrollHeight;
      }

      return room;
});

//CONTROLLERS
var controllers = angular.module('app.controllers',[]);

controllers.controller('MainCtrl', function( $scope, $location, $routeParams, Room, Drink)  {
  $scope.Room = Room;

 
  if ($routeParams.roomid) {
    // get the detail info
    $scope.Room.roomid = parseInt($routeParams.roomid);
    $scope.Room.flowid = parseInt($routeParams.flowid);
    if ($routeParams.roomid == 0) {
      console.log("roomid is zero");
    } else {
      console.log("join room: roomid=" + $scope.Room.roomid + " flowid=" + $scope.Room.flowid);
      $scope.Room.send({'msgtype':SNW_DEMO,'api': SNW_DEMO_JOIN_ROOM, 
        'roomid': parseInt($routeParams.roomid), 
        'flowid': parseInt($routeParams.flowid)});
      Room.startStream();
    }
    
    // all three functions just cancel because can't do saves.
    $scope.cancel = function() {
      $location.path('/');
    }

    $scope.sendMsg = function() {
       console.log("enter pressed: " + $scope.Room.msg);
       $scope.Room.sendMsg();

    }

    $scope.getMsgs = function() {
       return $scope.Room.getMsgs();
    }
  
  } else {
    // get the list info
    console.log("room page");
    $scope.joinRoom = function(rid,fid) {
        var newRoute = "/" + rid + "/" + fid;
        $location.path( newRoute );
    };

  }
});

//SERVICES
var services = angular.module('app.services', [])

services.factory( 'Drink', function($http) {
    var Drink = function(data) { angular.extend(this, data); };

    Drink.get = function(drink) {
        return $http.get('drink.json').then(function(response) { return response.data; });
    };

    Drink.list = function() {
        return $http.get('drinks.json').then(function(response, status) { return response.data; })
    };

    return Drink;
});
