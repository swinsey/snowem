(function(){
   var script = document.createElement('script');
   function getBaseUrl(filename) {
      var scriptElements = document.getElementsByTagName('script');
      for (var i = 0; i < scriptElements.length; i++) {
         var source = scriptElements[i].src;
         if (source.indexOf(filename) > -1) {
            var location = source.substring(0, source.indexOf(filename)) + filename;
            return location;
         }
      }
      return false;
   }      
   var url = getBaseUrl("app.js").replace("app.js","snowsdk.js");
 
   //script.src = window.location.protocol+ '//' 
   //             + window.location.hostname 
   //             + '/js/snowsdk.js';
   script.src = url;
   console.log("script src: " + script.src);
   script.async = true;
   var entry = document.getElementsByTagName('script')[0];
   entry.parentNode.insertBefore(script, entry);
})();

window.snowAsyncInit = function() {
   SnowSDK.init(function (){
      var isPublisher = 0;
      var channelid = 0;
      var channelid1 = 0;
      var channelid2 = 0;
      var peer = null;
      var config = {
         'servername': "media.snowem.io",
         'port': 443
      };

      function onPublishChannelCreated(peer) {
         console.log("onPublishChannelCreate: peer=" + JSON.stringify(peer));
         document.getElementById("yourId").innerHTML = peer.peerId;
         var settings = {
            'channelid': channelid,
            'localVideoId': document.getElementById('localVideo'),
            'remoteVideoId': null
         };

         peer.publish(settings);
      }

      //API calls go here.
      $("#publishBtn").click(function() {
         isPublisher = 1;
         $("#floatDiv").hide();
         //$("#publishVideoDiv").attr('class','col-md-6');
         $("#publishDiv").append('<div class="text-center"> Your webcam\'s channel id: <span style="color:#FF0000" id="yourId"></span></div>');
         peer = SnowSDK.createPeer(config);
         peer.createChannel({name: "demo"},onPublishChannelCreated);
      });

      function onPlayChannelCreated(peer) {
         console.log("onCreate: peer=" + JSON.stringify(peer));
         var settings = {
            'channelid': channelid,
            'localVideoId': null,
            'remoteVideoId': document.getElementById('playRemoteVideo')
         };

         peer.play(settings);
      }
      $("#playBtn").click(function() {
         channelid = parseInt(document.getElementById("playChannelId").value);
         isPublisher = 0;
         $("#playBtnDiv").hide();
         peer = SnowSDK.createPeer(config);
         peer.createChannel({name: "demo"},onPlayChannelCreated);
      });

      function onPlayChannelCreated1(peer) {
         console.log("onCreate: peer=" + channelid1);
         var settings = {
            'channelid': channelid1,
            'localVideoId': null,
            'remoteVideoId': document.getElementById('playRemoteVideo1')
         };

         peer.play(settings);
      }
      $("#playBtn1").click(function() {
         channelid1 = parseInt(document.getElementById("playChannelId1").value);
         isPublisher = 0;
         $("#playBtnDiv1").hide();
         peer = SnowSDK.createPeer(config);
         peer.createChannel({name: "demo"},onPlayChannelCreated1);
      });

      function onPlayChannelCreated2(peer) {
         console.log("onCreate: peer=" + JSON.stringify(peer));
         var settings = {
            'channelid': channelid2,
            'localVideoId': null,
            'remoteVideoId': document.getElementById('playRemoteVideo2')
         };

         peer.play(settings);
      }
      $("#playBtn2").click(function() {
         channelid2 = parseInt(document.getElementById("playChannelId2").value);
         isPublisher = 0;
         $("#playBtnDiv2").hide();
         peer = SnowSDK.createPeer(config);
         peer.createChannel({name: "demo"},onPlayChannelCreated2);
      });


   })
}

