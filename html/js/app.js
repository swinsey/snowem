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
      var peer = null;
      var config = {
         'servername': "media.peercall.vn",
         'port': 443
      };

      function onPublishChannelCreated(peer) {
         console.log("onPublishChannelCreate: peer=" + JSON.stringify(peer));
         document.getElementById("yourId").innerHTML = peer.peerId;
         var settings = {
            'channelid': channelid,
            'localVideoId': document.getElementById('localVideo'),
            'remoteVideoId': null
            //'remoteVideoId': document.getElementById('remoteVideo')
         };

         peer.publish(settings);
      }

      //API calls go here.
      document.getElementById("publishBtn").addEventListener("click", function() {
         isPublisher = 1;
         peer = SnowSDK.createPeer(config);
         peer.createChannel({name: "demo"},onPublishChannelCreated);
      });

      function onPlayChannelCreated(peer) {
         console.log("onCreate: peer=" + JSON.stringify(peer));
         document.getElementById("yourId").innerHTML = peer.peerId;
         var settings = {
            'channelid': channelid,
            //'localVideoId': document.getElementById('playLocalVideo'),
            'localVideoId': null,
            'remoteVideoId': document.getElementById('playRemoteVideo')
         };

         peer.play(settings);
      }


      document.getElementById("subscribeBtn").addEventListener("click", function() {
         channelid = parseInt(document.getElementById("subscribeChannelId").value);
         isPublisher = 0;
         peer = SnowSDK.createPeer(config);
         peer.createChannel({name: "demo"},onPlayChannelCreated);
      });
   })
}

