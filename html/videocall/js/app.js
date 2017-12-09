(function(){
   var script = document.createElement('script');
   script.src = window.location.protocol+ '//' 
                + window.location.hostname 
                + '/videocall/js/snowsdk.js';
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

      function onChannelCreated(peer) {
         console.log("onCreate: peer=" + JSON.stringify(peer));
         document.getElementById("yourId").innerHTML = peer.peerId;
         var config = {
            'channelid': channelid,
            'localVideoId': document.getElementById('localVideo'),
            'remoteVideoId': document.getElementById('remoteVideo')
         };

         if (isPublisher) {
            peer.publish(config);
         } else {
            peer.play(config);
         }
      }

      //API calls go here.
      document.getElementById("publishBtn").addEventListener("click", function() {
         isPublisher = 1;
         peer = SnowSDK.createPeer(config);
         peer.createChannel({name: "demo"},onChannelCreated);
      });

      document.getElementById("subscribeBtn").addEventListener("click", function() {
         channelid = parseInt(document.getElementById("subscribeChannelId").value);
         isPublisher = 0;
         peer = SnowSDK.createPeer(config);//create peer peer
         peer.createChannel({name: "demo"},onChannelCreated);
      });
   })
}

