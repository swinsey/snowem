(function(){
     var script = document.createElement('script');
     script.src = 'https://sdk.peercall.vn/sdk/widget.js?apikey=1235';
     script.async = true;
     var entry = document.getElementsByTagName('script')[0];
     entry.parentNode.insertBefore(script, entry);
})();

window.peerCallAsyncInit = function() {
     PeerCall.init(
        {api_key: "demo", version: "version"},
        function() {
           var is_publisher = 0;
           var roomid = 0;

           PeerCall.listen('onCreate', function(agent) {
              console.log("onCreate: agent=" + JSON.stringify(agent));
              document.getElementById("yourId").innerHTML = agent.peerId;
              agent.connect({name: "demo"});
           });

           PeerCall.listen('onIceConnected', function(agent) {
              console.log("ice connected: agent=" + JSON.stringify(agent));
              if (is_publisher) {
                 agent.publish({'name': "demo", 'channelid': roomid});
              } else {
                 agent.play({'name': "demo", 'channelid': roomid});
              }
           });

           //API calls go here.
           document.getElementById("publishBtn").addEventListener("click", function() {
              //var channelId = PeerCall.getAvailableChannel();
              //PeerCall.publish({channel_id: channelId});
              is_publisher = 1;
              PeerCall.create();
           });

           document.getElementById("subscribeBtn").addEventListener("click", function() {
              //var channelId = PeerCall.getAvailableChannel();
              //PeerCall.publish({channel_id: channelId});
              roomid = parseInt(document.getElementById("subscribeRoomId").value);
              PeerCall.create();
           });

        }
     );
}

