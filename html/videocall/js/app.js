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
     function onSuccess() {
        var isPublisher = 0;
        var roomid = 0;
        var peer = null;

        function onCreate() {
           console.log("onCreate: peer=" + JSON.stringify(peer));
           document.getElementById("yourId").innerHTML = peer.peerId;
           peer.connect({name: "demo"});
        }

        //TODO: remove this
        function onIceConnected() {
           console.log("ice connected: peer=" + JSON.stringify(peer));
           if (isPublisher) {
              peer.publish({'name': "demo", 'channelid': roomid});
           } else {
              peer.play({'name': "demo", 'channelid': roomid});
           }
        }

        //API calls go here.
        document.getElementById("publishBtn").addEventListener("click", function() {
           //var channelId = SnowSDK.getAvailableChannel();
           isPublisher = 1;
           peer = SnowSDK.createPeer();
           peer.listen('onCreate',onCreate);
           peer.listen('onIceConnected',onIceConnected);
           peer.create({name: "demo"});
        });

        document.getElementById("subscribeBtn").addEventListener("click", function() {
           //var channelId = SnowSDK.getAvailableChannel();
           roomid = parseInt(document.getElementById("subscribeRoomId").value);
           peer = SnowSDK.createPeer();//create peer peer
           peer.listen('onCreate',onCreate);
           peer.create('onIceConnected',onIceConnected);
        });
     }

     SnowSDK.init({api_key: "demo", version: "version"}, onSuccess);
}

