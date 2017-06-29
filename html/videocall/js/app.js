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
        var is_publisher = 0;
        var roomid = 0;

        SnowSDK.listen('onCreate', function(agent) {
           console.log("onCreate: agent=" + JSON.stringify(agent));
           document.getElementById("yourId").innerHTML = agent.peerId;
           agent.connect({name: "demo"});
        });

        SnowSDK.listen('onIceConnected', function(agent) {
           console.log("ice connected: agent=" + JSON.stringify(agent));
           if (is_publisher) {
              agent.publish({'name': "demo", 'channelid': roomid});
           } else {
              agent.play({'name': "demo", 'channelid': roomid});
           }
        });

        //API calls go here.
        document.getElementById("publishBtn").addEventListener("click", function() {
           //var channelId = SnowSDK.getAvailableChannel();
           //SnowSDK.publish({channel_id: channelId});
           is_publisher = 1;
           SnowSDK.create();
        });

        document.getElementById("subscribeBtn").addEventListener("click", function() {
           //var channelId = SnowSDK.getAvailableChannel();
           //SnowSDK.publish({channel_id: channelId});
           roomid = parseInt(document.getElementById("subscribeRoomId").value);
           SnowSDK.create();
        });
     }

     SnowSDK.init({api_key: "demo", version: "version"}, onSuccess);
}

