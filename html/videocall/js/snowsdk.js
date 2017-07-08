// declare SnowSDK namespace
(function(window, undefined) {
   var SnowSDK = {};

   if (window.SnowSDK) {
      return;
   }

   function loadScript(url, callback) {
      var script = document.createElement('script');
      script.async = true;
      script.src = url;
      var entry = document.getElementsByTagName('script')[0];
      entry.parentNode.insertBefore(script, entry);

      console.log("loading script: " + url);
      script.onload = script.onreadystatechange = function() {
         var rdyState = script.readyState;
         if (!rdyState || /complete|loaded/.test(script.readyState)) {
            console.log("script loaded: " + url);
            callback();
            script.onload = null;
            script.onreadystatechange = null;
         }
      }
      //script.addEventListener("load",function() {
      //   console.log("script loaded: " + url);
      //}, false);
   }

   SnowSDK.init = function(callback) {
      loadScript(window.location.protocol + '//' + window.location.hostname +
                 '/videocall/js/snowcore.js', callback);
   }
   window.SnowSDK = SnowSDK;
   
   // call user-defined callback if needed
   if (typeof window.snowAsyncInit === 'function') {
      console.log("snowAsynInit");
      window.snowAsyncInit();
   }

})(this);



