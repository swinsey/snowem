
/*(function(){
   function loadStylesheet(url) {
      var link = document.createElement('link');
      link.rel  = 'stylesheet';
      link.type = 'text/css';
      link.href = url;
      var entry = document.getElementsByTagName('script')[0];
      entry.parentNode.insertBefore(link, entry);
   }


   function getScriptUrl(re) {
      var scripts = document.getElementsByTagName('script'),
         element,
         src;

      for (var i = 0; i < scripts.length; i++) {
         element = scripts[i];
       
         src = element.getAttribute ? 
            element.getAttribute('src') : el.src;

         if (src && re.test(src)) {
            return src;
         }
      } 
      return null;
   }

   function getQueryParameters(query) {

      var args   = query.split('&'),
           params = {},
           pair, 
           key, 
           value;

      function decode(string) {
         return decodeURIComponent(string || "")
            .replace('+', ' ');
      }
       
      for (var i = 0; i < args.length; i++) {
         pair  = args[i].split('=');
         key   = decode(pair.shift());
         value = decode(pair ? pair[0] : null);
           
         params[key] = value;
      }
      return params;
   };

   var url  = getScriptUrl(/\/widget\.js/);
   var params = getQueryParameters(url.replace(/^.*\?/, ''));
   console.log("got url: " + url);
   console.log("got params: " + JSON.stringify(params));


})();*/

// loading widget
/*(function(){
   console.log("widget loaded");

   function loadSupportingFiles(callback) {
      console.log("load supporing files");
      callback();
   }
   function getWidgetParams() {
      console.log("get widget params");
   }
   function getRatingData(params, callback) {
      console.log("get rating data");
      callback();
   }
   function drawWidget() {
      console.log("draw widget");
   }

   loadSupportingFiles(function() {
      var params = getWidgetParams();
      getRatingData(params, function() {
         drawWidget();
      });
   });


})();*/


// declare PeerCall namespace
(function(window, undefined) {
   var PeerCall = {};

   if (window.PeerCall) {
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

   PeerCall.init = function(config, callback) {
      console.log("api_key: " + config.api_key);
      console.log("version: " + config.version);
      loadScript('https://local.peercall.vn/sdk/lib.js', callback);
   }
   window.PeerCall = PeerCall;
   
   // call user-defined callback if needed
   if (typeof window.peerCallAsyncInit === 'function') {
      window.peerCallAsyncInit();
   }

})(this);



