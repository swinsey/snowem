(function (window) {

function NetService(){
   var globals = window.Globals();
   this.id = 0;
   this.IsInited = 0;
   this.usercb = {};
   this.roomcb = {};
   this.negotiationcb = {};
   this.reportcb = {};

   this.sendMessage = function(message){
      console.log('Client sending message: ', message);
      if (typeof message === 'object') {
         message = JSON.stringify(message);
      }
      this.websocket.send(message);
   };

   // initialize net service
   this.init = function(onsuccess) {
      if ("WebSocket" in window) {
         //console.log("WebSocket is supported by your Browser!");
         // Let us open a web socket
         this.websocket = new WebSocket("wss://"+globals.SGN_IPADDR+":"+globals.SGN_PORT,"default");
         this.websocket.binaryType = 'blob';
         this.websocket.onopen = function(e) {
            console.log("onopen: web socket is opened");
            this.IsInited = 1;
            if (onsuccess) onsuccess();
         };

         this.websocket.onmessage = function (evt) {
            var msg = JSON.parse(evt.data);
            console.log("onmessage: ", evt.data);

            if (msg.cmd == globals.SGN_USER ) {
               this.usercb(msg);
               return;
            }

            if (msg.cmd == globals.SGN_ROOM ) {
               this.roomcb(msg);
               return;
            }

            if (msg.cmd == globals.SGN_NEGOTIATION ) {
               this.negotiationcb(msg);
               return;
            }

            if (msg.cmd == globals.SGN_REPORT ) {
               this.reportcb(msg);
               return;
            }

            console.log("[ERROR] unknown msg: " + JSON.stringify(msg));
            return;

         };

      }
   }

   this.close = function() {
      console.log("close net service");
   }

   this.setUserCB = function(usercb) {
      this.usercb = usercb;
   }

   this.setRoomCB = function(roomcb) {
      this.roomcb = roomcb;
   }

   this.setNegotiationCB = function(negotiationcb) {
      this.negotiationcb = negotiationcb;
   }
   this.setReportCB = function(reportcb) {
      this.reportcb = reportcb;
   }
   
   return this;
}

window.NetService = NetService;

})(window);
