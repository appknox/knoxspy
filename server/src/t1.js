📦
1085 /intercept.js.map
1869 /intercept.js
✄
{"version":3,"file":"intercept.js","sourceRoot":"/home/ajay/Projects/MDM/server/src/","sources":["intercept.js"],"names":[],"mappings":"AACA,wBAAwB;AACxB,iDAAiD;AACjD,oEAAoE;AACpE,oEAAoE;AACpE,0FAA0F;AAC1F,kLAAkL;AAClL,iFAAiF;AACjF,qCAAqC;AACrC,qDAAqD;AACrD,kDAAkD;AAClD,yDAAyD;AACzD,sDAAsD;AACtD,+CAA+C;AAC/C,uCAAuC;AACvC,oCAAoC;AACpC,YAAY;AACZ,UAAU;AACV,IAAI;AACJ,2BAA2B;AAC3B,IAAI,SAAS,GAAG,OAAO,CAAC,WAAW,CAAC,CAAC;AACrC,8BAA8B;AAC9B,IAAI,KAAK,GAAG,yBAAyB,CAAC;AACtC,gCAAgC;AAChC,IAAI,QAAQ,GAAG,IAAI,SAAS,CAAC,KAAK,CAAC,CAAC;AACpC,wDAAwD;AACxD,QAAQ,CAAC,EAAE,CAAC,MAAM,EAAE;IAChB,OAAO,CAAC,GAAG,CAAC,uCAAuC,CAAC,CAAC;IACrD,+BAA+B;IAC/B,QAAQ,CAAC,IAAI,CAAC,gBAAgB,CAAC,CAAC;AACpC,CAAC,CAAC,CAAC;AACH,gEAAgE;AAChE,QAAQ,CAAC,EAAE,CAAC,SAAS,EAAE,UAAU,OAAO;IACpC,OAAO,CAAC,GAAG,CAAC,0BAA0B,EAAE,OAAO,CAAC,QAAQ,CAAC,CAAC;AAC9D,CAAC,CAAC,CAAC;AACH,6DAA6D;AAC7D,QAAQ,CAAC,EAAE,CAAC,OAAO,EAAE;IACjB,OAAO,CAAC,GAAG,CAAC,kCAAkC,CAAC,CAAC;AACpD,CAAC,CAAC,CAAC;AACH,sCAAsC;AACtC,QAAQ,CAAC,EAAE,CAAC,OAAO,EAAE,UAAU,KAAK;IAChC,OAAO,CAAC,KAAK,CAAC,sBAAsB,EAAE,KAAK,CAAC,CAAC;AACjD,CAAC,CAAC,CAAC"}
✄
// if (ObjC.available) {
//     // Define the classes we are interested in
//     var AFHTTPSessionManager = ObjC.classes.AFHTTPSessionManager;
//     var NSURLSessionDataTask = ObjC.classes.NSURLSessionDataTask;
//     // Hook the method 'dataTaskWithRequest:completionHandler:' of AFHTTPSessionManager
//     var dataTaskWithRequest_completionHandler = AFHTTPSessionManager['- dataTaskWithHTTPMethod:URLString:parameters:headers:uploadProgress:downloadProgress:success:failure:'];
//     Interceptor.attach(dataTaskWithRequest_completionHandler.implementation, {
//         onEnter: function (args) {
//             var method = new ObjC.Object(args[2]);
//             var url = new ObjC.Object(args[3]);
//             var parameters = new ObjC.Object(args[4]);
//             var headers = new ObjC.Object(args[5]);
//             console.log(`${method} ${url}`);
//             console.log(parameters);
//             console.log(headers);
//         }
//     });
// }
// Import necessary modules
var WebSocket = require('websocket');
// URL of the WebSocket server
var wsUrl = 'ws://example.com/socket';
// Create a new WebSocket client
var wsClient = new WebSocket(wsUrl);
// Event listener for when the connection is established
wsClient.on('open', function () {
    console.log('[*] WebSocket connection established.');
    // Send a message to the server
    wsClient.send('Hello, server!');
});
// Event listener for when a message is received from the server
wsClient.on('message', function (message) {
    console.log('[*] Message from server:', message.utf8Data);
});
// Event listener for when the WebSocket connection is closed
wsClient.on('close', function () {
    console.log('[*] WebSocket connection closed.');
});
// Event listener for WebSocket errors
wsClient.on('error', function (error) {
    console.error('[!] WebSocket error:', error);
});