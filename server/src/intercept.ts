'use strict';

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
const WebSocket = require('websocket');

// URL of the WebSocket server
const wsUrl = 'ws://example.com/socket';

// Create a new WebSocket client
const wsClient = new WebSocket(wsUrl);

// Event listener for when the connection is established
wsClient.on('open', function() {
    console.log('[*] WebSocket connection established.');

    // Send a message to the server
    wsClient.send('Hello, server!');
});

// Event listener for when a message is received from the server
wsClient.on('message', function(message) {
    console.log('[*] Message from server:', message.utf8Data);
});

// Event listener for when the WebSocket connection is closed
wsClient.on('close', function() {
    console.log('[*] WebSocket connection closed.');
});

// Event listener for WebSocket errors
wsClient.on('error', function(error) {
    console.error('[!] WebSocket error:', error);
});