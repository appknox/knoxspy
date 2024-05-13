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
'use strict';

// Define the WebSocket URL
const wsUrl = 'ws://example.com/socket';

// Create a new WebSocket instance
const ws = new WebSocket(wsUrl);

// Event listener for when the WebSocket connection is established
ws.onopen = function () {
    console.log('[*] WebSocket connection established.');

    // Send a message to the server
    ws.send('Hello, server!');
};

// Event listener for when a message is received from the server
ws.onmessage = function (event) {
    console.log('[*] Message from server:', event.data);
};

// Event listener for WebSocket errors
ws.onerror = function (error) {
    console.error('[!] WebSocket error:', error);
};

// Event listener for WebSocket connection closure
ws.onclose = function () {
    console.log('[*] WebSocket connection closed.');
};

// Declare the WebSocket class to avoid 'WebSocket is not defined' error
function WebSocket(url) {
    const ws = new ObjC.classes.NSURL.URLWithString_(ObjC.classes.NSString.stringWithString_(url));
    const request = ObjC.classes.NSURLRequest.requestWithURL_(ws);
    const delegate = new ObjC.Object({
        'connection:didReceiveData:': function (conn, data) {
            const str = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
            console.log(str.toString());
        },
        'connection:didFailWithError:': function (conn, error) {
            console.error(error.toString());
        },
        'connection:didReceiveResponse:': function (conn, response) {
            console.log('Connection established.');
        }
    });
    const connection = ObjC.classes.NSURLConnection.connectionWithRequest_delegate_(request, delegate);
    connection.start();
}
