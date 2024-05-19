'use strict';

if (ObjC.available) {
    var NSURLSession = ObjC.classes.NSURLSession;
    var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;

    if (NSURLSession) {
        // Hook the dataTaskWithRequest:completionHandler: method
        var dataTaskWithRequest = NSURLSession['- dataTaskWithRequest:'];
        Interceptor.attach(dataTaskWithRequest.implementation, {
            onEnter: function (args) {
                var request = new ObjC.Object(args[2]);
                var url = request.URL().absoluteString().toString();
                var method = request.HTTPMethod().toString();
                var headers = request.allHTTPHeaderFields();

                const urlHost = url.split("/")[2];
                const urlEndpoint = "/" + url.split("/").slice(3).join("/");

                // Convert headers dictionary to a list of strings
                var headersList = [];
                if (headers) {
                    var keys = headers.allKeys();
                    for (var i = 0; i < keys.count(); i++) {
                        var key = keys.objectAtIndex_(i).toString();
                        var value = headers.objectForKey_(key).toString();
                        headersList.push(key + ": " + value);
                    }
                }

                // Capture the HTTP body if it exists
                var body = null;
                if (method === "POST" || method === "PUT") {
                    var httpBody = request.HTTPBody();
                    if (httpBody) {
                        body = httpBody.bytes().readUtf8String(httpBody.length());
                    }
                }

                const payload = {
                    'method': method,
                    'host':urlHost,
                    'endpoint': urlEndpoint,
                    'request_headers': JSON.stringify(headersList), 
                    'status_code': 200,
                    'response_headers': JSON.stringify(['HTTP/2 200', 'Date: Wed, 15 May 2024 02:49:07 GMT', 'Content-Type: application/json', 'Content-Length: 83']),
                    'response_body': body
                }
                send(JSON.stringify(payload));
            },
            onLeave: function (retval) {
                // Hook the resume method of NSURLSessionDataTask to get the response
                var task = new ObjC.Object(retval);
                var resume = task.resume;
                // console.log(task);
                Interceptor.attach(resume.implementation, {
                    onLeave: function (retval) {
                        // var response = task.response();
                        // if (response) {
                        //     var statusCode = response.statusCode();
                        //     var responseHeaders = response.allHeaderFields();

                        //     // Convert response headers dictionary to a list of strings
                        //     var responseHeadersList = [];
                        //     var responseKeys = responseHeaders.allKeys();
                        //     for (var i = 0; i < responseKeys.count(); i++) {
                        //         var key = responseKeys.objectAtIndex_(i).toString();
                        //         var value = responseHeaders.objectForKey_(key).toString();
                        //         responseHeadersList.push(key + ": " + value);
                        //     }

                        //     var payload = {
                        //         'status_code': statusCode,
                        //         'response_headers': responseHeadersList,
                        //     };
                        //     send(JSON.stringify(payload));
                        // }
                    }
                });
            }
        });
    } else {
        send(JSON.stringify({"error": "NSURLSession class not available!"}));
    }
} else {
    send(JSON.stringify({"error": "Objective-C runtime is not available!"}));
}
