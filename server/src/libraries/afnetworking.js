'use strict';

if (ObjC.available) {
    var AFHTTPSessionManager = ObjC.classes.AFHTTPSessionManager;
    var NSURLSessionDataTask = ObjC.classes.NSURLSessionDataTask;
    
    var dataTaskWithRequest = AFHTTPSessionManager['- dataTaskWithHTTPMethod:URLString:parameters:headers:uploadProgress:downloadProgress:success:failure:'];
    Interceptor.attach(dataTaskWithRequest.implementation, {
        onEnter: function (args) {
            var method = new ObjC.Object(args[2]).toString();
            var url = new ObjC.Object(args[3]).toString();

            const urlHost = url.split("/")[2];
            const urlEndpoint = "/" + url.split("/").slice(3).join("/");

            // console.log(method);
            // console.log(urlHost);

            // console.log(urlEndpoint);
            const tmpPayload = {
                'method': method,
                'host':urlHost,
                'endpoint': urlEndpoint,
                'request_headers': JSON.stringify(['Content-Type: application/json', 'Host: jsonplaceholder.typicode.com']), 
                'status_code': 200,
                'response_headers': JSON.stringify(['HTTP/2 200', 'Date: Wed, 15 May 2024 02:49:07 GMT', 'Content-Type: application/json', 'Content-Length: 83']),
                'response_body': '{"userId": 1,"id": 1,"title": "delectus aut autem","completed": false}'
            }
            // const payload = {'method': method, 'host': urlHost, 'url': urlEndpoint, 'status': 200, 'length': 5000};
            send(JSON.stringify(tmpPayload))
        }
    });
}



