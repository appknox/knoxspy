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
            const payload = {'method': method, 'host': urlHost, 'url': urlEndpoint, 'status': 200, 'length': 5000};
            send(JSON.stringify(payload))
        }
    });
}
