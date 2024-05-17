Java.perform(function() {
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    OkHttpClient.newCall.overload('okhttp3.Request').implementation = function(request) {
        var requestUrl = request.url().toString();
        var method = request.method().toString();
        const requestList = requestUrl.split("/");
        const requestHost = requestList[2];
        const  urlEndpoint = "/" + requestList.slice(3).join("/");
        const tmpPayload = {
            'method': method,
            'host':requestHost,
            'endpoint': requestUrl,
            'request_headers': JSON.stringify(['Content-Type: application/json', 'Host: jsonplaceholder.typicode.com']), 
            'status_code': 200,
            'response_headers': JSON.stringify(['HTTP/2 200', 'Date: Wed, 15 May 2024 02:49:07 GMT', 'Content-Type: application/json', 'Content-Length: 83']),
            'response_body': '{"userId": 1,"id": 1,"title": "delectus aut autem","completed": false}'
        }
        send(JSON.stringify(tmpPayload))
        return this.newCall(request);    
}
});
