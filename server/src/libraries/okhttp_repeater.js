Java.perform(function() {
    recv('sendRequest', function(message) {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var RequestBuilder = Java.use('okhttp3.Request$Builder');
        var client = OkHttpClient.$new();
        var payload = message.payload.data;
        var body = payload.request_body;
        var url = payload.endpoint;
        if (payload.method == 'POST') {
            var request = makePostRequest(url,body)
        } else {
            var request = RequestBuilder.$new()
            .url(url)
            .build();
        }
        var response = client.newCall(request).execute();
        var responseHeaders = response.headers();
        var responseHeaderNames = responseHeaders.names();
        var responseHeaderNamesArray = responseHeaderNames.toArray();
        var responseStatus = response.code();
        var responseMessage = response.message();
        var responseProtocol = response.protocol().toString();
        var respHeaders = [`${responseProtocol.toUpperCase()} ${responseStatus} ${responseMessage}`];
        for (var i = 0; i < responseHeaderNamesArray.length; i++) {
            var responseHeaderName = responseHeaderNamesArray[i];
            var responseHeaderValue = responseHeaders.get(responseHeaderName);
            var finalValue = `${responseHeaderName}: ${responseHeaderValue}`;
            respHeaders.push(finalValue);
        }
        var responseBodyString = '';
        var responseBody = response.body();
        if (responseBody !== null) {
            if (response.isSuccessful()) {
                responseBodyString = responseBody.string();
            } 
            else {
                console.log("Error: Response not successful");
                }
            } else {
            console.log("Error: Empty response body");
        }
        const tmpPayload = {
                "method": payload.method,
                "host":payload.host,
                "endpoint": payload.endpoint,
                "request_headers": payload.request_headers,
                "request_body": payload.request_body,
                "status_code": payload.status_code,
                "session_id": payload.session_id,
                "response_headers": JSON.stringify(respHeaders),
                "response_body": responseBodyString
            }
        send(JSON.stringify(tmpPayload));
        })

function makePostRequest(url, request_body){
    var MediaType = Java.use('okhttp3.MediaType');
    var RequestBuilder = Java.use('okhttp3.Request$Builder');
    var JSON = MediaType.parse('application/json; charset=utf-8');
    var RequestBody = Java.use('okhttp3.RequestBody');
    var body = RequestBody.create(JSON, request_body);
    var request = RequestBuilder.$new()
        .url(url)
        .post(body)
        .build();
    return request;
}
});