Java.perform(function() {
    recv('data', function(message) {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var RequestBuilder = Java.use('okhttp3.Request$Builder');
        var client = OkHttpClient.$new();
        var payload = message.payload;
        var body = payload.request_body;
        var url = payload.protocol + "://" + payload.host + payload.endpoint;
        var headersArray = JSON.parse(payload.request_headers);
        if (payload.method == 'POST') {
            var contentType = headersArray.find(header => header.toLowerCase().startsWith("content-type:"));
            if (contentType) {
                contentType = contentType.split(": ")[1];
                var builder = makePostRequest(url,body,contentType)
            } else {
                var builder = makePostRequest(url,body)
            }
        } 
        else if (payload.method == 'PUT') {
            var builder = makePutRequest(url,body)
        }
        else if (payload.method == 'DELETE') {
            var builder = makeDeleteRequest(url)
        }
        else if (payload.method == 'PATCH') {
            var builder = makePatchRequest(url,body)
        }
        else {
            var builder = RequestBuilder.$new()
            .url(url)   
        }
        headersArray.forEach(function(header) {
            var splitHeader = header.split(": ");
            var headerName = splitHeader[0];
            var headerValue = splitHeader[1];
            builder.header(headerName, headerValue);
        });
        var request = builder.build();
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
                "protocol": payload.protocol,
                "host":payload.host,
                "endpoint": payload.endpoint,
                "request_headers": JSON.parse(payload.request_headers),
                "request_body": payload.request_body,
                "status_code": payload.status_code,
                "session_id": payload.session_id,
                "response_headers": respHeaders,
                "response_body": responseBodyString
            }
        send(JSON.stringify(tmpPayload));
        })

});

function makePostRequest(url, request_body, content_type){
    var MediaType = Java.use('okhttp3.MediaType');
    var RequestBuilder = Java.use('okhttp3.Request$Builder');
    if (content_type) {
        var media_type = MediaType.parse(content_type);
    } else {
        var media_type = MediaType.parse('application/json; charset=utf-8');
    }
    
    var RequestBody = Java.use('okhttp3.RequestBody');
    var body = RequestBody.create(media_type, request_body);
    var request = RequestBuilder.$new()
        .url(url)
        .post(body)
    return request;
}

function makePutRequest(url, request_body){
    var MediaType = Java.use('okhttp3.MediaType');
    var RequestBuilder = Java.use('okhttp3.Request$Builder');
    var JSON = MediaType.parse('application/json; charset=utf-8');
    var RequestBody = Java.use('okhttp3.RequestBody');
    var body = RequestBody.create(JSON, request_body);
    var request = RequestBuilder.$new()
        .url(url)
        .put(body)
    return request;
}

function makePatchRequest(url, request_body){
    var MediaType = Java.use('okhttp3.MediaType');
    var RequestBuilder = Java.use('okhttp3.Request$Builder');
    var JSON = MediaType.parse('application/json; charset=utf-8');
    var RequestBody = Java.use('okhttp3.RequestBody');
    var body = RequestBody.create(JSON, request_body);
    var request = RequestBuilder.$new()
        .url(url)
        .patch(body)
    return request;
}

function makeDeleteRequest(url){
    var RequestBuilder = Java.use('okhttp3.Request$Builder');
    var request = RequestBuilder.$new()
        .url(url)
        .delete()
    return request;
}
