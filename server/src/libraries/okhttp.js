Java.perform(function() {
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var Buffer = Java.use('okio.Buffer');
    OkHttpClient.newCall.overload('okhttp3.Request').implementation = function(request) {
        var requestUrl = request.url().toString();
        var requestBody = request.body();
        var method = request.method().toString();
        const requestList = requestUrl.split("/");
        const requestHost = requestList[2];
        var contentLength = requestBody ? requestBody.contentLength() : 0;
        var buffer = Buffer.$new();
        var requestBodyString = '';
        var contentType = '';
        var headersArr = [];
        var hostHeader = `Host: ${requestHost}`;
        headersArr.push(hostHeader);
        if (contentLength > 0) {
            requestBody.writeTo(buffer);
            if (buffer.size() !== 0) {
                requestBodyString = buffer.readUtf8();
                contentType = requestBody.contentType();
                var contentHeader = `Content-Type: ${contentType}`;
                headersArr.push(contentHeader);
            }
        }
        // HTTP headers here
        var requestHeaders = request.headers();
        var requestHeaderNames = requestHeaders.names();
        var requestHeaderNamesArray = requestHeaderNames.toArray();
        for (var i = 0; i < requestHeaderNamesArray.length; i++) {
            var headerName = requestHeaderNamesArray[i];
            var headerValue = requestHeaders.get(headerName);
            var finalValue = `${headerName}: ${headerValue}`;
            headersArr.push(finalValue);
        }
        // Response data here
        var response = this.newCall(request).execute();
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

        // Response body
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
            'method': method,
            'host':requestHost,
            'endpoint': requestUrl,
            'request_headers': JSON.stringify(headersArr),
            'request_body': JSON.stringify(requestBodyString),
            'status_code': 200,
            'response_headers': JSON.stringify(respHeaders),
            'response_body': responseBodyString
        }
        send(JSON.stringify(tmpPayload))
        return this.newCall(request);    
}
});
