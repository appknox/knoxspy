
Java.perform(() => {
    const OkHttpClient = Java.use('okhttp3.OkHttpClient');
    const Buffer = Java.use('okio.Buffer');
    const RequestBuilder = Java.use('okhttp3.Request$Builder');
    RequestBuilder.build.implementation = function () {
        const request = this.build();
        const method = request.method();
        const url = request.url().toString();
        const requestBody = request.body();
        let bodyStr = '';
        if (requestBody !== null) {
            try {
                const buffer = Buffer.$new();
                requestBody.writeTo(buffer);
                bodyStr = buffer.readUtf8();
            }
            catch (e) {
                bodyStr = '[Failed to read body]';
            }
        }
        // Uncomment for debug:
        // console.log(`➡️ HTTP Request:\n   Method: ${method}\n   URL: ${url}\n   Body: ${bodyStr || '<empty>'}`);
        return request;
    };
    OkHttpClient.newCall.overload('okhttp3.Request').implementation = function (request) {
        try {
            const requestUrl = request.url().toString();
            const protocol = request.url().scheme();
            const requestBody = request.body();
            const method = request.method().toString();
            const requestList = requestUrl.split('/');
            const requestHost = requestList[2];
            const URL = requestUrl.split(requestHost)[1];
            const contentLength = requestBody ? requestBody.contentLength() : 0;
            const buffer = Buffer.$new();
            let requestBodyString = '';
            let contentType = '';
            let headersArr = [];
            headersArr.push(`Host: ${requestHost}`);
            if (contentLength > 0 && requestBody) {
                requestBody.writeTo(buffer);
                if (buffer.size() !== 0) {
                    requestBodyString = buffer.readUtf8();
                    contentType = requestBody.contentType()?.toString() || '';
                    headersArr.push(`Content-Type: ${contentType}`);
                }
            }
            const requestHeaders = request.headers();
            const requestHeaderNames = requestHeaders.names().toArray();
            for (let i = 0; i < requestHeaderNames.length; i++) {
                const headerName = requestHeaderNames[i];
                const headerValue = requestHeaders.get(headerName);
                if (headerName.toLowerCase() !== 'host') {
                    headersArr.push(`${headerName}: ${headerValue}`);
                }
            }
            console.log('[LOG] Request headers:', headersArr);
            headersArr = headersArr.filter((item, index) => headersArr.indexOf(item) === index);
            const response = this.newCall(request).execute();
            const responseHeaders = response.headers();
            const responseHeaderNames = responseHeaders.names().toArray();
            const responseStatus = response.code();
            const responseMessage = response.message();
            const responseProtocol = response.protocol().toString();
            const respHeaders = [`${responseProtocol.toUpperCase()} ${responseStatus} ${responseMessage}`];
            for (let i = 0; i < responseHeaderNames.length; i++) {
                const name = responseHeaderNames[i];
                const value = responseHeaders.get(name);
                respHeaders.push(`${name}: ${value}`);
            }
            let responseBodyString = '';
            const responseBody = response.body();
            if (responseBody !== null) {
                if (response.isSuccessful()) {
                    responseBodyString = responseBody.string();
                }
                else {
                    console.log('Error: Response not successful');
                }
            }
            else {
                console.log('Error: Empty response body');
            }
            const tmpPayload = {
                method,
                protocol,
                host: requestHost,
                endpoint: URL,
                request_headers: JSON.stringify(headersArr),
                request_body: requestBodyString,
                status_code: responseStatus,
                response_headers: JSON.stringify(respHeaders),
                response_body: responseBodyString
            };
            send(JSON.stringify(tmpPayload));
        }
        catch (error) {
            console.error('Error in OkHttp hook:', error);
        }
        return this.newCall(request);
    };
});