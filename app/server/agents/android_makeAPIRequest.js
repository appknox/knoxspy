console.log("[+] Script starting...");


Java.perform(function () {
    console.log("[*] Inside Java.perform");

    const OkHttpClient = Java.use('okhttp3.OkHttpClient');
    const Request = Java.use('okhttp3.Request');
    const RequestBuilder = Java.use('okhttp3.Request$Builder');
    const RequestBody = Java.use('okhttp3.RequestBody');
    const MediaType = Java.use('okhttp3.MediaType');
    const Callback = Java.use('okhttp3.Callback');
    const IOException = Java.use('java.io.IOException');
    const Object = Java.use('java.lang.Object');
    const Call = Java.use('okhttp3.Call');
    const Response = Java.use('okhttp3.Response');
    const OkHttpResponseBody = Java.use('okhttp3.ResponseBody'); // Renamed to avoid conflict

    console.log("[*] Found OkHttp classes");

    // --- Define the Callback Implementation ---
    // We define this outside the class for simplicity, but it could be nested
    const MyCallback = Java.registerClass({
        name: 'com.example.frida.MyOkHttpCallbackV2', // Unique name
        implements: [Callback],
        fields: {
            returnPayload: 'java.lang.String',
        },
        methods: {
            onFailure: function (call, ioException) {
                const requestUrl = call.request().url().toString();
                console.error(`[!] OkHttp onFailure for ${requestUrl}: ${ioException.getMessage()}`);
                // ioException.printStackTrace(); // Uncomment for full stack trace
            },
            onResponse: function (call, response) {
                let t_payload = JSON.parse(this.returnPayload.value);
                
                const requestUrl = call.request().url().toString();
                const responseCode = response.code();
                t_payload.status_code = responseCode;
                console.log(`[*] OkHttp onResponse for ${requestUrl}: Status Code: ${responseCode}`);

                const headers = response.headers(); // Get okhttp3.Headers object
                const headersArray = [];
                for (let i = 0; i < headers.size(); i++) {
                    headersArray.push(headers.name(i) + ": " + headers.value(i));
                }
                const responseHeadersString = JSON.stringify(headersArray);

                console.log(`[*] OkHttp onResponse for ${requestUrl}: Response Headers: ${responseHeadersString}`);
                t_payload.response_headers = responseHeadersString;

                const body = response.body();
                let bodyString = null;
                if (body) {
                    try {
                        // Use peekBody to avoid consuming the stream if the app might need it later
                        // Note: peekBody loads the whole body into memory, up to a limit (e.g., 1MB)
                        // For very large responses, use body.source().readString(java.nio.charset.Charset.forName("UTF-8"))
                        // or body.string() if you are sure nothing else needs the body.
                        // bodyString = body.peekBody(java.lang.Long.MAX_VALUE).string(); // Might fail for large bodies
                            bodyString = body.string(); // Reads and consumes the body
                            console.log(`[+] Response Body (${requestUrl}):\n${bodyString}`);
                            t_payload.response_body = bodyString;
                    } catch (e) {
                        console.error(`[!] Error reading response body for ${requestUrl}: ${e}`);
                    } finally {
                        // If you used body.string(), it's already closed.
                        // If you used peekBody or other methods, ensure closure.
                            try { body.close(); } catch(e) {} // Close if not already closed
                    }
                } else {
                    console.log(`[*] Response body is null for ${requestUrl}.`);
                }
                send(JSON.stringify(t_payload));
            }
        }
    });

    // --- Define the OkHttp Client Class ---
    class OkHttpFridaClient {
        constructor() {
            console.log("[Class] Initializing OkHttpFridaClient...");
            // Create a single client instance for this class instance
            this.client = OkHttpClient.$new();
            // Store class handles (already fetched outside)
            this.RequestBuilder = RequestBuilder;
            this.RequestBody = RequestBody;
            this.MediaType = MediaType;
            this.MyCallback = MyCallback; // Use the callback defined outside
            this.returnPayload = null;
            console.log("[Class] OkHttpClient instance created.");
        }

        /**
         * Internal helper to build the request object.
         * @param {string} url - The target URL.
         * @param {string} method - HTTP method (GET, POST, etc.).
         * @param {object|null} headers - Optional headers object (key-value pairs).
         * @param {string|null} bodyString - Optional request body as a string.
         * @param {string|null} mediaTypeString - Optional media type (e.g., 'application/json; charset=utf-8'). Required if bodyString is provided.
         * @returns {okhttp3.Request} - The built request object.
         */
        _buildRequest(url, method, headers = null, bodyString = null, mediaTypeString = null) {
            const requestBuilder = this.RequestBuilder.$new();
            requestBuilder.url(url);

            // Add headers
            if (headers) {
                for (const key in headers) {
                    if (Object.hasOwnProperty.call(headers, key)) {
                        requestBuilder.addHeader(key, headers[key]);
                    }
                }
            }

            // Handle request body for relevant methods
            let requestBody = null;
            if (bodyString !== null && (method === 'POST' || method === 'PUT' || method === 'DELETE' || method === 'PATCH')) {
                    if (!mediaTypeString) {
                    throw new Error("mediaTypeString is required when providing a request body.");
                }
                const mediaType = this.MediaType.parse(mediaTypeString);
                requestBody = this.RequestBody.create(mediaType, bodyString);
                requestBuilder.method(method, requestBody);
            } else if (method === 'DELETE' && bodyString === null) {
                // Handle DELETE requests that might have no body
                requestBuilder.method(method, null);
                } else {
                // For GET, HEAD, OPTIONS etc.
                requestBuilder.method(method, null);
            }

            const request = requestBuilder.build();
            console.log(`[Class] Built ${method} Request for URL: ${request.url().toString()}`);
            return request;
        }

        /**
         * Internal helper to execute the request asynchronously.
         * @param {okhttp3.Request} request - The request object to execute.
         */
        _executeRequest(request) {
            try {
                const callbackInstance = this.MyCallback.$new();
                callbackInstance.returnPayload.value = JSON.stringify(this.returnPayload);
                const call = this.client.newCall(request);
                console.log(`[Class] Enqueuing ${request.method()} request to ${request.url().toString()}...`);
                call.enqueue(callbackInstance);
                console.log(`[Class] Request enqueued.`);
            } catch(error) {
                    console.error(`[Class] Error executing request for ${request.url().toString()}: ${error}`);
                    console.error(error.stack);
            }
        }

        setReturnPayload(payload) {
            this.returnPayload = payload;
        }

        // --- Public Methods for HTTP Verbs ---

        get(url, headers = null) {
            const request = this._buildRequest(url, 'GET', headers);
            this._executeRequest(request);
        }

        post(url, headers = null, bodyString = '', mediaTypeString = 'application/json; charset=utf-8') {
            const request = this._buildRequest(url, 'POST', headers, bodyString, mediaTypeString);
            this._executeRequest(request);
        }

        put(url, headers = null, bodyString = '', mediaTypeString = 'application/json; charset=utf-8') {
            const request = this._buildRequest(url, 'PUT', headers, bodyString, mediaTypeString);
            this._executeRequest(request);
        }

        // Note: OkHttp DELETE can optionally have a body
        delete(url, headers = null, bodyString = null, mediaTypeString = 'application/json; charset=utf-8') {
            const request = this._buildRequest(url, 'DELETE', headers, bodyString, bodyString !== null ? mediaTypeString : null);
            this._executeRequest(request);
        }

        head(url, headers = null) {
            const request = this._buildRequest(url, 'HEAD', headers);
            this._executeRequest(request);
        }

        options(url, headers = null) {
            const request = this._buildRequest(url, 'OPTIONS', headers);
            this._executeRequest(request);
        }

        patch(url, headers = null, bodyString = '', mediaTypeString = 'application/json; charset=utf-8') {
            const request = this._buildRequest(url, 'PATCH', headers, bodyString, mediaTypeString);
            this._executeRequest(request);
        }

        trace(url, headers = null) {
            const request = this._buildRequest(url, 'TRACE', headers);
            this._executeRequest(request);
        }
    } // --- End of OkHttpFridaClient Class ---

    
    console.log("[*] Creating OkHttpFridaClient instance...");
    const okHttpApiClient = new OkHttpFridaClient();
    console.log("[*] OkHttpFridaClient instance ready.");

    recv('data', function(message) {
        console.log("[+] Received message: " + JSON.stringify(message.payload));
        const method = message.payload.method;
        const endpoint = message.payload.endpoint;
        const request_headers = JSON.parse(message.payload.request_headers);
        const request_body = message.payload.request_body;
        const id = message.payload.id;
        const protocol = message.payload.protocol;
        const host = message.payload.host;
        const status_code = message.payload.status_code;
        const response_body = message.payload.response_body;
        const response_headers = message.payload.response_headers;
        const session_id = message.payload.session_id;
        let t_payload = message.payload;
        t_payload.request_headers = JSON.stringify(request_headers);
        okHttpApiClient.setReturnPayload(t_payload);
        
        if (method === 'GET') {
            const url = protocol + "://" + host + endpoint;
            console.log("[+] Received GET request: " + url);
            okHttpApiClient.get(url, request_headers);
        } else if (method === 'POST') {
            const url = protocol + "://" + host + endpoint;
            console.log("[+] Received POST request: " + url);
            okHttpApiClient.post(url, request_headers, request_body, 'application/json; charset=utf-8');
        } else if (method === 'PUT') {
            const url = protocol + "://" + host + endpoint;
            console.log("[+] Received PUT request: " + url);
            okHttpApiClient.put(url, request_headers, request_body, 'application/json; charset=utf-8');
        } else if (method === 'DELETE') {
            const url = protocol + "://" + host + endpoint;
            console.log("[+] Received DELETE request: " + url);
            okHttpApiClient.delete(url, request_headers);
        } else if (method === 'HEAD') {
            const url = protocol + "://" + host + endpoint;
            console.log("[+] Received HEAD request: " + url);
            okHttpApiClient.head(url, request_headers);
        } else if (method === 'OPTIONS') {
            const url = protocol + "://" + host + endpoint;
            console.log("[+] Received OPTIONS request: " + url);
            okHttpApiClient.options(url, request_headers);
        } else if (method === 'PATCH') {
            const url = protocol + "://" + host + endpoint;
            console.log("[+] Received PATCH request: " + url);
            okHttpApiClient.patch(url, request_headers, request_body, 'application/json; charset=utf-8');
        } else if (method === 'TRACE') {
            const url = protocol + "://" + host + endpoint;
            console.log("[+] Received TRACE request: " + url);
            okHttpApiClient.trace(url, request_headers);
        }

    });
});

console.log("[+] Script execution finished (main thread). OkHttp callbacks will run asynchronously.");
