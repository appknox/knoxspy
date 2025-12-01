// console.log("[+] Script starting...");


// Java.perform(function () {
//     console.log("[*] Inside Java.perform");

//     const OkHttpClient = Java.use('okhttp3.OkHttpClient');
//     const Request = Java.use('okhttp3.Request');
//     const RequestBuilder = Java.use('okhttp3.Request$Builder');
//     const RequestBody = Java.use('okhttp3.RequestBody');
//     const MediaType = Java.use('okhttp3.MediaType');
//     const Callback = Java.use('okhttp3.Callback');
//     const IOException = Java.use('java.io.IOException');
//     const Object = Java.use('java.lang.Object');
//     const Call = Java.use('okhttp3.Call');
//     const Response = Java.use('okhttp3.Response');
//     const OkHttpResponseBody = Java.use('okhttp3.ResponseBody'); // Renamed to avoid conflict

//     console.log("[*] Found OkHttp classes");

//     // --- Define the Callback Implementation ---
//     // We define this outside the class for simplicity, but it could be nested
//     const MyCallback = Java.registerClass({
//         name: 'com.example.frida.MyOkHttpCallbackV2', // Unique name
//         implements: [Callback],
//         fields: {
//             returnPayload: 'java.lang.String',
//         },
//         methods: {
//             onFailure: function (call, ioException) {
//                 const requestUrl = call.request().url().toString();
//                 console.error(`[!] OkHttp onFailure for ${requestUrl}: ${ioException.getMessage()}`);
//                 // ioException.printStackTrace(); // Uncomment for full stack trace
//             },
//             onResponse: function (call, response) {
//                 let t_payload = JSON.parse(this.returnPayload.value);
                
//                 const requestUrl = call.request().url().toString();
//                 const responseCode = response.code();
//                 t_payload.status_code = responseCode;
//                 console.log(`[*] OkHttp onResponse for ${requestUrl}: Status Code: ${responseCode}`);

//                 const headers = response.headers(); // Get okhttp3.Headers object
//                 const headersArray = [];
//                 for (let i = 0; i < headers.size(); i++) {
//                     headersArray.push(headers.name(i) + ": " + headers.value(i));
//                 }
//                 const responseHeadersString = JSON.stringify(headersArray);

//                 console.log(`[*] OkHttp onResponse for ${requestUrl}: Response Headers: ${responseHeadersString}`);
//                 t_payload.response_headers = responseHeadersString;

//                 const body = response.body();
//                 let bodyString = null;
//                 if (body) {
//                     try {
//                         // Use peekBody to avoid consuming the stream if the app might need it later
//                         // Note: peekBody loads the whole body into memory, up to a limit (e.g., 1MB)
//                         // For very large responses, use body.source().readString(java.nio.charset.Charset.forName("UTF-8"))
//                         // or body.string() if you are sure nothing else needs the body.
//                         // bodyString = body.peekBody(java.lang.Long.MAX_VALUE).string(); // Might fail for large bodies
//                             bodyString = body.string(); // Reads and consumes the body
//                             console.log(`[+] Response Body (${requestUrl}):\n${bodyString}`);
//                             t_payload.response_body = bodyString;
//                     } catch (e) {
//                         console.error(`[!] Error reading response body for ${requestUrl}: ${e}`);
//                     } finally {
//                         // If you used body.string(), it's already closed.
//                         // If you used peekBody or other methods, ensure closure.
//                             try { body.close(); } catch(e) {} // Close if not already closed
//                     }
//                 } else {
//                     console.log(`[*] Response body is null for ${requestUrl}.`);
//                 }
//                 send(JSON.stringify(t_payload));
//             }
//         }
//     });

//     // --- Define the OkHttp Client Class ---
//     class OkHttpFridaClient {
//         constructor() {
//             console.log("[Class] Initializing OkHttpFridaClient...");
//             // Create a single client instance for this class instance
//             this.client = OkHttpClient.$new();
//             // Store class handles (already fetched outside)
//             this.RequestBuilder = RequestBuilder;
//             this.RequestBody = RequestBody;
//             this.MediaType = MediaType;
//             this.MyCallback = MyCallback; // Use the callback defined outside
//             this.returnPayload = null;
//             console.log("[Class] OkHttpClient instance created.");
//         }

//         /**
//          * Internal helper to build the request object.
//          * @param {string} url - The target URL.
//          * @param {string} method - HTTP method (GET, POST, etc.).
//          * @param {object|null} headers - Optional headers object (key-value pairs).
//          * @param {string|null} bodyString - Optional request body as a string.
//          * @param {string|null} mediaTypeString - Optional media type (e.g., 'application/json; charset=utf-8'). Required if bodyString is provided.
//          * @returns {okhttp3.Request} - The built request object.
//          */
//         _buildRequest(url, method, headers = null, bodyString = null, mediaTypeString = null) {
//             const requestBuilder = this.RequestBuilder.$new();
//             requestBuilder.url(url);

//             // Add headers
//             if (headers) {
//                 for (const key in headers) {
//                     if (Object.hasOwnProperty.call(headers, key)) {
//                         requestBuilder.addHeader(key, headers[key]);
//                     }
//                 }
//             }

//             // Handle request body for relevant methods
//             let requestBody = null;
//             if (bodyString !== null && (method === 'POST' || method === 'PUT' || method === 'DELETE' || method === 'PATCH')) {
//                     if (!mediaTypeString) {
//                     throw new Error("mediaTypeString is required when providing a request body.");
//                 }
//                 const mediaType = this.MediaType.parse(mediaTypeString);
//                 requestBody = this.RequestBody.create(mediaType, bodyString);
//                 requestBuilder.method(method, requestBody);
//             } else if (method === 'DELETE' && bodyString === null) {
//                 // Handle DELETE requests that might have no body
//                 requestBuilder.method(method, null);
//                 } else {
//                 // For GET, HEAD, OPTIONS etc.
//                 requestBuilder.method(method, null);
//             }

//             const request = requestBuilder.build();
//             console.log(`[Class] Built ${method} Request for URL: ${request.url().toString()}`);
//             return request;
//         }

//         /**
//          * Internal helper to execute the request asynchronously.
//          * @param {okhttp3.Request} request - The request object to execute.
//          */
//         _executeRequest(request) {
//             try {
//                 const callbackInstance = this.MyCallback.$new();
//                 callbackInstance.returnPayload.value = JSON.stringify(this.returnPayload);
//                 const call = this.client.newCall(request);
//                 console.log(`[Class] Enqueuing ${request.method()} request to ${request.url().toString()}...`);
//                 call.enqueue(callbackInstance);
//                 console.log(`[Class] Request enqueued.`);
//             } catch(error) {
//                     console.error(`[Class] Error executing request for ${request.url().toString()}: ${error}`);
//                     console.error(error.stack);
//             }
//         }

//         setReturnPayload(payload) {
//             this.returnPayload = payload;
//         }

//         // --- Public Methods for HTTP Verbs ---

//         get(url, headers = null) {
//             const request = this._buildRequest(url, 'GET', headers);
//             this._executeRequest(request);
//         }

//         post(url, headers = null, bodyString = '', mediaTypeString = 'application/json; charset=utf-8') {
//             const request = this._buildRequest(url, 'POST', headers, bodyString, mediaTypeString);
//             this._executeRequest(request);
//         }

//         put(url, headers = null, bodyString = '', mediaTypeString = 'application/json; charset=utf-8') {
//             const request = this._buildRequest(url, 'PUT', headers, bodyString, mediaTypeString);
//             this._executeRequest(request);
//         }

//         // Note: OkHttp DELETE can optionally have a body
//         delete(url, headers = null, bodyString = null, mediaTypeString = 'application/json; charset=utf-8') {
//             const request = this._buildRequest(url, 'DELETE', headers, bodyString, bodyString !== null ? mediaTypeString : null);
//             this._executeRequest(request);
//         }

//         head(url, headers = null) {
//             const request = this._buildRequest(url, 'HEAD', headers);
//             this._executeRequest(request);
//         }

//         options(url, headers = null) {
//             const request = this._buildRequest(url, 'OPTIONS', headers);
//             this._executeRequest(request);
//         }

//         patch(url, headers = null, bodyString = '', mediaTypeString = 'application/json; charset=utf-8') {
//             const request = this._buildRequest(url, 'PATCH', headers, bodyString, mediaTypeString);
//             this._executeRequest(request);
//         }

//         trace(url, headers = null) {
//             const request = this._buildRequest(url, 'TRACE', headers);
//             this._executeRequest(request);
//         }
//     } // --- End of OkHttpFridaClient Class ---

    
//     console.log("[*] Creating OkHttpFridaClient instance...");
//     const okHttpApiClient = new OkHttpFridaClient();
//     console.log("[*] OkHttpFridaClient instance ready.");

//     recv('data', function(message) {
//         console.log("[+] Received message: " + JSON.stringify(message.payload));
//         const method = message.payload.method;
//         const endpoint = message.payload.endpoint;
//         const request_headers = JSON.parse(message.payload.request_headers);
//         const request_body = message.payload.request_body;
//         const id = message.payload.id;
//         const protocol = message.payload.protocol;
//         const host = message.payload.host;
//         const status_code = message.payload.status_code;
//         const response_body = message.payload.response_body;
//         const response_headers = message.payload.response_headers;
//         const session_id = message.payload.session_id;
//         let t_payload = message.payload;
//         t_payload.request_headers = JSON.stringify(request_headers);
//         okHttpApiClient.setReturnPayload(t_payload);
        
//         if (method === 'GET') {
//             const url = protocol + "://" + host + endpoint;
//             console.log("[+] Received GET request: " + url);
//             okHttpApiClient.get(url, request_headers);
//         } else if (method === 'POST') {
//             const url = protocol + "://" + host + endpoint;
//             console.log("[+] Received POST request: " + url);
//             okHttpApiClient.post(url, request_headers, request_body, 'application/json; charset=utf-8');
//         } else if (method === 'PUT') {
//             const url = protocol + "://" + host + endpoint;
//             console.log("[+] Received PUT request: " + url);
//             okHttpApiClient.put(url, request_headers, request_body, 'application/json; charset=utf-8');
//         } else if (method === 'DELETE') {
//             const url = protocol + "://" + host + endpoint;
//             console.log("[+] Received DELETE request: " + url);
//             okHttpApiClient.delete(url, request_headers);
//         } else if (method === 'HEAD') {
//             const url = protocol + "://" + host + endpoint;
//             console.log("[+] Received HEAD request: " + url);
//             okHttpApiClient.head(url, request_headers);
//         } else if (method === 'OPTIONS') {
//             const url = protocol + "://" + host + endpoint;
//             console.log("[+] Received OPTIONS request: " + url);
//             okHttpApiClient.options(url, request_headers);
//         } else if (method === 'PATCH') {
//             const url = protocol + "://" + host + endpoint;
//             console.log("[+] Received PATCH request: " + url);
//             okHttpApiClient.patch(url, request_headers, request_body, 'application/json; charset=utf-8');
//         } else if (method === 'TRACE') {
//             const url = protocol + "://" + host + endpoint;
//             console.log("[+] Received TRACE request: " + url);
//             okHttpApiClient.trace(url, request_headers);
//         }

//     });
// });

// console.log("[+] Script execution finished (main thread). OkHttp callbacks will run asynchronously.");


console.log("[+] Script starting...");

Java.perform(function () {
    console.log("[*] Inside Java.perform");

    const URL = Java.use("java.net.URL");
    const HttpURLConnection = Java.use("java.net.HttpURLConnection");
    const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
    const OutputStreamWriter = Java.use("java.io.OutputStreamWriter");
    const BufferedReader = Java.use("java.io.BufferedReader");
    const InputStreamReader = Java.use("java.io.InputStreamReader");
    const StringBuilder = Java.use("java.lang.StringBuilder");
    const TrustManager = Java.use("javax.net.ssl.TrustManager");
    const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    const SSLContext = Java.use("javax.net.ssl.SSLContext");
    const HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");

    console.log("[*] Found HttpURLConnection classes");

    // Disable SSL certificate verification
    function disableSSLVerification() {
        try {
            // Create a trust manager that does not validate certificate chains
            const TrustAllManager = Java.registerClass({
                name: 'com.frida.TrustAllManagerV1',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() {
                        return [];
                    }
                }
            });
            
            // Create a hostname verifier that accepts all hostnames
            const AllHostnameVerifier = Java.registerClass({
                name: 'com.frida.AllHostnameVerifierV1',
                implements: [HostnameVerifier],
                methods: {
                    verify: function(hostname, session) {
                        return true;
                    }
                }
            });
            
            // Install the all-trusting trust manager
            const sslContext = SSLContext.getInstance("TLS");
            const trustManagers = Java.array('Ljavax.net.ssl.TrustManager;', [TrustAllManager.$new()]);
            sslContext.init(null, trustManagers, null);
            
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier(AllHostnameVerifier.$new());
            
            console.log("[*] SSL certificate verification disabled");
        } catch (e) {
            console.log("[!] Error disabling SSL verification: " + e);
        }
    }

    // --- Define the HttpURLConnection Client Class ---
    class HttpURLConnectionClient {
        constructor() {
            console.log("[Class] Initializing HttpURLConnectionClient...");
            this.returnPayload = null;
            console.log("[Class] HttpURLConnectionClient instance created.");
        }

        /**
         * Internal helper to execute HTTP request.
         * @param {string} url - The target URL.
         * @param {string} method - HTTP method (GET, POST, etc.).
         * @param {object|null} headers - Optional headers object (key-value pairs).
         * @param {string|null} bodyString - Optional request body as a string.
         */
        _executeRequest(url, method, headers = null, bodyString = null) {
            try {
                console.log(`[Class] Executing ${method} request to ${url}...`);
                
                // Create URL object
                const urlObj = URL.$new(url);
                
                // Open connection
                const connection = urlObj.openConnection();
                let httpConnection;
                
                if (url.startsWith('https://')) {
                    httpConnection = Java.cast(connection, HttpsURLConnection);
                } else {
                    httpConnection = Java.cast(connection, HttpURLConnection);
                }
                
                // Set request method
                httpConnection.setRequestMethod(method);
                
                // Set default headers if none provided
                if (!headers || Object.keys(headers).length === 0) {
                    httpConnection.setRequestProperty("User-Agent", "Dart/3.8 (dart:io)");
                    httpConnection.setRequestProperty("Accept-Encoding", "gzip");
                }
                
                // Add custom headers
                if (headers) {
                    for (const key in headers) {
                        if (Object.hasOwnProperty.call(headers, key)) {
                            httpConnection.setRequestProperty(key, headers[key]);
                        }
                    }
                }
                
                // Set DoInput BEFORE any connection is established
                httpConnection.setDoInput(true);
                
                // Handle request body for methods that support it
                if (bodyString !== null && bodyString !== '' && 
                    (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE')) {
                    
                    // Set Content-Type if not already set
                    let hasContentType = false;
                    if (headers) {
                        for (const key in headers) {
                            if (key.toLowerCase() === 'content-type') {
                                hasContentType = true;
                                break;
                            }
                        }
                    }
                    if (!hasContentType) {
                        httpConnection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                    }
                    
                    httpConnection.setRequestProperty("Content-Length", String(bodyString.length));
                    httpConnection.setDoOutput(true);
                    
                    // Write request body
                    const outputStream = httpConnection.getOutputStream();
                    const writer = OutputStreamWriter.$new(outputStream, "UTF-8");
                    writer.write(bodyString, 0, bodyString.length);
                    writer.flush();
                    writer.close();
                    outputStream.close();
                    
                    console.log(`[Class] Request body sent: ${bodyString.substring(0, 100)}${bodyString.length > 100 ? '...' : ''}`);
                }
                
                // Get response code
                const responseCode = httpConnection.getResponseCode();
                const responseMessage = httpConnection.getResponseMessage();
                
                console.log(`[Class] Response: ${responseCode} ${responseMessage}`);
                
                // Collect response headers
                const headersArray = [];
                for (let i = 0; i < 100; i++) {
                    const key = httpConnection.getHeaderFieldKey(i);
                    const value = httpConnection.getHeaderField(i);
                    
                    if (key !== null && value !== null) {
                        headersArray.push(key + ": " + value);
                    } else if (key === null && value === null) {
                        break;
                    }
                }
                
                // Read response body
                let inputStream;
                if (responseCode >= 200 && responseCode < 300) {
                    inputStream = httpConnection.getInputStream();
                } else {
                    inputStream = httpConnection.getErrorStream();
                }
                
                let responseBody = '';
                if (inputStream !== null) {
                    const reader = BufferedReader.$new(InputStreamReader.$new(inputStream, "UTF-8"));
                    const response = StringBuilder.$new();
                    let line;
                    
                    while ((line = reader.readLine()) !== null) {
                        response.append(line);
                        response.append("\n");
                    }
                    
                    reader.close();
                    inputStream.close();
                    
                    responseBody = response.toString().trim();
                    console.log(`[Class] Response body received (${responseBody.length} chars)`);
                }
                
                httpConnection.disconnect();
                
                // Update return payload
                let t_payload = JSON.parse(JSON.stringify(this.returnPayload));
                t_payload.status_code = responseCode;
                t_payload.response_headers = JSON.stringify(headersArray);
                t_payload.response_body = responseBody;
                
                console.log("[Class] Sending payload back...");
                send(JSON.stringify(t_payload));
                
            } catch (error) {
                console.error(`[Class] Error executing request: ${error}`);
                console.error(error.stack);
                
                // Send error response
                if (this.returnPayload) {
                    let t_payload = JSON.parse(JSON.stringify(this.returnPayload));
                    t_payload.status_code = 0;
                    t_payload.response_headers = JSON.stringify([]);
                    t_payload.response_body = `Error: ${error.toString()}`;
                    send(JSON.stringify(t_payload));
                }
            }
        }

        setReturnPayload(payload) {
            this.returnPayload = payload;
        }

        // --- Public Methods for HTTP Verbs ---

        get(url, headers = null) {
            this._executeRequest(url, 'GET', headers);
        }

        post(url, headers = null, bodyString = '') {
            this._executeRequest(url, 'POST', headers, bodyString);
        }

        put(url, headers = null, bodyString = '') {
            this._executeRequest(url, 'PUT', headers, bodyString);
        }

        delete(url, headers = null, bodyString = null) {
            this._executeRequest(url, 'DELETE', headers, bodyString);
        }

        head(url, headers = null) {
            this._executeRequest(url, 'HEAD', headers);
        }

        options(url, headers = null) {
            this._executeRequest(url, 'OPTIONS', headers);
        }

        patch(url, headers = null, bodyString = '') {
            this._executeRequest(url, 'PATCH', headers, bodyString);
        }

        trace(url, headers = null) {
            this._executeRequest(url, 'TRACE', headers);
        }
    } // --- End of HttpURLConnectionClient Class ---

    // Disable SSL verification first
    disableSSLVerification();
    
    console.log("[*] Creating HttpURLConnectionClient instance...");
    const httpApiClient = new HttpURLConnectionClient();
    console.log("[*] HttpURLConnectionClient instance ready.");

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
        
        // Convert headers array to object for HttpURLConnection
        const headersObj = {};
        if (request_headers && Array.isArray(request_headers)) {
            for (let i = 0; i < request_headers.length; i++) {
                const header = request_headers[i];
                const colonIndex = header.indexOf(':');
                if (colonIndex > 0) {
                    const key = header.substring(0, colonIndex).trim();
                    const value = header.substring(colonIndex + 1).trim();
                    headersObj[key] = value;
                }
            }
        }
        
        let t_payload = message.payload;
        t_payload.request_headers = JSON.stringify(request_headers);
        httpApiClient.setReturnPayload(t_payload);
        
        const url = protocol + "://" + host + endpoint;
        
        if (method === 'GET') {
            console.log("[+] Received GET request: " + url);
            httpApiClient.get(url, headersObj);
        } else if (method === 'POST') {
            console.log("[+] Received POST request: " + url);
            httpApiClient.post(url, headersObj, request_body);
        } else if (method === 'PUT') {
            console.log("[+] Received PUT request: " + url);
            httpApiClient.put(url, headersObj, request_body);
        } else if (method === 'DELETE') {
            console.log("[+] Received DELETE request: " + url);
            httpApiClient.delete(url, headersObj);
        } else if (method === 'HEAD') {
            console.log("[+] Received HEAD request: " + url);
            httpApiClient.head(url, headersObj);
        } else if (method === 'OPTIONS') {
            console.log("[+] Received OPTIONS request: " + url);
            httpApiClient.options(url, headersObj);
        } else if (method === 'PATCH') {
            console.log("[+] Received PATCH request: " + url);
            httpApiClient.patch(url, headersObj, request_body);
        } else if (method === 'TRACE') {
            console.log("[+] Received TRACE request: " + url);
            httpApiClient.trace(url, headersObj);
        } else {
            console.log("[!] Unknown HTTP method: " + method);
        }
    });
});

console.log("[+] Script execution finished (main thread). HTTP requests will be made synchronously.");
