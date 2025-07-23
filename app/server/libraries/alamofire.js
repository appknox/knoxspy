/*
 * Target Methods:
 * -[Alamofire.SessionDelegate URLSession:dataTask:didReceiveData:]
 * -[Alamofire.SessionDelegate URLSession:task:didCompleteWithError:]
 */

(function () { // Using IIFE for clean scope
    'use strict';
    console.log("[*] Initializing Accurate Alamofire Interception Script...");

    // --- Global Store for Task Data ---
    let taskDataStore = {};

    // --- HTTP Status Code Reason Phrases (Common Codes) ---
    const httpReasonPhrases = {
        // 1xx Informational
        100: "Continue", 101: "Switching Protocols", 102: "Processing", 103: "Early Hints",
        // 2xx Success
        200: "OK", 201: "Created", 202: "Accepted", 203: "Non-Authoritative Information",
        204: "No Content", 205: "Reset Content", 206: "Partial Content", 207: "Multi-Status",
        208: "Already Reported", 226: "IM Used",
        // 3xx Redirection
        300: "Multiple Choices", 301: "Moved Permanently", 302: "Found", 303: "See Other",
        304: "Not Modified", 305: "Use Proxy", // Deprecated
        307: "Temporary Redirect", 308: "Permanent Redirect",
        // 4xx Client Error
        400: "Bad Request", 401: "Unauthorized", 402: "Payment Required", 403: "Forbidden",
        404: "Not Found", 405: "Method Not Allowed", 406: "Not Acceptable", 407: "Proxy Authentication Required",
        408: "Request Timeout", 409: "Conflict", 410: "Gone", 411: "Length Required",
        412: "Precondition Failed", 413: "Payload Too Large", 414: "URI Too Long", 415: "Unsupported Media Type",
        416: "Range Not Satisfiable", 417: "Expectation Failed", 418: "I'm a teapot", // :)
        421: "Misdirected Request", 422: "Unprocessable Entity", 423: "Locked", 424: "Failed Dependency",
        425: "Too Early", 426: "Upgrade Required", 428: "Precondition Required", 429: "Too Many Requests",
        431: "Request Header Fields Too Large", 451: "Unavailable For Legal Reasons",
        // 5xx Server Error
        500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway", 503: "Service Unavailable",
        504: "Gateway Timeout", 505: "HTTP Version Not Supported", 506: "Variant Also Negotiates",
        507: "Insufficient Storage", 508: "Loop Detected", 510: "Not Extended", 511: "Network Authentication Required"
    };
    // --- Helper Functions ---

    // Safely gets description for an ObjC object
    function safeDescription(obj) {
        try {
            if (obj === null || typeof obj !== 'object') { return obj ? obj.toString() : null; }
            if (obj.isKindOfClass_ && obj.isKindOfClass_(ObjC.classes.NSNull)) { return null; }
            return obj.toString();
        } catch (e) {
            console.error("[!] Error in safeDescription:", e.message);
            return "(error getting description)";
        }
    }

    // Formats NSDictionary headers into a JSON string representing an array of "Key: Value" strings
    // Optionally prepends the status code if provided
    function formatHeadersToJsonStringArray(nsDict, statusCode = null, hostValue = null) { // Add statusCode argument
        let outputArray = []; // Initialize array

        // --- Prepend Status Code if provided ---
        if (statusCode !== null && statusCode !== undefined) {
            try {
                const numericStatusCode = Number(statusCode); // Ensure it's a number
                const reasonPhrase = httpReasonPhrases[numericStatusCode] || "Status"; // Look up using the number
                // You could also try to format a pseudo status-line, but requires guessing:
                // const reasonPhrase = getReasonPhrase(statusCode); // You'd need a helper for this
                // outputArray.push(`HTTP/? ${statusCode} ${reasonPhrase}`);
                // Sticking to a simple Status: CODE representation is safer:
                outputArray.push(`${statusCode} ${reasonPhrase}`);
            } catch (e) {
                console.error("[!] Error adding status code to headers array:", e.message);
                outputArray.push(`_ErrorAddingStatusCode: ${e.message}`);
            }
        
        // --- End Status Code Prepending ---

        // --- Prepend Host Header if provided (for Requests) ---
        } else if (hostValue) { // Only add host if statusCode is NOT provided
            try {
                const hostStr = safeDescription(hostValue); // Use safeDescription
                if (hostStr) {
                    outputArray.push(`Host: ${hostStr}`);
                }
            } catch (e) {
                console.error("[!] Error adding host header to headers array:", e.message);
                outputArray.push(`_ErrorAddingHostHeader: ${e.message}`);
            }
        }

        if (!nsDict || typeof nsDict.isNull === 'function' && nsDict.isNull() || typeof nsDict.isKindOfClass_ !== 'function') {
            return JSON.stringify(outputArray);
        }
        try {
            if (!nsDict.isKindOfClass_(ObjC.classes.NSDictionary)) {
                outputArray.push(`_ErrorNotDictionary: ${nsDict.class().toString()}`);
                return JSON.stringify(outputArray);
            }

            const dict = new ObjC.Object(nsDict);
            const count = dict.count();
            if (count > 0) {
                const keys = dict.allKeys();
                for (let i = 0; i < count; i++) {
                    const keyObj = keys.objectAtIndex_(i);
                    const valueObj = dict.objectForKey_(keyObj);
                    const key = safeDescription(keyObj);
                    const value = safeDescription(valueObj);
                    if (key !== null) {
                        outputArray.push(`${key}: ${value}`);
                    }
                }
            }
            return JSON.stringify(outputArray);
        } catch (e) {
            console.error("[!] Error in formatHeadersToJsonStringArray:", e.message, e.stack);
            outputArray.push(`_ErrorFormattingHeaders: ${e.message}`);
            return JSON.stringify(outputArray);
        }
    }
    // Processes NSData body: tries UTF-8, returns string or null/placeholder string
    function formatBodyToString(nsData) {
        if (!nsData || nsData.isKindOfClass_(ObjC.classes.NSNull)) {
            return null; // No data, return null
        }
        try {
            // let data = new ObjC.Object(nsData);
            // let length = data.length();
            // if (length === 0) {
            //     return ""; // Empty data, return empty string
            // }

            // let NSString = ObjC.classes.NSString;
            // let nsString = NSString.alloc().initWithData_encoding_(data, 4); // 4 = NSUTF8StringEncoding
            // if (nsString !== null) {
            //     return nsString.toString(); // Return decoded string
            // } else {
            //      // Return placeholder if not UTF-8 (Database likely expects a string)
            //     return `[Binary or Non-UTF8 Data, Length: ${length}]`;
            // }
            let body = nsData.bytes().readUtf8String(nsData.length());
            return body;
        } catch (e) {
            console.error("[!] Error in formatBodyToString:", e.message, e.stack);
            return `[Error formatting body: ${e.message}]`;
        }
    }

    // --- Main Interception Logic ---
    let TARGET_CLASS = 'Alamofire.SessionDelegate';
    let DelegateClass = ObjC.classes[TARGET_CLASS];

    if (!DelegateClass) {
        console.error(`[!] Delegate class not found: ${TARGET_CLASS}`);
        // send(JSON.stringify({ script_error: `Delegate class not found: ${TARGET_CLASS}` }));
        return;
    }

    // Get necessary ObjC classes
    let NSMutableData = ObjC.classes.NSMutableData;
    let NSHTTPURLResponse = ObjC.classes.NSHTTPURLResponse;
    let NSString = ObjC.classes.NSString; // Re-declared for clarity within scope

    // 1. Intercept didReceiveData (Capture Request Info & Accumulate Response Body)
    let didReceiveDataSig = '- URLSession:dataTask:didReceiveData:';
    let didReceiveDataMethod = DelegateClass[didReceiveDataSig];
    if (didReceiveDataMethod) {
        Interceptor.attach(didReceiveDataMethod.implementation, {
            onEnter(args) {
                let taskId;
                try {
                    let dataTask = new ObjC.Object(args[3]);
                    let responseDataChunk = args[4] ? new ObjC.Object(args[4]) : null; // Handle potential null chunk
                    taskId = dataTask.taskIdentifier();

                    if (!responseDataChunk || responseDataChunk.length() === 0) {
                        // Don't process empty chunks, can happen
                        // console.log(`[*] Task ${taskId}: Skipping empty data chunk.`);
                        return;
                    }

                    // Initialize storage on first valid chunk
                    if (!taskDataStore[taskId]) {
                        taskDataStore[taskId] = {
                            request: null, // Initialize as null until captured
                            responseBody: NSMutableData.alloc().init()
                        };

                        let request = dataTask.originalRequest() || dataTask.currentRequest();
                        if (request) {
                            let url = request.URL();
                            let capturedRequestHeadersOriginal = request.allHTTPHeaderFields(); // Get original handle
                            let capturedRequestBody = request.HTTPBody();

                            // --- Create an immutable COPY of the request headers ---
                            let capturedRequestHeadersCopy = null;
                            let copyError = null; // To track if copying failed
                            if (capturedRequestHeadersOriginal && !capturedRequestHeadersOriginal.isNull()) {
                                try {
                                    // Use the 'copy' method of NSDictionary to create a new, independent dictionary
                                    capturedRequestHeadersCopy = capturedRequestHeadersOriginal.copy();
                                    console.log(`[*] Task ${taskId}: Successfully created an immutable copy of request headers.`);
                                } catch (e_copy) {
                                    copyError = `[!] Error copying request headers: ${e_copy.message}`;
                                    console.error(`[*] Task ${taskId}: ${copyError}`);
                                    // Fallback: Store null or potentially the original if copy fails? Storing null is safer.
                                    capturedRequestHeadersCopy = null;
                                }
                            } else {
                                console.log(`[*] Task ${taskId}: Original request headers object was null, cannot copy.`);
                            }
                            // --- End copy ---
                            // You can keep or remove this log now the issue is understood.
                            let formattedReqHeadersOnError = "(Original headers not logged)";
                            try {
                                formattedReqHeadersOnError = formatHeadersToJsonStringArray(capturedRequestHeadersOriginal);
                                console.log(`[*] Task ${taskId}: Captured Request. Formatted Original Headers (at capture time): ${formattedReqHeadersOnError}`);
                            } catch (e_format) { /* handle error */ }

                            taskDataStore[taskId].request = { // Store details directly
                                method: safeDescription(request.HTTPMethod()),
                                host: safeDescription(url ? url.host() : null),
                                endpoint: safeDescription(url ? url.path() : "/"),
                                request_headers_raw: capturedRequestHeadersCopy, // Store raw headers object
                                request_body_raw: capturedRequestBody // Store raw body NSData
                            };
                            // console.log(`[*] Task ${taskId}: Captured request request headers raw: ${taskDataStore[taskId].request.request_headers_raw}`);
                            // Handle empty path case
                            if (taskDataStore[taskId].request.endpoint === "") {
                                taskDataStore[taskId].request.endpoint = "/";
                            }
                        } else {
                            console.log(`[*] Task ${taskId}: Could not get request object on first data chunk.`);
                            taskDataStore[taskId].request = { error: "Could not get request object" };
                        }
                    }

                    // Append current chunk
                    if (taskDataStore[taskId] && taskDataStore[taskId].responseBody) {
                        taskDataStore[taskId].responseBody.appendData_(responseDataChunk);
                    }

                } catch (error) {
                    let taskIdStr = taskId !== undefined ? `Task ${taskId}` : 'unknown';
                    console.error(`[!] Error in didReceiveData for Task ${taskIdStr}: ${error.message} \n Stack: ${error.stack}`);
                    // Store error state if needed, e.g.:
                    if (taskId !== undefined && taskDataStore[taskId]) {
                        taskDataStore[taskId].script_error = `didReceiveData Error: ${error.message}`;
                    }
                }
            }
        });
        console.log(`[*] Attached accurate data interceptor to ${TARGET_CLASS} ${didReceiveDataSig}`);
    } else {
        console.log(`[!] Method not found: ${TARGET_CLASS} ${didReceiveDataSig}`);
    }

    // 2. Intercept didCompleteWithError (Finalize Response Info & Send Payload)
    let didCompleteSig = '- URLSession:task:didCompleteWithError:';
    let didCompleteMethod = DelegateClass[didCompleteSig];
    if (didCompleteMethod) {
        Interceptor.attach(didCompleteMethod.implementation, {
            onEnter(args) {
                let taskId;
                let task;
                try {
                    task = new ObjC.Object(args[3]);
                    taskId = task.taskIdentifier();

                    let storedData = taskDataStore[taskId];
                    if (!storedData) {
                        // console.log(`[*] Task ${taskId}: No stored data found on completion.`);
                        // Attempt to get request details directly from task for error reporting?
                        // If a task completes very quickly or before script attached, this can happen.
                        return; // Don't proceed if we didn't capture anything
                    }
                    // console.log(`storedData: ${JSON.stringify(storedData)}`);

                    // Check if request capture failed earlier
                    if (!storedData.request || storedData.request.error) {
                        console.log(`[*] Task ${taskId}: Request details were not captured successfully.`);
                        // Decide if to send a minimal payload or just log
                        // send(JSON.stringify({ taskId: taskId, error: "Failed to capture request details."}));
                        delete taskDataStore[taskId]; // Clean up anyway
                        return;
                    }

                    // --- Prepare Final Payload ---
                    let statusCode = null;
                    let responseHeadersRaw = null;
                    let errorMessage = storedData.script_error || null; // Use stored script error if any

                    // Process network error argument first
                    let errorPtr = args[4];
                    if (errorPtr && !errorPtr.isNull()) {
                        let errorObj = new ObjC.Object(errorPtr);
                        errorMessage = safeDescription(errorObj.localizedDescription()) || "Network error";
                        // Maybe set a specific status code for network errors? e.g., -1009 for offline
                        // statusCode = errorObj.code ? errorObj.code() : -1;
                    }

                    // Process response object
                    let response = task.response();
                    if (response && !response.isNull()) {
                        let responseObj = new ObjC.Object(response);
                        if (responseObj.isKindOfClass_(NSHTTPURLResponse)) {
                            statusCode = responseObj.statusCode();
                            responseHeadersRaw = responseObj.allHeaderFields();
                            // console.log(`[*] Task ${taskId}: HTTP Response Status Code: ${statusCode}`);
                            // console.log(`[*] Task ${taskId}: HTTP Response Headers: ${responseHeadersRaw}`);
                        } else {
                            statusCode = -1; // Indicate non-HTTP response
                            // If no network error, maybe put non-HTTP info here
                            if (!errorMessage) { errorMessage = "Non-HTTP response received"; }
                        }
                    } else if (!errorMessage) {
                        // If no error and no response, something unusual happened
                        errorMessage = "Task completed with no error and no response object.";
                        statusCode = -2; // Indicate missing response state
                    }

                    // +++ SAFER DEBUG LOGGING +++
                    console.log(`\n--- DEBUG Task ${taskId} ---`);

                    // --- Check Request Headers ---
                    let reqHeadersPtr = null;
                    try {
                        if (storedData && storedData.request) {
                            reqHeadersPtr = storedData.request.request_headers_raw; // Get the handle/pointer
                        }
                        console.log(`[DEBUG] reqHeadersPtr obtained: ${reqHeadersPtr !== null}`);

                        if (reqHeadersPtr && !reqHeadersPtr.isNull()) {
                            // Check Class (usually safe)
                            try {
                                console.log(`[DEBUG] reqHeaders Class: ${reqHeadersPtr.class().toString()}`);
                            } catch (e_class) {
                                console.error(`[DEBUG ERROR] Getting reqHeaders class: ${e_class.message}`);
                            }
                            // Check Count (usually safe if it's a collection)
                            try {
                                // Only call count if it's likely a dictionary/collection
                                if (reqHeadersPtr.isKindOfClass_(ObjC.classes.NSDictionary)) {
                                    let reqDict = new ObjC.Object(reqHeadersPtr);
                                    console.log(`[DEBUG] reqHeaders Count: ${reqDict.count()}`);
                                } else {
                                    console.log(`[DEBUG] reqHeaders is not NSDictionary, skipping count.`);
                                }
                            } catch (e_count) {
                                console.error(`[DEBUG ERROR] Getting reqHeaders count: ${e_count.message}`);
                            }
                        } else {
                            console.log(`[DEBUG] reqHeadersPtr is null or points to null.`);
                        }

                    } catch (e_req) {
                        console.error(`[DEBUG ERROR] Accessing storedData.request.request_headers_raw: ${e_req.message}`);
                    }

                    // --- Check Response Headers ---
                    let respHeadersPtr = responseHeadersRaw; // Already have this handle
                    try {
                        console.log(`[DEBUG] respHeadersPtr obtained: ${respHeadersPtr !== null}`);

                        if (respHeadersPtr && !respHeadersPtr.isNull()) {
                            // Check Class
                            try {
                                console.log(`[DEBUG] respHeaders Class: ${respHeadersPtr.class().toString()}`);
                            } catch (e_class) {
                                console.error(`[DEBUG ERROR] Getting respHeaders class: ${e_class.message}`);
                            }
                            // Check Count
                            try {
                                if (respHeadersPtr.isKindOfClass_(ObjC.classes.NSDictionary)) {
                                    let respDict = new ObjC.Object(respHeadersPtr);
                                    console.log(`[DEBUG] respHeaders Count: ${respDict.count()}`);
                                } else {
                                    console.log(`[DEBUG] respHeaders is not NSDictionary, skipping count.`);
                                }
                            } catch (e_count) {
                                console.error(`[DEBUG ERROR] Getting respHeaders count: ${e_count.message}`);
                            }
                        } else {
                            console.log(`[DEBUG] respHeadersPtr is null or points to null.`);
                        }
                    } catch (e_resp) {
                        console.error(`[DEBUG ERROR] Accessing responseHeadersRaw: ${e_resp.message}`);
                    }

                    console.log(`--- END DEBUG Task ${taskId} ---\n`);
                    // +++ END SAFER DEBUG LOGGING +++
                    // Format data for the payload matching the DB schema
                    let payload = {
                        method: storedData.request.method,
                        host: storedData.request.host,
                        endpoint: storedData.request.endpoint,
                        status_code: statusCode,
                        request_headers: formatHeadersToJsonStringArray(storedData.request.request_headers_raw, null, storedData.request.host), // Pass host value HERE
                        response_headers: formatHeadersToJsonStringArray(responseHeadersRaw, statusCode, null), // Pass statusCode HERE
                        request_body: formatBodyToString(storedData.request.request_body_raw),
                        response_body: formatBodyToString(storedData.responseBody)
                        // error_message: errorMessage // Send error separately or log it if DB can't handle
                    };
                    // console.log(`[*] Task ${taskId}: storedData.request.request_headers_raw: ${storedData.request.request_headers_raw}`);

                    // Log error message separately if it exists (as DB doesn't have column)
                    if (errorMessage) {
                        console.log(`[*] Task ${taskId}: Completed with error/warning: ${errorMessage}`);
                        // Optionally send a separate message for errors if needed by the tool
                        console.log(JSON.stringify({ type: "error", taskId: taskId, message: errorMessage }));
                    }

                    // Send the primary payload
                    console.log(`[*] Task ${taskId}: Sending payload: ${JSON.stringify(payload)}`);
                    send(JSON.stringify(payload));
                    // Optionally send a separate message for errors if needed by the tool


                } catch (e) {
                    let taskIdStr = taskId !== undefined ? `Task ${taskId}` : (task ? `Task ${task.taskIdentifier()}` : "Unknown Task");
                    console.log(`[!] Error in didCompleteWithError for Task ${taskIdStr}: ${e.message} \n Stack: ${e.stack}`);
                    // Optionally send script error message
                    console.log(JSON.stringify({ script_error: `didComplete Processing Error: ${e.message}` }));
                } finally {
                    // Clean up stored data for this task ID
                    if (taskId !== undefined && taskDataStore[taskId]) {
                        delete taskDataStore[taskId];
                    }
                }
            }
        });
        console.log(`[*] Attached accurate data interceptor to ${TARGET_CLASS} ${didCompleteSig}`);
    } else {
        console.log(`[!] Method not found: ${TARGET_CLASS} ${didCompleteSig}`);
    }

    console.log("[*] Accurate Alamofire network interception script attached. Waiting for activity...");

})();