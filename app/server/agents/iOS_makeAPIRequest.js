function httpRequest(input) {
    const {
        protocol,
        host,
        endpoint,
        method,
        request_headers,
        request_body,
        id,
        session_id,
    } = input;

    const url = `${protocol}://${host}${endpoint}`;
	console.log("[*] URL: " + url);
    const NSString = ObjC.classes.NSString;
    const NSURL = ObjC.classes.NSURL;
    const NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
    const NSJSONSerialization = ObjC.classes.NSJSONSerialization;
    const NSData = ObjC.classes.NSData;
    const NSURLSession = ObjC.classes.NSURLSession;
    const NSDictionary = ObjC.classes.NSDictionary;
    const NSArray = ObjC.classes.NSArray;

	const nsStr = NSString.stringWithUTF8String_(Memory.allocUtf8String(url));
	const nsURL = NSURL.URLWithString_(nsStr);

    const request = NSMutableURLRequest.requestWithURL_(nsURL);
	const methodPtr = Memory.allocUtf8String(method);
	const nsMethod = NSString.stringWithUTF8String_(methodPtr);
	console.log("Setting HTTP Method: " + nsMethod);
	request.setHTTPMethod_(nsMethod);

    // // --- Headers ---
    const headersArray = JSON.parse(request_headers); // Expecting: ["Header: Value", ...]
    const headerDict = {};
    headersArray.forEach(h => {
        const [key, ...valParts] = h.split(":");
        const val = valParts.join(":").trim();
        headerDict[key.trim()] = val;
    });
	console.log("Headers: " + JSON.stringify(headerDict));

    const headerObj = ObjC.classes.NSMutableDictionary.alloc().init();
    for (const key in headerDict) {
        const keyPtr = Memory.allocUtf8String(key);
        const valPtr = Memory.allocUtf8String(headerDict[key]);
        const nsKey = NSString.stringWithUTF8String_(keyPtr);
        const nsVal = NSString.stringWithUTF8String_(valPtr);
        headerObj.setObject_forKey_(nsVal, nsKey);
    }
    request.setAllHTTPHeaderFields_(headerObj);

    // // --- Body ---
    if (["POST", "PUT", "PATCH"].includes(method.toUpperCase()) && request_body) {
        const bodyData = NSString.stringWithUTF8String_(Memory.allocUtf8String(request_body)).dataUsingEncoding_(4); // 4 = UTF8
        request.setHTTPBody_(bodyData);
    }

    // --- Start Request ---
    const session = NSURLSession.sharedSession();

    const task = session.dataTaskWithRequest_completionHandler_(
        request,
        new ObjC.Block({
            retType: 'void',
            argTypes: ['object', 'object', 'object'],
            implementation: function (data, response, error) {
				const payload = Object.assign({}, input);
				payload.status_code = '';
				payload.response_body = '';
				payload.response_headers = '';

                if (error && !error.isNull()) {
                    const errObj = new ObjC.Object(error);
                    payload.response_body = errObj.localizedDescription().toString();
                    payload.status_code = -1;
                }

                if (response && !response.isNull()) {
                    const res = new ObjC.Object(response);
					try {
						payload.status_code = res.statusCode().toString();
						console.log("Status Code: " + payload.status_code);

						const headers = res.allHeaderFields();
						const headerDict = new ObjC.Object(headers);
						const keys = headerDict.allKeys();
						const count = keys.count();
						const headerList = [];

						for (let i = 0; i < count; i++) {
							const key = keys.objectAtIndex_(i).toString();
							const value = headerDict.objectForKey_(keys.objectAtIndex_(i)).toString();
							headerList.push(`${key}: ${value}`);
						}
						payload.response_headers = JSON.stringify(headerList);
						console.log("Response Headers: " + payload.response_headers);
					} catch (e) {
						console.error("Error processing response headers:", e);
						console.log(e);
					}
                }

                if (data && !data.isNull()) {
                    const nsData = new ObjC.Object(data);
                    const str = nsData.bytes().readUtf8String(nsData.length());
                    payload.response_body = str;
                }

                send(JSON.stringify(payload));
            }
        })
    );

    task.resume();
}

const input = {
  id: 42,
  protocol: 'https',
  host: 'jsonplaceholder.typicode.com',
  status_code: '',
  response_body: '',
  response_headers: '',
  session_id: 15,
  method: 'GET',
  endpoint: '/todos/1',
  request_headers: '["Host: jsonplaceholder.typicode.com","Content-Type: application/json"]',
  request_body: ''
};

recv('data', function(message) {
	const input = message.payload;
	console.log("[*] Received message: " + JSON.stringify(input));
	httpRequest(input);
	
	// ObjC.schedule(ObjC.mainQueue, function () {
    // try {
    // } catch (e) {
    //     console.error("Error processing request:", e);
    // }
});
