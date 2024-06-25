class RequestHandler {
    constructor() {
        if (ObjC.available) {
            this.NSURL = ObjC.classes.NSURL;
            this.NSURLRequest = ObjC.classes.NSURLRequest;
            this.NSURLSession = ObjC.classes.NSURLSession;
            this.NSDictionary = ObjC.classes.NSDictionary;
            this.NSMutableDictionary = ObjC.classes.NSMutableDictionary;
            this.NSString = ObjC.classes.NSString;
            this.NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
            this.configuration = ObjC.classes.NSURLSessionConfiguration;
            this.jsonPayload = {}
            this.setupCompletionHandler();
        } else {
            console.error("Objective-C runtime not available.");
        }
    }

    setupCompletionHandler() {
        this.completionHandler = new ObjC.Block({
            retType: 'void',
            argTypes: ['pointer', 'pointer', 'pointer'],
            implementation: this.handleResponse.bind(this)
        });
    }

    handleResponse(data, response, error) {
        if (!data.isNull()) {
            const responseObj = new ObjC.Object(response);
            if (responseObj.isKindOfClass_(ObjC.classes.NSHTTPURLResponse)) {
                const httpResponse = ObjC.Object(responseObj);
                var url = httpResponse.URL().absoluteString().toString();
                var headers = httpResponse.allHeaderFields();
                const status_code = httpResponse.statusCode();

                const urlHost = url.split("/")[2];
                const urlEndpoint = "/" + url.split("/").slice(3).join("/");

                var headersList = [];
                if (headers) {
                    var keys = headers.allKeys();
                    for (var i = 0; i < keys.count(); i++) {
                        var key = keys.objectAtIndex_(i).toString();
                        var value = headers.objectForKey_(key).toString();
                        headersList.push(key + ": " + value);
                    }
                }
                this.jsonPayload['host'] = urlHost;
                this.jsonPayload['endpoint'] = urlEndpoint;
                this.jsonPayload['status_code'] = status_code;
            }

            const dataObj = new ObjC.Object(data);
            const jsonString = this.NSString.alloc().initWithData_encoding_(dataObj, 4);

            this.jsonPayload['response_headers'] = headersList;
            this.jsonPayload['request_body'] = "";
            this.jsonPayload['response_body'] = jsonString.toString();
            send(JSON.stringify(this.jsonPayload));
        } else {
            console.error("Error: " + error);
        }
    }

    makeGETRequest(request_url, request_headers) {
        const configuration = this.configuration.defaultSessionConfiguration();
        const session = this.NSURLSession.sessionWithConfiguration_delegate_delegateQueue_(configuration, null, null);
        // const session = this.NSURLSession.sharedSession();
        const urlString = this.NSString.stringWithString_(request_url);
        const url = this.NSURL.URLWithString_(urlString);
        const request = this.NSMutableURLRequest.requestWithURL_(url);


        
        const headersDict = this.NSMutableDictionary.alloc().init();
        for (const key in request_headers) {
            const value = request_headers[key];
            headersDict.setValue_forKey_(this.NSString.stringWithString_(value), this.NSString.stringWithString_(key));
        }

        // Set request headers
        request.setAllHTTPHeaderFields_(headersDict);
        const headersList = []
        var tmpHeaders = request.allHTTPHeaderFields();
        // console.log(tmpHeaders);
        const keys = tmpHeaders.allKeys();
        for (let i = 0; i < keys.count(); i++) {
            const key = keys.objectAtIndex_(i).toString();
            const value = tmpHeaders.objectForKey_(key).toString();
            headersList.push(`${key}: ${value}`)
            // console.log(key + ": " + value);
        }
        this.jsonPayload['request_headers'] = headersList
        
        this.jsonPayload['method'] = "GET"
        const dataTask = session.dataTaskWithRequest_completionHandler_(request, this.completionHandler);
        // console.log(configuration.getValue_forKey_('httpAdditionalHeaders'))
        dataTask.resume();
        console.log(request.allHTTPHeaderFields())
    }
}

const requestHandler = new RequestHandler();
requestHandler.makeGETRequest("http://192.168.29.200:8000/", {"Authorization": "test"});
