"use strict";
// class RequestHandler {
//     private jsonPayload: { [key: string]: any } = {};
//     private NSURL: ObjC.Object['NSURL'];
//     private NSURLRequest: ObjC.Object['NSURLRequest'];
//     private NSURLSession: ObjC.Object['NSURLSession'];
//     private NSDictionary: ObjC.Object['NSDictionary'];
//     private NSMutableDictionary: ObjC.Object['NSMutableDictionary'];
//     private NSString: ObjC.Object['NSString'];
//     private NSMutableURLRequest: ObjC.Object['NSMutableURLRequest'];
//     private configuration: ObjC.Object['configuration'];
//     private completionHandler!: ObjC.Block;
//     constructor() {
//         if (ObjC.available) {
//             this.NSURL = ObjC.classes.NSURL;
//             this.NSURLRequest = ObjC.classes.NSURLRequest;
//             this.NSURLSession = ObjC.classes.NSURLSession;
//             this.NSDictionary = ObjC.classes.NSDictionary;
//             this.NSMutableDictionary = ObjC.classes.NSMutableDictionary;
//             this.NSString = ObjC.classes.NSString;
//             this.NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
//             this.configuration = ObjC.classes.NSURLSessionConfiguration;
//             this.setupCompletionHandler();
//         } else {
//             console.error("Objective-C runtime not available.");
//         }
//     }
//     private setupCompletionHandler() {
//         this.completionHandler = new ObjC.Block({
//             retType: 'void',
//             argTypes: ['pointer', 'pointer', 'pointer'],
//             implementation: (data: any, response: any, error: any) => {
//                 if (!data.isNull()) {
//                     const responseObj = new ObjC.Object(response);
//                     if (responseObj.isKindOfClass_(ObjC.classes.NSHTTPURLResponse)) {
//                         const httpResponse = new ObjC.Object(responseObj);
//                         const url = httpResponse.URL().absoluteString().toString();
//                         const headers = httpResponse.allHeaderFields();
//                         const statusCode = httpResponse.statusCode();
//                         const urlHost = url.split("/")[2];
//                         const urlEndpoint = "/" + url.split("/").slice(3).join("/");
//                         const headersList: string[] = [];
//                         if (headers) {
//                             const keys = headers.allKeys();
//                             for (let i = 0; i < keys.count(); i++) {
//                                 const key = keys.objectAtIndex_(i).toString();
//                                 const value = headers.objectForKey_(key).toString();
//                                 headersList.push(`${key}: ${value}`);
//                             }
//                         }
//                         this.jsonPayload['host'] = urlHost;
//                         this.jsonPayload['endpoint'] = urlEndpoint;
//                         this.jsonPayload['status_code'] = statusCode;
//                         this.jsonPayload['response_headers'] = headersList;
//                     }
//                     const dataObj = new ObjC.Object(data);
//                     const jsonString = this.NSString.alloc().initWithData_encoding_(dataObj, 4);
//                     this.jsonPayload['request_body'] = "";
//                     this.jsonPayload['response_body'] = jsonString.toString();
//                     send(JSON.stringify(this.jsonPayload));
//                 } else {
//                     console.error("Error: " + error);
//                 }
//             },
//         });
//     }
//     public makeGETRequest(requestUrl: string, requestHeaders: { [key: string]: string }) {
//         const configuration = this.configuration.defaultSessionConfiguration();
//         const session = this.NSURLSession.sessionWithConfiguration_delegate_delegateQueue_(configuration, null, null);
//         const urlString = this.NSString.stringWithString_(requestUrl);
//         const url = this.NSURL.URLWithString_(urlString);
//         const request = this.NSMutableURLRequest.requestWithURL_(url);
//         const headersDict = this.NSMutableDictionary.alloc().init();
//         for (const key in requestHeaders) {
//             const value = requestHeaders[key];
//             headersDict.setValue_forKey_(this.NSString.stringWithString_(value), this.NSString.stringWithString_(key));
//         }
//         // Set request headers
//         request.setAllHTTPHeaderFields_(headersDict);
//         const headersList: string[] = [];
//         const tmpHeaders = request.allHTTPHeaderFields();
//         const keys = tmpHeaders.allKeys();
//         for (let i = 0; i < keys.count(); i++) {
//             const key = keys.objectAtIndex_(i).toString();
//             const value = tmpHeaders.objectForKey_(key).toString();
//             headersList.push(`${key}: ${value}`)
//             // console.log(key + ": " + value);
//         }
//         this.jsonPayload['request_headers'] = headersList
//         this.jsonPayload['method'] = "GET"
//         const dataTask = session.dataTaskWithRequest_completionHandler_(request, this.completionHandler);
//         // console.log(configuration.getValue_forKey_('httpAdditionalHeaders'))
//         dataTask.resume();
//         console.log(request.allHTTPHeaderFields())
//     }
// }
// const requestHandler = new RequestHandler();
// requestHandler.makeGETRequest("http://192.168.29.200:8000/", { "Authorization": "test" });
