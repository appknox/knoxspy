"use strict";
// function delay(seconds: number) {
//     return new Promise(resolve => setTimeout(resolve, seconds * 1000));
// }
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var libraryStatus = {};
function detectLibraries() {
    return __awaiter(this, void 0, void 0, function* () {
        // await delay(5);
        // if (Java.available) {
        //     Java.perform(function () {
        //         try {
        //             Java.use("okhttp3.OkHttpClient");
        //             libraryStatus['okhttp'] = 'loaded';
        //         } catch (e) {
        //             libraryStatus['okhttp'] = 'not loaded';
        //         }
        //         send(JSON.stringify(libraryStatus));
        //     });
        // } else if (ObjC.available) {
        //     var loadedLibraries = [
        //         { name: 'Alamofire', status: ObjC.classes.Alamofire ? true : false , platform: 'iOS' },
        //         { name: 'TrustKit', status: ObjC.classes.TSKPinningValidator ? true : false , platform: 'iOS'  },
        //         { name: 'AFNetworking', status: ObjC.classes.AFHTTPSessionManager ? true : false , platform: 'iOS' },
        //         { name: 'NSURLSession', status: ObjC.classes.NSURLSession ? true : false , platform: 'iOS' }
        //     ];
        //     send(JSON.stringify(loadedLibraries));
        // } else {
        //     // console.log("Platform: Unknown");
        //     send(JSON.stringify(libraryStatus));
        // }
    });
}
detectLibraries();
