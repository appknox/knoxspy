// function delay(seconds: number) {
//     return new Promise(resolve => setTimeout(resolve, seconds * 1000));
// }

var libraryStatus = {};

async function detectLibraries() {
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
}

detectLibraries();
