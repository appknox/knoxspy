function delay(seconds) {
    return new Promise(resolve => setTimeout(resolve, seconds * 1000));
}

var libraryStatus = {};

async function detectLibraries() {
    // Delay to ensure the app has fully loaded
    await delay(5);

    if (Java.available) {
        // console.log("Platform: Android");
        Java.perform(function () {
            try {
                Java.use("okhttp3.OkHttpClient");
                // console.log("okhttp is loaded");
                libraryStatus['okhttp'] = 'loaded';
            } catch (e) {
                // console.log("okhttp is not loaded");
                libraryStatus['okhttp'] = 'not loaded';
            }
            send(JSON.stringify(libraryStatus));
        });
    } else if (ObjC.available) {
        // console.log("Platform: iOS");
        var loadedLibraries = [
            { name: 'Alamofire', status: ObjC.classes.Alamofire ? true : false , platform: 'iOS' },
            { name: 'TrustKit', status: ObjC.classes.TSKPinningValidator ? true : false , platform: 'iOS'  },
            { name: 'AFNetworking', status: ObjC.classes.AFHTTPSessionManager ? true : false , platform: 'iOS' },
            { name: 'NSURLSession', status: ObjC.classes.NSURLSession ? true : false , platform: 'iOS' }
        ];

        send(JSON.stringify(loadedLibraries));
    } else {
        // console.log("Platform: Unknown");
        send(JSON.stringify(libraryStatus));
    }
}

detectLibraries();
