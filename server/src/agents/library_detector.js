function delay(seconds) {
    return new Promise(resolve => setTimeout(resolve, seconds * 1000));
}

var libraryStatus = [];

async function detectLibraries() {
    await delay(5);

    if (Java.available) {
        Java.perform(function () {
            try {
                Java.use("okhttp3.OkHttpClient");
                libraryStatus.push({ name: 'okhttp3', status: true , platform: 'android' });
            } catch (e) {
                libraryStatus.push({ name: 'okhttp3', status: false , platform: 'android' });
            }
            send(JSON.stringify(libraryStatus));
        });
    } else if (ObjC.available) {
        // console.log("Platform: iOS");
        var loadedLibraries = [
            { name: 'Alamofire', status: ObjC.classes['Alamofire.Request'] ? true : false , platform: 'iOS' },
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
