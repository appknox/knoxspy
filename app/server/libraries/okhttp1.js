Java.perform(function () {
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var RequestBuilder = Java.use('okhttp3.Request$Builder');
    var RequestBody = Java.use('okhttp3.RequestBody');
    var Buffer = Java.use('okio.Buffer');

    console.log("[*] Hooking OkHttp Request Builders");

    RequestBuilder.build.implementation = function () {
        var request = this.build();
        var method = request.method();
        var url = request.url().toString();

        var requestBody = request.body();
        var bodyStr = "";

        if (requestBody !== null) {
            try {
                var buffer = Buffer.$new();
                requestBody.writeTo(buffer);
                bodyStr = buffer.readUtf8();
            } catch (e) {
                bodyStr = "[Failed to read body]";
            }
        }

        console.log("➡️  HTTP Request:");
        console.log("   Method: " + method);
        console.log("   URL: " + url);
        if (bodyStr.length > 0) {
            console.log("   Body: " + bodyStr);
        } else {
            console.log("   Body: <empty>");
        }

        return request;
    };
});

