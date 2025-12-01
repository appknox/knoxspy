📦
9992 /agent/index.js
5919 /agent/index.js.map
✄
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};

// frida-builtins:/node-globals.js
var init_node_globals = __esm({
  "frida-builtins:/node-globals.js"() {
    "use strict";
  }
});

// agent/index.ts
var require_index = __commonJS({
  "agent/index.ts"() {
    init_node_globals();
    var writeDict = {};
    var readDict = {};
    var activeWriteThreads = {};
    var sslWriteDict = {};
    var sslReadDict = {};
    var libFlutter = Process.getModuleByName("libflutter.so");
    var libc = Process.getModuleByName("libc.so");
    function byteArrayToString(byteArray) {
      return Array.from(new Uint8Array(byteArray)).map((byte) => String.fromCharCode(byte)).join("");
    }
    function parseHeadersAndBody(raw) {
      if (!raw)
        return { headers: "", body: "" };
      const splitIndex = raw.indexOf("\r\n\r\n");
      if (splitIndex !== -1) {
        return {
          headers: raw.substring(0, splitIndex),
          body: raw.substring(splitIndex + 4)
        };
      } else {
        return { headers: raw, body: "" };
      }
    }
    function isValidHttpContent(content) {
      if (!content || content.length < 4)
        return false;
      const httpMethods = ["GET ", "POST", "PUT ", "DELETE ", "HEAD", "PATCH", "OPTIONS", "CONNECT", "TRACE"];
      const httpResponses = ["HTTP/"];
      for (const method of httpMethods) {
        if (content.startsWith(method))
          return true;
      }
      for (const response of httpResponses) {
        if (content.startsWith(response))
          return true;
      }
      return false;
    }
    function completePair(writeData, readData, protocol, identifier, reason, cleanup) {
      if (!writeData && !readData)
        return;
      console.log(`=== ${protocol.toUpperCase()} Request-Response Pair (${protocol === "http" ? "fd" : "SSL"}: ${identifier}) ===`);
      console.log(`Completion Reason: ${reason}`);
      console.log(`Timestamp: ${(/* @__PURE__ */ new Date()).toISOString()}`);
      if (writeData) {
        console.log("--- REQUEST ---");
        console.log(writeData);
      }
      if (readData) {
        console.log("--- RESPONSE ---");
        console.log(readData);
      }
      console.log("==================================================");
      try {
        const req = parseHeadersAndBody(writeData || "");
        const resp = parseHeadersAndBody(readData || "");
        let method = "", host = "", endpoint = "";
        const reqLines = req.headers.split("\r\n");
        const headersArr = [];
        if (reqLines.length > 0) {
          const reqLine = reqLines[0] || "";
          const reqParts = reqLine.split(" ");
          if (reqParts.length >= 2) {
            method = reqParts[0] || "";
            endpoint = reqParts[1] || "";
          }
        }
        for (const line of reqLines.slice(1)) {
          if (line.trim() && line.includes(":")) {
            headersArr.push(line);
            if (line.toLowerCase().startsWith("host:")) {
              host = line.substring(5).trim();
            }
          }
        }
        const respLines = resp.headers.split("\r\n");
        const respHeaders = [];
        let statusCode = 0;
        if (respLines.length > 0) {
          const statusLine = respLines[0] || "";
          respHeaders.push(statusLine);
          const statusMatch = statusLine.match(/\s(\d{3})\s/);
          if (statusMatch && statusMatch[1]) {
            statusCode = parseInt(statusMatch[1], 10);
          }
        }
        for (const line of respLines.slice(1)) {
          if (line.trim() && line.includes(":")) {
            respHeaders.push(line);
          }
        }
        const tmpPayload = {
          method,
          protocol,
          host,
          endpoint,
          request_headers: JSON.stringify(headersArr),
          request_body: req.body,
          status_code: statusCode,
          response_headers: JSON.stringify(respHeaders),
          response_body: resp.body
        };
        if (typeof send === "function") {
          send(JSON.stringify(tmpPayload));
        }
      } catch (e) {
      }
      cleanup();
    }
    function completeHttpPair(fd, reason) {
      completePair(writeDict[fd], readDict[fd], "http", fd, reason, () => {
        delete writeDict[fd];
        delete readDict[fd];
      });
    }
    function completeHttpsPair(ssl_ptr, reason) {
      completePair(sslWriteDict[ssl_ptr], sslReadDict[ssl_ptr], "https", ssl_ptr, reason, () => {
        delete sslWriteDict[ssl_ptr];
        delete sslReadDict[ssl_ptr];
      });
    }
    var Socket_WriteList = libFlutter.base.add(8724264);
    Interceptor.attach(Socket_WriteList, {
      onEnter(args) {
        const tid = Process.getCurrentThreadId();
        activeWriteThreads[tid] = true;
      },
      onLeave(retval) {
        delete activeWriteThreads[Process.getCurrentThreadId()];
      }
    });
    Interceptor.attach(libc.findExportByName("write"), {
      onEnter(args) {
        const tid = Process.getCurrentThreadId();
        if (!activeWriteThreads[tid])
          return;
        const fd = args[0].toInt32();
        const len = args[2].toInt32();
        const byteArray = args[1].readByteArray(len);
        if (!byteArray)
          return;
        const content = byteArrayToString(byteArray);
        if (isValidHttpContent(content)) {
          if (writeDict[fd] && writeDict[fd].length > 0) {
            console.log(`[DEBUG] New request detected on fd=${fd}, completing previous pair`);
            completeHttpPair(fd, "NEW_REQUEST_ON_KEEPALIVE");
          }
          writeDict[fd] = content;
        } else {
          if (writeDict[fd]) {
            writeDict[fd] += content;
          } else {
            console.log(`[DEBUG] Ignoring non-HTTP content for fd: ${fd}`);
          }
        }
        console.log(`[DEBUG] write() captured for fd: ${fd}, length: ${len}`);
      }
    });
    Interceptor.attach(libFlutter.base.add(8748292), {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
      },
      onLeave(retval) {
        const fd = this.fd;
        const bytesRead = retval.toInt32();
        if (bytesRead <= 0)
          return;
        if (!writeDict[fd]) {
          console.log(`[DEBUG] Ignoring response for fd=${fd} (no valid request tracked)`);
          return;
        }
        const byteArray = this.buf.readByteArray(bytesRead);
        if (!byteArray)
          return;
        const chunk = byteArrayToString(byteArray);
        if (!readDict[fd]) {
          readDict[fd] = "";
        }
        readDict[fd] += chunk;
        console.log(`[DEBUG] SocketBase::Read captured for fd: ${fd}, bytes read: ${bytesRead}`);
      }
    });
    Interceptor.attach(libc.findExportByName("close"), {
      onEnter(args) {
        const fd = args[0].toInt32();
        if (writeDict[fd]) {
          console.log(`[DEBUG] close() completing fd=${fd}`);
          completeHttpPair(fd, "CLOSE_DETECTION");
        } else if (readDict[fd]) {
          console.log(`[DEBUG] close() cleaning up orphaned response for fd=${fd}`);
          delete readDict[fd];
        }
      }
    });
    Interceptor.attach(libFlutter.base.add(7421504), {
      onEnter(args) {
        const ssl_ptr = args[0].toString();
        const len = args[2].toInt32();
        const byteArray = args[1].readByteArray(len);
        if (!byteArray)
          return;
        const content = byteArrayToString(byteArray);
        if (isValidHttpContent(content)) {
          if (sslWriteDict[ssl_ptr] && sslWriteDict[ssl_ptr].length > 0) {
            console.log(`[DEBUG] New HTTPS request detected on SSL=${ssl_ptr}, completing previous pair`);
            completeHttpsPair(ssl_ptr, "NEW_REQUEST_ON_KEEPALIVE");
          }
          sslWriteDict[ssl_ptr] = content;
        } else {
          if (sslWriteDict[ssl_ptr]) {
            sslWriteDict[ssl_ptr] += content;
          } else {
            console.log(`[DEBUG] Ignoring non-HTTP content for SSL: ${ssl_ptr}`);
          }
        }
        console.log(`[DEBUG] SSL_write captured for SSL: ${ssl_ptr}, length: ${len}`);
      }
    });
    Interceptor.attach(libFlutter.base.add(7419444), {
      onEnter(args) {
        this.ssl_ptr = args[0].toString();
        this.buf = args[1];
        this.max_len = args[2].toInt32();
      },
      onLeave(retval) {
        const ssl_ptr = this.ssl_ptr;
        const bytesRead = retval.toInt32();
        if (bytesRead <= 0)
          return;
        if (!sslWriteDict[ssl_ptr]) {
          console.log(`[DEBUG] Ignoring HTTPS response for SSL=${ssl_ptr} (no valid request tracked)`);
          return;
        }
        const byteArray = this.buf.readByteArray(bytesRead);
        if (!byteArray)
          return;
        const chunk = byteArrayToString(byteArray);
        if (!sslReadDict[ssl_ptr]) {
          sslReadDict[ssl_ptr] = "";
        }
        sslReadDict[ssl_ptr] += chunk;
        console.log(`[DEBUG] SSL_read captured for SSL: ${ssl_ptr}, bytes read: ${bytesRead}`);
      }
    });
    Interceptor.attach(libFlutter.base.add(7418288), {
      onEnter(args) {
        const ptr = args[0].toString();
        console.log(`[DEBUG] SSL_free called with pointer: ${ptr}`);
        if (sslWriteDict[ptr]) {
          console.log(`[DEBUG] SSL_free completing SSL ptr=${ptr}`);
          completeHttpsPair(ptr, "SSL_FREE_CALLED");
        } else if (sslReadDict[ptr]) {
          console.log(`[DEBUG] SSL_free cleaning up orphaned response for SSL ptr=${ptr}`);
          delete sslReadDict[ptr];
        }
      }
    });
    console.log("[*] Combined HTTP/HTTPS interceptor loaded");
  }
});
export default require_index();

✄
{
  "version": 3,
  "sources": ["frida-builtins:/node-globals.js", "agent/index.ts"],
  "mappings": "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",
  "names": []
}
