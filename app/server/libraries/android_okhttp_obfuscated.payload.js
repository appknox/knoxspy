(function () {
  function getJavaApi() {
    if (typeof Java !== "undefined") return Java;
    if (typeof globalThis !== "undefined" && globalThis.Java) return globalThis.Java;
    return null;
  }

  function startWithRetry(remainingRetries) {
    var JavaApi = getJavaApi();
    if (!JavaApi || !JavaApi.available) {
      if (remainingRetries > 0) {
        setTimeout(function () {
          startWithRetry(remainingRetries - 1);
        }, 250);
        return;
      }
      var unavailableMsg = "Java bridge not available in current process/session";
      console.log("[okhttp-obf] " + unavailableMsg);
      if (typeof send === "function") {
        send(JSON.stringify({ error: unavailableMsg }));
      }
      return;
    }

    JavaApi.perform(function () {
      var Java = JavaApi;
      var JArray = Java.use("java.lang.reflect.Array");
      var JArrays = Java.use("java.util.Arrays");
      var JString = Java.use("java.lang.String");
      var ObfRequest = Java.use("okhttp3.v");
      var ObfRequestBody = Java.use("okhttp3.w");
      var ObfResponseBody = Java.use("okhttp3.y");
      var ObfByteString = Java.use("i.h");
      var codecState = {};
      var pendingBodies = {};
      var pendingSources = {};
      var inSourceReadHook = false;
      var MAX_RESPONSE_CAPTURE_BYTES = 262144;

      function safeToString(value) {
        if (value === null || value === undefined) return "";
        try {
          return value.toString();
        } catch (e) {
          return "";
        }
      }

      function objId(obj) {
        if (!obj) return "null";
        try {
          return safeToString(obj.hashCode());
        } catch (e) {
          return safeToString(obj);
        }
      }

      function looksLikeObjectAddress(text) {
        return /^[\w.$]+@[0-9a-f]+$/i.test(text || "");
      }

      function parseUrl(url) {
        var out = { protocol: "", host: "", endpoint: "" };
        if (!url) return out;

        var re = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^\/?#]+)([^?#]*)(\?[^#]*)?/;
        var m = re.exec(url);
        if (!m) {
          out.endpoint = url;
          return out;
        }

        out.protocol = m[1] || "";
        out.host = m[2] || "";
        out.endpoint = (m[3] && m[3].length ? m[3] : "/") + (m[4] || "");
        return out;
      }

      function eachField(obj, callback) {
        if (!obj) return;
        var cls = obj.getClass();
        while (cls !== null) {
          var fields = cls.getDeclaredFields();
          for (var i = 0; i < fields.length; i++) {
            try {
              fields[i].setAccessible(true);
              callback(fields[i]);
            } catch (e) {}
          }
          try {
            cls = cls.getSuperclass();
          } catch (e2) {
            break;
          }
        }
      }

      function getFirstFieldByType(obj, typeName) {
        var found = null;
        eachField(obj, function (field) {
          if (found !== null) return;
          try {
            if (field.getType().getName() === typeName) {
              found = field.get(obj);
            }
          } catch (e) {}
        });
        return found;
      }

      function getHttpMethodFromFields(reqObj) {
        var method = "";
        eachField(reqObj, function (field) {
          if (method) return;
          try {
            if (field.getType().getName() !== "java.lang.String") return;
            var v = safeToString(field.get(reqObj)).toUpperCase();
            if (/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)$/.test(v)) {
              method = v;
            }
          } catch (e) {}
        });
        return method;
      }

      function decodeByteArray(bytes) {
        if (!bytes) return "";
        try {
          return JString.$new(bytes, "UTF-8").toString();
        } catch (e) {
          try {
            return JString.$new(bytes).toString();
          } catch (e2) {
            return "";
          }
        }
      }

      function bytesToDisplay(bytes) {
        if (!bytes) return "";
        var asText = decodeByteArray(bytes);
        if (!asText) return "";
        var nonPrintable = asText.replace(/[\x09\x0a\x0d\x20-\x7e]/g, "");
        if (nonPrintable.length === 0) return asText;
        try {
          return "[binary " + JArray.getLength(bytes) + " bytes]";
        } catch (e) {
          return "[binary]";
        }
      }

      function decodeByteString(bsObj) {
        if (!bsObj) return "";
        try {
          bsObj = Java.cast(bsObj, ObfByteString);
        } catch (castErr) {}
        try {
          var b1 = bsObj.f();
          var t1 = bytesToDisplay(b1);
          if (t1) return t1;
        } catch (e1) {}
        try {
          var b2 = bsObj.k();
          var t2 = bytesToDisplay(b2);
          if (t2) return t2;
        } catch (e2) {}
        try {
          var b3 = bsObj.w();
          var t3 = bytesToDisplay(b3);
          if (t3) return t3;
        } catch (e3) {}
        try {
          var s = safeToString(bsObj.i());
          if (s && !looksLikeObjectAddress(s)) return s;
        } catch (e4) {}
        try {
          var s2 = safeToString(bsObj.x());
          if (s2 && !looksLikeObjectAddress(s2)) return s2;
        } catch (e5) {}
        return "";
      }

      function extractBodyViaWriteTo(bodyObj) {
        if (!bodyObj) return "";
        try {
          try {
            bodyObj = Java.cast(bodyObj, ObfRequestBody);
          } catch (castErr) {}
          var BufferClass = Java.use("i.e");
          var buffer = BufferClass.$new();
          try {
            bodyObj.writeTo(buffer);
          } catch (e1) {
            try {
              bodyObj.writeTo.overload("i.f").call(bodyObj, buffer);
            } catch (e2) {
              return "";
            }
          }
          try {
            var raw = buffer.J();
            var decoded = bytesToDisplay(raw);
            if (decoded) return decoded;
          } catch (e3) {}
          try {
            var txt = safeToString(buffer.B0());
            if (txt && !looksLikeObjectAddress(txt)) return txt;
          } catch (e4) {}
        } catch (e) {}
        return "";
      }

      function extractRequestBody(bodyObj) {
        if (!bodyObj) return "";

        var bestText = "";
        var bestLen = -1;

        eachField(bodyObj, function (field) {
          try {
            var t = field.getType().getName();
            var v = field.get(bodyObj);
            if (v === null || v === undefined) return;

            if (t === "[B") {
              var decoded = bytesToDisplay(v);
              if (decoded && decoded.length > bestLen) {
                bestText = decoded;
                bestLen = decoded.length;
              }
              return;
            }

            if (t === "i.h") {
              var bsText = decodeByteString(v);
              if (bsText && bsText.length > bestLen) {
                bestText = bsText;
                bestLen = bsText.length;
              }
              return;
            }

            if (t === "java.lang.String") {
              var s = safeToString(v);
              if (s && !looksLikeObjectAddress(s) && s.length > bestLen) {
                bestText = s;
                bestLen = s.length;
              }
            }
          } catch (e) {}
        });

        if (bestText) return bestText;

        var viaWriteTo = extractBodyViaWriteTo(bodyObj);
        if (viaWriteTo) return viaWriteTo;

        var fallback = safeToString(bodyObj);
        return looksLikeObjectAddress(fallback) ? "" : fallback;
      }

      function headersToArray(headersObj) {
        var result = [];
        if (!headersObj) return result;

        var namesAndValues = null;
        eachField(headersObj, function (field) {
          if (namesAndValues !== null) return;
          try {
            if (field.getType().getName() === "[Ljava.lang.String;") {
              namesAndValues = field.get(headersObj);
            }
          } catch (e) {}
        });

        if (namesAndValues !== null) {
          try {
            var len = JArray.getLength(namesAndValues);
            for (var i = 0; i + 1 < len; i += 2) {
              var key = safeToString(JArray.get(namesAndValues, i));
              var value = safeToString(JArray.get(namesAndValues, i + 1));
              if (key) result.push(key + ": " + value);
            }
          } catch (e2) {}
        }

        if (result.length === 0) {
          var txt = safeToString(headersObj);
          if (txt) {
            var lines = txt.split("\n");
            for (var j = 0; j < lines.length; j++) {
              var line = lines[j].trim();
              if (line.indexOf(":") > 0) result.push(line);
            }
          }
        }

        return result;
      }

      function getHeaderValue(headersArr, keyLower) {
        if (!headersArr || !keyLower) return "";
        for (var i = 0; i < headersArr.length; i++) {
          var line = safeToString(headersArr[i]);
          var idx = line.indexOf(":");
          if (idx <= 0) continue;
          var k = line.slice(0, idx).trim().toLowerCase();
          if (k === keyLower) return line.slice(idx + 1).trim();
        }
        return "";
      }

      function isBinaryContentType(contentType) {
        var ct = safeToString(contentType).toLowerCase();
        if (!ct) return false;
        return (
          ct.indexOf("application/zip") >= 0 ||
          ct.indexOf("application/octet-stream") >= 0 ||
          ct.indexOf("application/pdf") >= 0 ||
          ct.indexOf("image/") >= 0 ||
          ct.indexOf("audio/") >= 0 ||
          ct.indexOf("video/") >= 0
        );
      }

      function extractResponseBodyViaSource(bodyObj, responseHeaders) {
        if (!bodyObj) return "";

        var ct = getHeaderValue(responseHeaders || [], "content-type");
        if (isBinaryContentType(ct)) return "";

        try {
          try {
            bodyObj = Java.cast(bodyObj, ObfResponseBody);
          } catch (castErr) {}

          var source = bodyObj.source();
          if (!source) return "";

          // Non-consuming snapshot strategy: fill upstream buffer, clone it, read from clone.
          try {
            source.request(MAX_RESPONSE_CAPTURE_BYTES);
          } catch (requestErr) {
            try {
              source.request(1);
            } catch (requestErr2) {}
          }

          var buffer = source.h();
          if (!buffer) return "";

          var cloned = buffer.clone();
          var total = parseInt(safeToString(cloned.c()), 10);
          if (isNaN(total) || total <= 0) return "";

          var take = total > MAX_RESPONSE_CAPTURE_BYTES ? MAX_RESPONSE_CAPTURE_BYTES : total;
          var raw = cloned.N(take);
          var bodyText = bytesToDisplay(raw);

          if (bodyText && total > take) {
            bodyText += "\n[truncated " + (total - take) + " bytes]";
          }
          return bodyText || "";
        } catch (e) {}

        return "";
      }

      function extractRequest(reqObj) {
        var req = {
          method: "",
          protocol: "",
          host: "",
          endpoint: "",
          request_headers: [],
          request_body: "",
          _url: ""
        };

        if (!reqObj) return req;

        try {
          try {
            reqObj = Java.cast(reqObj, ObfRequest);
          } catch (castErr) {}

          req.method = safeToString(reqObj.g());
          var urlObj = reqObj.j();
          var headersObj = reqObj.e();
          var bodyObj = reqObj.a();

          if (!req.method) req.method = getHttpMethodFromFields(reqObj);
          if (!urlObj) urlObj = getFirstFieldByType(reqObj, "okhttp3.p");
          if (!headersObj) headersObj = getFirstFieldByType(reqObj, "okhttp3.o");
          if (!bodyObj) bodyObj = getFirstFieldByType(reqObj, "okhttp3.w");

          req._url = safeToString(urlObj);
          var parsed = parseUrl(req._url);
          req.protocol = parsed.protocol;
          req.host = parsed.host;
          req.endpoint = parsed.endpoint;
          req.request_headers = headersToArray(headersObj);
          req.request_body = extractRequestBody(bodyObj);

          if (req.host) {
            var hasHost = false;
            for (var i = 0; i < req.request_headers.length; i++) {
              if (req.request_headers[i].toLowerCase().indexOf("host:") === 0) {
                hasHost = true;
                break;
              }
            }
            if (!hasHost) req.request_headers.unshift("Host: " + req.host);
          }
        } catch (e) {}

        return req;
      }

      function applyRequestLine(req, requestLine) {
        if (!requestLine || !req) return;
        var m = /^([A-Z]+)\s+(\S+)\s+HTTP\/[0-9.]+/.exec(requestLine);
        if (!m) return;
        req.method = m[1] || req.method;
        req.endpoint = m[2] || req.endpoint;
      }

      function protocolString(protocolObj, responseToString) {
        var p = safeToString(protocolObj);
        if (!p && responseToString) {
          var pm = /protocol=([^,}]+)/.exec(responseToString);
          if (pm && pm[1]) p = pm[1];
        }
        if (!p) return "HTTP/1.1";
        p = p.toUpperCase();
        if (p.indexOf("HTTP_") === 0) p = p.replace("HTTP_", "HTTP/").replace(/_/g, ".");
        return p;
      }

      function extractResponse(respObj) {
        var out = {
          status_code: 0,
          message: "",
          response_headers: [],
          response_body: "",
          request_obj: null,
          body_obj: null
        };

        if (!respObj) return out;

        var responseText = safeToString(respObj);
        var protoObj = getFirstFieldByType(respObj, "okhttp3.t");
        var headersObj = getFirstFieldByType(respObj, "okhttp3.o");
        out.body_obj = getFirstFieldByType(respObj, "okhttp3.y");
        out.request_obj = getFirstFieldByType(respObj, "okhttp3.v");

        eachField(respObj, function (field) {
          try {
            var t = field.getType().getName();
            var value = field.get(respObj);
            if (!out.status_code && t === "int") {
              var code = parseInt(safeToString(value), 10);
              if (!isNaN(code) && code >= 100 && code <= 599) out.status_code = code;
            }
            if (!out.message && t === "java.lang.String") {
              var s = safeToString(value);
              if (s && s.length < 120 && s.indexOf("http") === -1) out.message = s;
            }
          } catch (e) {}
        });

        if (!out.status_code && responseText) {
          var cm = /code=(\d{3})/.exec(responseText);
          if (cm && cm[1]) out.status_code = parseInt(cm[1], 10);
        }
        if (!out.message && responseText) {
          var mm = /message=([^,}]+)/.exec(responseText);
          if (mm && mm[1]) out.message = mm[1];
        }

        out.response_headers = headersToArray(headersObj);
        if (out.status_code) {
          var statusLine =
            protocolString(protoObj, responseText) +
            " " +
            out.status_code +
            (out.message ? " " + out.message : "");
          out.response_headers.unshift(statusLine);
        }

        return out;
      }

      function sendPayload(req, resp) {
        var payload = {
          method: req.method || "",
          protocol: req.protocol || "",
          host: req.host || "",
          endpoint: req.endpoint || "",
          request_headers: JSON.stringify(req.request_headers || []),
          request_body: req.request_body || "",
          status_code: resp.status_code || 0,
          response_headers: JSON.stringify(resp.response_headers || []),
          response_body: resp.response_body || ""
        };
        send(JSON.stringify(payload));
      }

      function flushPendingBody(bodyId) {
        var pending = pendingBodies[bodyId];
        if (!pending) return;
        var sourceIds = Object.keys(pendingSources);
        for (var i = 0; i < sourceIds.length; i++) {
          if (pendingSources[sourceIds[i]] === bodyId) delete pendingSources[sourceIds[i]];
        }
        if (!pending.resp.response_body) {
          pending.resp.response_body = extractResponseBodyViaSource(
            pending.bodyObj,
            pending.resp.response_headers || []
          );
        }
        sendPayload(pending.req, pending.resp);
        delete pendingBodies[bodyId];
      }

      function appendResponseChunkFromRead(sourceObj, sinkObj, bytesRead) {
        if (!sourceObj || !sinkObj) return;
        var readLen = parseInt(safeToString(bytesRead), 10);
        if (isNaN(readLen) || readLen <= 0) return;

        var bid = pendingSources[objId(sourceObj)];
        if (!bid) return;
        var pending = pendingBodies[bid];
        if (!pending || pending.isBinary) return;

        if (inSourceReadHook) return;
        inSourceReadHook = true;
        try {
          var cloned = sinkObj.clone();
          var all = cloned.J();
          var total = JArray.getLength(all);
          if (total <= 0) return;

          var start = total - readLen;
          if (start < 0) start = 0;
          var chunkBytes = JArrays.copyOfRange(all, start, total);
          var chunk = bytesToDisplay(chunkBytes);
          if (!chunk) return;

          var next = (pending.resp.response_body || "") + chunk;
          if (next.length > MAX_RESPONSE_CAPTURE_BYTES) {
            pending.resp.response_body = next.slice(0, MAX_RESPONSE_CAPTURE_BYTES) + "\n[truncated]";
          } else {
            pending.resp.response_body = next;
          }
        } catch (e) {
        } finally {
          inSourceReadHook = false;
        }
      }

      function installResponseSourceHooks() {
        function hookSourceClass(className) {
          try {
            var Source = Java.use(className);
            var readOv = Source.read.overload("i.e", "long");
            readOv.implementation = function (sink, byteCount) {
              var ret = readOv.call(this, sink, byteCount);
              try {
                appendResponseChunkFromRead(this, sink, ret);
              } catch (e) {
              }
              return ret;
            };

            var closeOv = Source.close.overload();
            closeOv.implementation = function () {
              var sourceId = objId(this);
              var bid = pendingSources[sourceId];
              var ret = closeOv.call(this);
              if (bid) flushPendingBody(bid);
              return ret;
            };
          } catch (e) {
            console.log("[okhttp-obf] Failed hooking source class " + className + ": " + e);
          }
        }

        hookSourceClass("okhttp3.c0.d.a$c");
        hookSourceClass("okhttp3.c0.d.a$d");
      }

      function installResponseBodyHooks() {
        try {
          var RespBody = Java.use("okhttp3.y");

          var stringOv = RespBody.string.overload();
          stringOv.implementation = function () {
            var bid = objId(this);
            var ret = stringOv.call(this);
            var pending = pendingBodies[bid];
            if (pending) {
              pending.resp.response_body = safeToString(ret);
              flushPendingBody(bid);
            }
            return ret;
          };

          var bytesOv = RespBody.bytes.overload();
          bytesOv.implementation = function () {
            var bid = objId(this);
            var ret = bytesOv.call(this);
            var pending = pendingBodies[bid];
            if (pending) {
              pending.resp.response_body = decodeByteArray(ret);
              flushPendingBody(bid);
            }
            return ret;
          };
        } catch (e) {
          console.log("[okhttp-obf] Failed hooking okhttp3.y body readers: " + e);
        }
      }

      installResponseBodyHooks();
      installResponseSourceHooks();

      try {
        var ObfOkHttpClient = Java.use("okhttp3.s");
        var obfNewCall = ObfOkHttpClient.newCall.overload("okhttp3.v");
        obfNewCall.implementation = function (reqObj) {
          var callObj = obfNewCall.call(this, reqObj);
          try {
            var callId = objId(callObj);
            var reqInfo = extractRequest(reqObj);
            codecState["call:" + callId] = codecState["call:" + callId] || {};
            codecState["call:" + callId].request = reqInfo;
          } catch (e) {}
          return callObj;
        };
      } catch (e1) {
        console.log("[okhttp-obf] Failed hooking okhttp3.s.newCall: " + e1);
      }

      try {
        var ObfRealCall = Java.use("okhttp3.u");
        var obfExecute = ObfRealCall.execute.overload();
        obfExecute.implementation = function () {
          return obfExecute.call(this);
        };
        var obfEnqueue = ObfRealCall.enqueue.overload("okhttp3.Callback");
        obfEnqueue.implementation = function (cb) {
          return obfEnqueue.call(this, cb);
        };
      } catch (e2) {
        console.log("[okhttp-obf] Failed hooking okhttp3.u execute/enqueue: " + e2);
      }

      try {
        var ObfCodec = Java.use("okhttp3.c0.d.a");

        var writeHeaders = ObfCodec.writeRequestHeaders.overload("okhttp3.v");
        writeHeaders.implementation = function (reqObj) {
          var codecId = objId(this);
          try {
            codecState[codecId] = codecState[codecId] || {};
            codecState[codecId].request = extractRequest(reqObj);
          } catch (e) {}
          return writeHeaders.call(this, reqObj);
        };

        if (ObfCodec.v && ObfCodec.v.overloads) {
          ObfCodec.v.overloads.forEach(function (ov) {
            var args = ov.argumentTypes || [];
            if (
              args.length === 2 &&
              args[0].className === "okhttp3.o" &&
              args[1].className === "java.lang.String"
            ) {
              ov.implementation = function (headersObj, requestLine) {
                var codecId = objId(this);
                try {
                  codecState[codecId] = codecState[codecId] || {};
                  codecState[codecId].requestLine = safeToString(requestLine);
                  if (!codecState[codecId].request) {
                    codecState[codecId].request = {
                      method: "",
                      protocol: "",
                      host: "",
                      endpoint: "",
                      request_headers: headersToArray(headersObj),
                      request_body: "",
                      _url: ""
                    };
                  }
                  applyRequestLine(codecState[codecId].request, codecState[codecId].requestLine);
                } catch (e) {}
                return ov.call(this, headersObj, requestLine);
              };
            }
          });
        }

        var openBodySource = ObfCodec.openResponseBodySource.overload("okhttp3.x");
        openBodySource.implementation = function (respObj) {
          var result = openBodySource.call(this, respObj);
          var codecId = objId(this);

          try {
            var state = codecState[codecId] || {};
            var resp = extractResponse(respObj);
            var req = state.request || extractRequest(resp.request_obj);
            applyRequestLine(req, state.requestLine || "");

            if (resp.body_obj) {
              var bid = objId(resp.body_obj);
              pendingBodies[bid] = {
                req: req,
                bodyObj: resp.body_obj,
                isBinary: isBinaryContentType(getHeaderValue(resp.response_headers || [], "content-type")),
                resp: {
                  status_code: resp.status_code,
                  message: resp.message,
                  response_headers: resp.response_headers,
                  response_body: ""
                }
              };
              if (result) pendingSources[objId(result)] = bid;
              setTimeout(function () {
                flushPendingBody(bid);
              }, 8000);
            } else {
              sendPayload(req, resp);
            }

            delete codecState[codecId];
          } catch (e) {
            console.log("[okhttp-obf] openResponseBodySource payload error: " + e);
          }

          return result;
        };
      } catch (e3) {
        console.log("[okhttp-obf] Failed hooking okhttp3.c0.d.a: " + e3);
      }
    });
  }

  var initialDelayMs = 5000;
  console.log("[okhttp-obf] Delaying hook startup by " + initialDelayMs + "ms");
  setTimeout(function () {
    startWithRetry(60);
  }, initialDelayMs);
})();
