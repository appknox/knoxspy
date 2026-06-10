---
name: apk-network-hook-generator
description: >
  Analyzes an Android APK to identify its framework (Native, Flutter, React Native, Xamarin, Cordova),
  detect which libraries or functions handle HTTP/HTTPS requests (OkHttp3, Volley, HttpURLConnection,
  Flutter BoringSSL, or unknown/custom), and generate a Frida hook script that intercepts all network
  traffic and sends it to the KnoxSpy host via send() in the required payload format. Also produces a
  markdown analysis report. Use this skill when the user provides an APK file and wants to intercept
  its HTTP traffic without a proxy.
metadata:
  version: "1.0.0"
  author: knoxspy
  tags:
    - android
    - frida
    - apk
    - network-interception
    - reverse-engineering
compatibility: >
  Requires jadx and apktool in PATH. Requires analyzeHeadless (Ghidra) in PATH only for Flutter apps.
  Also uses nm, readelf, strings, unzip (standard Linux tools).
---

# APK Network Hook Generator

Generate a Frida hook script for any Android APK that intercepts HTTP/HTTPS requests and sends them to KnoxSpy's host.

## Inputs

- `apk_path` (required): Absolute path to the APK file.
- `output_dir` (optional): Where to write outputs. Defaults to `knoxspy_analysis/output/`.

## Payload Format (CRITICAL)

Every generated hook MUST produce this exact JSON structure and call `send()`. This is the format KnoxSpy expects. See `references/android_okhttp.js` lines 85-96 for the canonical implementation.

```javascript
const tmpPayload = {
    method,                                       // "GET", "POST", "PUT", "DELETE", etc.
    protocol,                                     // "http" or "https"
    host: requestHost,                            // "api.example.com"
    endpoint: URL,                                // "/api/v1/users?foo=bar"
    request_headers: JSON.stringify(headersArr),   // JSON string of ["Host: x", "Content-Type: y"]
    request_body: requestBodyString,              // raw request body string
    status_code: responseStatus,                  // integer: 200, 404, etc.
    response_headers: JSON.stringify(respHeaders), // JSON string of ["HTTP/1.1 200 OK", "Key: Val"]
    response_body: responseBodyString             // raw response body string
};
send(JSON.stringify(tmpPayload));
```

## Procedure

### Step 1 — Validate Dependencies

Check that these tools are in `$PATH`:
- `jadx` — if not found, also check `/home/yash/.apklab/jadx-1.5.3/bin/jadx`
- `apktool`

If either is missing, stop and tell the user what to install. Do NOT check for `analyzeHeadless` yet — that is only needed if Flutter is detected later.

### Step 2 — Decompile the APK

Create a working directory and decompile with both tools:

```bash
WORK_DIR="knoxspy_analysis/$(basename $APK_PATH .apk)"
mkdir -p "$WORK_DIR"

# JADX: produces readable Java source from DEX
jadx -d "$WORK_DIR/jadx_output" "$APK_PATH"

# apktool: decodes resources, AndroidManifest.xml, AND produces smali disassembly
# The smali output is at apktool_output/smali/ and apktool_output/smali_classes2/ etc.
# Smali is the exact bytecode representation — it preserves real class/method names
# even when jadx's decompilation is inaccurate or incomplete.
apktool d -f -o "$WORK_DIR/apktool_output" "$APK_PATH"

# Also extract raw APK contents for native lib analysis
mkdir -p "$WORK_DIR/apk_extracted"
unzip -o "$APK_PATH" -d "$WORK_DIR/apk_extracted"
```

**Two complementary sources:**
- `jadx_output/sources/` — Readable Java. Best for understanding logic, identifying patterns.
- `apktool_output/smali*/` — Smali bytecode. Best for exact class/method/field names, especially when obfuscated. Smali always reflects the true DEX contents.

Use both: start with jadx for readability, cross-reference with smali for accuracy.

### Step 3 — Extract APK Metadata

Use `aapt` for quick metadata AND parse the decoded `AndroidManifest.xml` from apktool for full details:

```bash
# Quick metadata via aapt
aapt dump badging "$APK_PATH"

# Full decoded manifest from apktool (already human-readable XML)
cat "$WORK_DIR/apktool_output/AndroidManifest.xml"
```

| Field | How to extract |
|-------|---------------|
| Package name | aapt: `package: name='...'` or manifest `<manifest package="...">` |
| Version name/code | aapt: `versionName='...' versionCode='...'` |
| App label | aapt: `application-label:'...'` |
| Min SDK | aapt: `sdkVersion:'...'` or manifest `<uses-sdk android:minSdkVersion="...">` |
| Target SDK | aapt: `targetSdkVersion:'...'` |
| Permissions | aapt: `uses-permission:` lines or manifest `<uses-permission>` tags |
| Main activity | aapt: `launchable-activity: name='...'` |
| All activities/services | Parse manifest for `<activity>`, `<service>`, `<receiver>` |

### Step 4 — Identify Application Framework

Check the extracted APK contents in this order. First match wins.

**Flutter:**
- `apk_extracted/lib/<any_arch>/libflutter.so` exists
- Usually also has `libapp.so` and `assets/flutter_assets/`

**React Native:**
- `assets/index.android.bundle` exists
- `lib/<arch>/libreactnativejni.so` exists

**Xamarin:**
- `lib/<arch>/libmonodroid.so` exists
- `assemblies/` directory with `.dll` files

**Cordova / Ionic:**
- `assets/www/` directory with `cordova.js` inside

**Native Android (Java/Kotlin):**
- None of the above matched — this is the default.

Record the result as `framework_type`.

### Step 5 — Detect Network Libraries

#### 5A: Java-Layer (for Native Android, React Native, Xamarin, Cordova)

Search `jadx_output/sources/` for these packages/classes in priority order:

1. **OkHttp3 (clean)**: Directory `okhttp3/` exists AND `OkHttpClient.java` exists with that literal name. → `network_lib = "okhttp3"`
2. **OkHttp3 (obfuscated)**: Directory `okhttp3/` exists but classes are single-letter (`s.java`, `v.java`, `u.java`). Confirm by grepping for `newCall`, `Interceptor`, `Builder` inside them. Record the obfuscated name mappings. → `network_lib = "okhttp3_obfuscated"`
3. **Retrofit2**: `retrofit2/` directory exists. Retrofit uses OkHttp under the hood, so check OkHttp obfuscation status. → `network_lib = "retrofit2_over_okhttp"`
4. **Volley**: `com/android/volley/` directory exists. → `network_lib = "volley"`
5. **Apache HTTP**: `org/apache/http/` directory exists. → `network_lib = "apache_http"`
6. **HttpURLConnection**: grep for `HttpURLConnection` usage in source files. → `network_lib = "httpurlconnection"`

**Cross-reference with smali for obfuscated apps:** When jadx output has obfuscated names, verify the real class structure in `apktool_output/smali*/`. Smali files show exact class paths, method signatures, and field types:
```bash
# Find OkHttp-related smali classes
find apktool_output/smali* -path "*/okhttp3/*.smali" | head -20
# Check a specific class for method signatures
grep -n "\.method" apktool_output/smali/okhttp3/s.smali
# Find which obfuscated class has newCall
grep -rl "newCall" apktool_output/smali*/okhttp3/
```
Smali gives definitive method signatures (e.g., `.method public newCall(Lokhttp3/v;)Lokhttp3/d;`) which tell you exact parameter and return types even when jadx guesses wrong.

If NONE found → go to Step 5C.

#### 5B: Native-Layer (for Flutter only)

1. **Now** check that `analyzeHeadless` is in PATH. If not, stop with: "analyzeHeadless (Ghidra) is required for Flutter apps. Add it to PATH."

2. Find symbols in `libflutter.so`:
   ```bash
   ARCH=$(ls apk_extracted/lib/ | head -1)  # e.g., arm64-v8a
   nm -D "apk_extracted/lib/$ARCH/libflutter.so" | grep -iE "ssl_write|ssl_read|ssl_free|socket"
   readelf --dyn-syms "apk_extracted/lib/$ARCH/libflutter.so" | grep -iE "ssl_write|ssl_read|ssl_free"
   ```

3. If symbols are stripped, use Ghidra headless or the Ghidra MCP tools (`decompile_function`) to locate `SSL_write`, `SSL_read`, `SSL_free`, `SocketBase::WriteList`, `SocketBase::Read` and record their offsets from the library base.

4. Key functions and what they do:

   | Function | Role |
   |----------|------|
   | `SocketBase::WriteList` | Marks threads doing socket writes |
   | `libc write()` | Captures raw HTTP request bytes (filtered by active write threads) |
   | `SocketBase::Read` | Captures HTTP response bytes |
   | `SSL_write` | Captures HTTPS request plaintext |
   | `SSL_read` | Captures HTTPS response plaintext |
   | `SSL_free` | Flushes pending HTTPS request-response pairs |
   | `libc close()` | Flushes pending HTTP request-response pairs |

5. Record arch and all offsets. → `network_lib = "flutter_native"`

#### 5C: Unknown Library (from scratch)

When no known library is detected, discover HTTP functions manually using BOTH jadx and smali:

**Step 5C.1 — String-based grep discovery in jadx output:**
Search all `.java` files in `jadx_output/sources/` for HTTP indicators:
```bash
grep -rlI "Content-Type" sources/ --include="*.java"
grep -rlI "application/json" sources/ --include="*.java"
grep -rlI "User-Agent" sources/ --include="*.java"
grep -rlI '"GET"' sources/ --include="*.java"
grep -rlI '"POST"' sources/ --include="*.java"
grep -rlI "https://" sources/ --include="*.java"
grep -rlI "openConnection" sources/ --include="*.java"
grep -rlI "setRequestMethod" sources/ --include="*.java"
grep -rlI "getResponseCode" sources/ --include="*.java"
grep -rlI "getInputStream" sources/ --include="*.java"
```
Files appearing in 3+ searches are **candidate HTTP classes**.

**Step 5C.2 — Smali-based discovery (complements jadx):**
Smali is especially useful when jadx fails to decompile or produces incomplete output:
```bash
# Find smali classes that reference HTTP-related APIs
grep -rl "Ljava/net/HttpURLConnection;" apktool_output/smali*/
grep -rl "Ljava/net/URL;" apktool_output/smali*/
grep -rl "Ljavax/net/ssl/HttpsURLConnection;" apktool_output/smali*/
grep -rl "openConnection" apktool_output/smali*/
grep -rl "setRequestMethod" apktool_output/smali*/
grep -rl "getOutputStream" apktool_output/smali*/
grep -rl "getInputStream" apktool_output/smali*/
```
Smali reveals the full method signatures which are essential for hooking:
- `.method public doRequest(Lcom/app/a/b;)Lcom/app/a/c;` tells you the exact obfuscated class names for the Request and Response types, the method name, and calling convention.

**Step 5C.3 — Class analysis:**
Read each candidate class source (jadx Java + smali) and look for:
- URL or URI construction
- Header key-value setting
- Request body writing (OutputStream)
- Response stream reading (InputStream)
- Status code parsing
- Callback/listener interfaces (onSuccess, onFailure, onResponse)

**Step 5C.4 — Find the choke point:**
The ideal hook target is a single method where the full request is assembled AND the response is available. Look for:
- Methods taking a "Request" object and returning a "Response" object
- Methods named like `execute()`, `send()`, `dispatch()`, `performRequest()`, `doRequest()`
- Methods that call connection methods and then read the response
- In smali, look for methods that invoke-virtual on URL/connection classes and also return or store a response

**Step 5C.5 — Native library scan (if no Java-layer HTTP found):**
```bash
ARCH=$(ls apk_extracted/lib/ | head -1)
for so in apk_extracted/lib/$ARCH/*.so; do
    echo "=== $(basename $so) ==="
    nm -D "$so" 2>/dev/null | grep -iE "http|curl|ssl|request|response|connect" | head -20
    strings "$so" | grep -iE "content-type|user-agent|http/" | head -10
done
```
If a native library with HTTP symbols is found, use Ghidra to decompile relevant functions and understand calling conventions.

**Step 5C.6 — Record findings:**
- `network_lib = "custom"`
- Class/method names to hook (use the exact names from smali, not jadx)
- Parameter and return types (from smali method signatures)
- How to extract method, URL, headers, body from the request object
- How to extract status, headers, body from the response object

### Step 6 — Generate the Frida Hook Script

#### Why frida-compile is required (Frida 17+)

Frida 17+ **removed the `Java` global** from scripts loaded via `session.createScript()` (the Node.js API that KnoxSpy uses internally). In older Frida, `Java` was auto-available everywhere. Now it only exists in:
- The Frida CLI tools (`frida`, `frida-trace`) — they bundle it themselves
- Scripts compiled with `frida-compile` — the bridge is baked into the output JS

**There is no way to access `Java` in a plain `.js` file loaded by KnoxSpy on Frida 17+.** The solution is always `frida-compile`.

#### Hook file format

The output hook must be written as a **TypeScript entry file** (`<package_name>_hook.entry.ts`) that:
1. `import`s `frida-java-bridge` to make `Java` available
2. Contains all hook logic inline (no separate file needed)

Then compiled with `frida-compile` to produce `<package_name>_hook.js` — the file KnoxSpy actually loads.

**Template structure for all Java-layer hooks:**
```typescript
/**
 * KnoxSpy Auto-Generated Hook
 * Package: <package_name>
 * Framework: <framework_type>
 * Network Library: <network_lib>
 * Generated: <ISO timestamp>
 *
 * SOURCE FILE — edit this, then recompile:
 *   cd knoxspy_analysis/output
 *   npx frida-compile <package_name>_hook.entry.ts -o <package_name>_hook.js
 */

import Java from "frida-java-bridge";
(globalThis as any).Java = Java;

Java.perform(() => {
    // ... generated hook code ...
});
```

**For Flutter/native hooks** (no Java layer), use a plain `.js` file — `Interceptor.attach()` does not need the Java bridge:
```javascript
// KnoxSpy Auto-Generated Hook — Flutter/Native
// Package: <package_name>
// No frida-compile needed for native-only hooks.

Interceptor.attach(...);
```

#### Reference templates by library

| `network_lib` | Reference template | Key hook point |
|---|---|---|
| `okhttp3` | `references/android_okhttp.js` | `OkHttpClient.newCall(okhttp3.Request)` |
| `okhttp3_obfuscated` | `references/android_okhttp_obfuscated.js` | Reflection-based, hook obfuscated class names found in Step 5A |
| `retrofit2_over_okhttp` | Same as okhttp3/okhttp3_obfuscated | Hook the underlying OkHttp layer |
| `flutter_native` | `references/flutter_combined.js` | Replace offsets with values from Step 5B — **plain JS, no frida-compile** |
| `volley` | Generate new | Hook `BasicNetwork.performRequest` |
| `httpurlconnection` | Generate new | Hook `URL.openConnection`, `HttpURLConnection.getInputStream` |
| `apache_http` | Generate new | Hook `HttpClient.execute` |
| `custom` | Generate new | Hook the choke point identified in Step 5C |

**For all Java-layer hooks**, the generated script must:
- Use `Java.perform(() => { ... })` (arrow function, not `function()`) at top level — no IIFE wrapper
- Try/catch around all extraction logic
- Log debug info: `console.log("[KnoxSpy]", ...)`
- Handle async callbacks by storing request data keyed by thread/connection ID
- Always format and `send()` in the payload format from the top of this file

**Flutter offset warning**: The offsets in `references/flutter_combined.js` are build-specific. ALWAYS replace with offsets discovered from the target APK's `libflutter.so`.

### Step 7 — Generate Markdown Report

Write `<package_name>_analysis.md` containing:

1. **Application Info** — package name, app name, version, SDKs, permissions
2. **Framework Detection** — table of all frameworks checked with ✅/❌ and evidence
3. **Network Library Analysis** — which library was found, obfuscation status, class/function names
4. **Hooking Strategy** — table of every function/method being hooked, what it captures, addresses/offsets for native hooks
5. **Generated Files** — paths to both the source `.entry.ts` and the compiled `.js`, with recompile instructions
6. **Caveats** — any warnings (offset specificity, obfuscation fragility, manual steps needed)

The **Generated Files** section must always include this block:

```markdown
## Generated Files

| File | Purpose |
|------|--------|
| `<package_name>_hook.entry.ts` | **Source file** — edit this to modify the hook |
| `<package_name>_hook.js` | **Compiled bundle** — KnoxSpy loads this file |
| `<package_name>_analysis.md` | This report |

### How to recompile after editing the source

```bash
cd knoxspy_analysis/output
npx frida-compile <package_name>_hook.entry.ts -o <package_name>_hook.js
```

Then copy `<package_name>_hook.js` to `knoxspy/app/server/libraries/` and restart the server.

> **Why `frida-compile`?** Frida 17+ removed the `Java` global from scripts loaded
> via the Node.js API. `frida-compile` bundles `frida-java-bridge` directly into the
> output JS so `Java` is available without any server-side changes.
```

### Step 8 — Save Outputs

For **Java-layer hooks** (OkHttp, Volley, etc.), perform these steps:

```bash
OUTPUT_DIR="knoxspy_analysis/output"
PKG="<package_name>"

# 1. Write the TypeScript source (the file you edit)
# → $OUTPUT_DIR/${PKG}_hook.entry.ts

# 2. Compile it into the bundle KnoxSpy loads
cd "$OUTPUT_DIR"
npx frida-compile "${PKG}_hook.entry.ts" -o "${PKG}_hook.js"
cd -

# 3. Write the markdown report
# → $OUTPUT_DIR/${PKG}_analysis.md
```

For **Flutter/native hooks** (no Java bridge needed), skip step 2 — write `${PKG}_hook.js` directly as a plain JS file.

Save to `output_dir` (default `knoxspy_analysis/output/`):
- `<package_name>_hook.entry.ts` — TypeScript source (Java-layer hooks only)
- `<package_name>_hook.js` — Compiled bundle that KnoxSpy loads
- `<package_name>_analysis.md`

Print:
```
✅ Analysis complete for <package_name>
   Framework:       <framework_type>
   Network Library: <network_lib>
   Source File:     knoxspy_analysis/output/<package_name>_hook.entry.ts
   Hook Script:     knoxspy_analysis/output/<package_name>_hook.js
   Report:          knoxspy_analysis/output/<package_name>_analysis.md

   To recompile after editing the hook:
     cd knoxspy_analysis/output
     npx frida-compile <package_name>_hook.entry.ts -o <package_name>_hook.js
```

## References

- `references/android_okhttp.js` — Canonical clean OkHttp3 hook. Shows the payload format and synchronous request/response capture via `newCall().execute()`.
- `references/android_okhttp_obfuscated.js` — OkHttp3 hook for obfuscated apps. Uses Java reflection (`eachField`, `getFirstFieldByType`) to read fields by type instead of name. Hooks codec layer for request/response correlation. Has retry/delayed startup logic.
- `references/flutter_combined.js` — Flutter hook via native interception. Hooks `libflutter.so` + `libc.so` at specific offsets. Uses state dictionaries keyed by fd/SSL pointer to correlate request-response pairs. Parses raw HTTP text.
- `references/flutter_dio_combined.js` — Flutter DIO variant with different offsets.
- `references/config.yaml` — KnoxSpy library registration format.
