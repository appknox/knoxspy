import JavaBridge from "frida-java-bridge";

if (typeof globalThis !== "undefined" && !(globalThis as any).Java) {
  (globalThis as any).Java = JavaBridge;
}

import "./android_okhttp_obfuscated.payload.js";
