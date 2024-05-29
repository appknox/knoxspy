"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const frida = __importStar(require("frida"));
const ws_1 = __importDefault(require("ws"));
const mgr = frida.getDeviceManager();
class Channels {
    constructor(session, name, sessionId, appId, library, deviceId, processID = -1) {
        this.session = session;
        this.name = name;
        this.sessionId = sessionId;
        this.appId = appId;
        this.library = library;
        this.deviceId = deviceId;
        console.log("Channel has been setup!");
    }
    onchange() {
        console.log("Something changed");
    }
    disconnect() {
        mgr.changed.disconnect(this.changedSignal);
    }
    connect() {
        this.changedSignal = this.onchange.bind(this);
        mgr.changed.connect(this.changedSignal);
        const ws = new ws_1.default('ws://localhost:8000');
        ws.on('open', () => {
            console.log("Channel connected to the ws server!");
            ws.send(JSON.stringify({ 'action': 'deviceUpdate', 'message': 'Connected', 'appName': this.name, 'sessionId': this.sessionId, "appId": this.appId, "library": this.library, "deviceId": this.deviceId }));
        });
        let dev;
        let session;
        this.session.detached.connect((reason, crash) => {
            console.log("Disconnected");
            console.log(reason);
            ws.send(JSON.stringify({ 'action': 'deviceUpdate', 'message': 'Disconnected', 'appName': this.name, 'sessionId': this.sessionId, "appId": this.appId, "library": this.library, "deviceId": this.deviceId }));
        });
    }
}
exports.default = Channels;
