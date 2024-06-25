import * as frida from 'frida';
import WebSocket from 'ws';
import WebSocketManager from './websocket';

const mgr = frida.getDeviceManager()

export default class Channels {
    session: frida.Session
    changedSignal!: frida.DevicesChangedHandler;
    name: string
    sessionId: number
    appId: string
    library: string
    deviceId: string
    ws: WebSocketManager

    constructor(session: frida.Session, name: string, sessionId: number, appId: string, library: string, deviceId: string, ws: WebSocketManager, processID: number = -1) {
        this.session = session
        this.name = name
        this.sessionId = sessionId
        this.appId = appId
        this.library = library
        this.deviceId = deviceId
        this.ws = ws
        console.log("Channel has been setup!");
    }

    onchange(): void {
        console.log("Something changed");
    }

    disconnect(): void {
        mgr.changed.disconnect(this.changedSignal)
    }

    connect(): void {
        this.changedSignal = this.onchange.bind(this)
        mgr.changed.connect(this.changedSignal)

        this.ws.broadcastData(JSON.stringify({'action':'deviceUpdate', 'message':'Connected', 'appName': this.name, 'sessionId': this.sessionId, "appId": this.appId, "library": this.library, "deviceId": this.deviceId}));
        // const ws = new WebSocket('ws://localhost:8000')
        // ws.on('open', () => {
        //     console.log("Channel connected to the ws server!");
        //     ws.send(JSON.stringify({'action':'deviceUpdate', 'message':'Connected', 'appName': this.name, 'sessionId': this.sessionId, "appId": this.appId, "library": this.library, "deviceId": this.deviceId}));
        // })


        let dev: frida.Device
        let session: frida.Session

        this.session.detached.connect((reason: frida.SessionDetachReason, crash) => {
            console.log("Disconnected")
            console.log(reason);
            
            this.ws.broadcastData(JSON.stringify({'action':'deviceUpdate', 'message':'Disconnected', 'appName': this.name, 'sessionId': this.sessionId, "appId": this.appId, "library": this.library, "deviceId": this.deviceId}));
        })
    }
}