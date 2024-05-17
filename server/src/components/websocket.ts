import {Server, WebSocketServer, WebSocket, ServerOptions } from 'ws';
import DBManager from './database';
import { findApps, findDevices, startApp } from './utils';
import Channels from './channels';
import { Session } from 'frida';
import REPLManager from './repl';

var wss: Server;
var dbManager = new DBManager('./data.db');
var devices: Session[] = [];
var currentAppSession: number = -1

class WebSocketClient {
    ws: WebSocket
    manager: WebSocketManager
    devices: Session[]

    constructor(ws: WebSocket, manager: WebSocketManager) {
        this.ws = ws;
        this.manager = manager;
        this.devices = [];
        ws.on('close', this.close)
        ws.on('message', this.message)
        this.init(ws)
    }

    init(ws: WebSocket) {
        console.log('Client connected');
        dbManager.getDataFromDatabase((data) => {
            ws.send(JSON.stringify({'action':'trafficInit', 'message': data}))
        })
    }

    send(message: any) {
        this.ws.send(message)
    }

    message = async (message: string) => {
        const jsonData = JSON.parse(message);
        console.log('Received message:', jsonData);
        if(Object.keys(jsonData).indexOf("action") === -1) {
            console.log("Action is missing");
        } else {
            const devices = await findDevices();
            switch (jsonData['action']) {
                case 'devices':
                    this.send(JSON.stringify({"action":"devices", "devices":devices}))
                    break;
                case 'apps':
                    const deviceId = jsonData['deviceId']
                    console.log(devices);
                    console.log(deviceId);
                    if(devices.map((item) => item.id == deviceId).length > 0) {
                        const apps = await findApps(deviceId);
                        this.send(JSON.stringify({"action":"apps", "apps":apps}))
                    } else {
                        this.send(JSON.stringify({"action":"error", "message":"Device is not connected!"}))
                    }
                    break;
                case 'startApp':
                    const deviceId1 = jsonData['deviceId']
                    // console.log(devices);
                    // console.log(deviceId1);
                    
                    if(devices.map((item) => item.id == deviceId1).length > 0) {
                        const appId = jsonData['appId']
                        const appName = jsonData['appName']
                        const sessionId = jsonData['sessionId'];
                        const library = jsonData['library'];
                        console.log("About to start " + appId + " app...with session id:" + sessionId);
                        const session = await startApp(deviceId1, appId);
                        const channel = new Channels(session, appName, sessionId);
                        channel.connect()
                        const repl = new REPLManager(session, sessionId);
                        repl.run_script(library)
                    } else {
                        this.send(JSON.stringify({"action":"error", "message":"Device is not connected!"}))
                    }
                    // this.send(JSON.stringify({"action":"startApp"}))
                    break;
                case 'deviceUpdate':
                    // const deviceSession = jsonData['session']
                    // console.log("About to add device");
                    this.manager.broadcastData(JSON.stringify(jsonData))
                    // console.log("Added new device" + this.devices);
                    break;
                case 'trafficUpdate':
                    this.manager.broadcastData(JSON.stringify(jsonData))
                case 'library':
                    dbManager.getLibraries((row) => {
                        this.ws.send(JSON.stringify({'action':'library', 'message':row}))
                    })
                default:
                    break;
            }
        }

    }

    close() {
        console.log('Client disconnected');
    }
}

class WebSocketManager {
    wss: WebSocketServer

    constructor(server: any) {
        this.wss = new WebSocket.Server({ server: server });
        this.wss.on("connection", (ws: WebSocket) => {
            const client = new WebSocketClient(ws, this)
        })
    }

    broadcastData(data: any) {
        this.wss.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(data);
            }
        });
    }

}

export default WebSocketManager;