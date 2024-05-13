import {Server, WebSocketServer, WebSocket, ServerOptions } from 'ws';
import DBManager from './database';
import { findApps, findDevices, startApp } from './utils';
import Channels from './channels';
import { Session } from 'frida';
import REPLManager from './repl';

var wss: Server;
var dbManager = new DBManager('./data.db');
var devices: Session[] = [];

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
            switch (jsonData['action']) {
                case 'devices':
                    const devices = await findDevices();
                    this.send(JSON.stringify({"action":"devices", "devices":devices}))
                    break;
                case 'apps':
                    const deviceId = jsonData['deviceId']
                    const apps = await findApps(deviceId);
                    this.send(JSON.stringify({"action":"apps", "apps":apps}))
                    break;
                case 'startApp':
                    const deviceId1 = jsonData['deviceId']
                    const appId = jsonData['appId']
                    const appName = jsonData['appName']
                    console.log("About to start " + appId + " app...");
                    const session = await startApp(deviceId1, appId);
                    const channel = new Channels(session, appName);
                    channel.connect()
                    const repl = new REPLManager(session);
                    const code = "send('pokeBack');";
                    repl.run_script(code)
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
            console.log("New client");

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