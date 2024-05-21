"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const ws_1 = require("ws");
const database_1 = __importDefault(require("./database"));
const utils_1 = require("./utils");
const channels_1 = __importDefault(require("./channels"));
const repl_1 = __importDefault(require("./repl"));
var wss;
var dbManager = new database_1.default('./data.db');
var devices = [];
var currentAppSession = -1;
class WebSocketClient {
    constructor(ws, manager) {
        this.isValidJSON = (str) => {
            try {
                JSON.parse(str);
                return true;
            }
            catch (e) {
                return false;
            }
        };
        this.checkMissingParams = (tmpJson, params) => {
            var tmpErrors = [];
            for (var p in params) {
                if (Object.keys(tmpJson).indexOf(params[p]) === -1) {
                    tmpErrors.push(params[p] + " not provided");
                }
            }
            return tmpErrors;
        };
        this.message = (message) => __awaiter(this, void 0, void 0, function* () {
            if (!this.isValidJSON(message)) {
                this.send(JSON.stringify({ "action": "jsonError", "message": "Payload is not a valid JSON!" }));
            }
            else {
                const jsonData = JSON.parse(message);
                console.log('Received message:', jsonData);
                if (Object.keys(jsonData).indexOf("action") === -1) {
                    console.log("Action is missing");
                    this.send(JSON.stringify({ "action": "jsonError", "message": "Action is missing" }));
                }
                else {
                    const devices = yield (0, utils_1.findDevices)();
                    console.log("Devices: ", devices);
                    switch (jsonData['action']) {
                        case 'devices':
                            this.send(JSON.stringify({ "action": "devices", "devices": devices }));
                            break;
                        case 'processes':
                            const deviceID = jsonData['deviceId'];
                            console.log("DeviceID: ", deviceID);
                            const devicesList = devices.map((item) => { if (item.id == deviceID) {
                                return item.id;
                            } });
                            if (!deviceID) {
                                this.send(JSON.stringify({ "action": "jsonError", "message": "deviceId not provided" }));
                            }
                            else if (devicesList.length > 0 && devicesList.indexOf(deviceID) > -1) {
                                const processes = yield (0, utils_1.findProcesses)(deviceID);
                                this.send(JSON.stringify({ "action": "processes", "processes": processes }));
                            }
                            else {
                                this.send(JSON.stringify({ "action": "error", "message": "No such device found!" }));
                            }
                            break;
                        case 'apps':
                            const deviceId = jsonData['deviceId'];
                            // console.log(devices);
                            //console.log(deviceId);
                            // console.log(devices.map((item) => {if(item.id == deviceId){return item.id;}}))//.length > 0 && devices.map((item) => item.id == deviceId)[0]);
                            const deviceList = devices.map((item) => { if (item.id == deviceId) {
                                return item.id;
                            } });
                            if (!deviceId) {
                                this.send(JSON.stringify({ "action": "jsonError", "message": "deviceId not provided" }));
                            }
                            else if (deviceList.length > 0 && deviceList.indexOf(deviceId) > -1) {
                                const [apps, error] = yield (0, utils_1.findApps)(deviceId);
                                if (error) {
                                    this.send(JSON.stringify({ "action": "error", "message": error }));
                                }
                                else {
                                    this.send(JSON.stringify({ "action": "apps", "apps": apps }));
                                }
                            }
                            else {
                                this.send(JSON.stringify({ "action": "error", "message": "No such device found!" }));
                            }
                            break;
                        case 'startApp':
                            const deviceId1 = jsonData['deviceId'];
                            const tmpErrors = this.checkMissingParams(jsonData, ["processID", "appName", "sessionId", "library", "action", "deviceId"]);
                            if (tmpErrors.length) {
                                this.send(JSON.stringify({ "action": "jsonError", "message": tmpErrors }));
                            }
                            else if (devices.map((item) => item.id == deviceId1).length > 0) {
                                const appName = jsonData['appName'];
                                const sessionId = jsonData['sessionId'];
                                const library = jsonData['library'];
                                const processID = jsonData['processID'];
                                const session = yield (0, utils_1.startApp)(deviceId1, processID);
                                this.sessions.push({ 'id': sessionId, 'session': session });
                                console.log(this.sessions);
                                const channel = new channels_1.default(session, appName, sessionId, processID, library, deviceId1);
                                channel.connect();
                                if (library && library !== null) {
                                    const repl = new repl_1.default(session, sessionId);
                                    repl.run_script(library);
                                }
                                else {
                                    this.send(JSON.stringify({ "action": "jsonError", "message": "No library provided" }));
                                }
                            }
                            else {
                                this.send(JSON.stringify({ "action": "jsonError", "message": "No such device found!" }));
                            }
                            break;
                        case 'detectLibraries':
                            console.log("Detecting libraries");
                            const sessionId = jsonData['sessionId'];
                            console.log(this.sessions);
                            const tmpSession = this.sessions.map((item) => { if (item.id == sessionId) {
                                return item;
                            } });
                            if (tmpSession.length > 0) {
                                if (tmpSession[0]) {
                                    console.log(tmpSession[0]);
                                    const repl = new repl_1.default(tmpSession[0]['session'], sessionId);
                                    repl.detect_libraries();
                                }
                            }
                            break;
                        case 'changeLibrary':
                            console.log("Changing libraries");
                            const tmpSessionId = jsonData['sessionId'];
                            const tmpLibrary = jsonData['library']['file'];
                            console.log(this.sessions);
                            const tmpSession1 = this.sessions.map((item) => { if (item.id == tmpSessionId) {
                                return item;
                            } });
                            if (tmpSession1.length > 0) {
                                if (tmpSession1[0]) {
                                    console.log(tmpSession1[0]);
                                    const repl = new repl_1.default(tmpSession1[0]['session'], tmpSessionId);
                                    repl.run_script(tmpLibrary);
                                    console.log("changedLibrary already");
                                }
                            }
                            break;
                        case 'deviceUpdate':
                            this.manager.broadcastData(JSON.stringify(jsonData));
                            break;
                        case 'successOutput':
                            this.manager.broadcastData(JSON.stringify(jsonData));
                            break;
                        case 'trafficUpdate':
                            this.manager.broadcastData(JSON.stringify(jsonData));
                            break;
                        case 'scriptError':
                            this.manager.broadcastData(JSON.stringify(jsonData));
                            break;
                        case 'scriptOutput':
                            this.manager.broadcastData(JSON.stringify(jsonData));
                            break;
                        case 'library':
                            dbManager.getLibraries((row) => {
                                this.ws.send(JSON.stringify({ 'action': 'library', 'message': row }));
                            });
                        default:
                            this.send(JSON.stringify({ "action": "jsonError", "message": "Invalid action" }));
                            break;
                    }
                }
            }
        });
        this.ws = ws;
        this.manager = manager;
        this.devices = [];
        this.sessions = [];
        ws.on('close', this.close);
        ws.on('message', this.message);
        this.init(ws);
    }
    init(ws) {
        console.log('Client connected');
        dbManager.getDataFromDatabase((data) => {
            ws.send(JSON.stringify({ 'action': 'trafficInit', 'message': data }));
        });
    }
    send(message) {
        this.ws.send(message);
    }
    close() {
        console.log('Client disconnected');
    }
}
class WebSocketManager {
    constructor(server) {
        this.wss = new ws_1.WebSocket.Server({ server: server });
        this.wss.on("connection", (ws) => {
            const client = new WebSocketClient(ws, this);
        });
    }
    broadcastData(data) {
        this.wss.clients.forEach((client) => {
            if (client.readyState === ws_1.WebSocket.OPEN) {
                client.send(data);
            }
        });
    }
}
exports.default = WebSocketManager;
