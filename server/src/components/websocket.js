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
                this.send(JSON.stringify({ "action": "jsonError", "message": ["Payload is not a valid JSON!"] }));
            }
            else {
                const jsonData = JSON.parse(message);
                console.log('Received message:', jsonData);
                if (Object.keys(jsonData).indexOf("action") === -1) {
                    console.log("Action is missing");
                    this.send(JSON.stringify({ "action": "jsonError", "message": ["Action is missing"] }));
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
                                const processes = yield (0, utils_1.findProcesses)(deviceID, "");
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
                        case 'attachApp':
                            const deviceId1 = jsonData['deviceId'];
                            const tmpErrors = this.checkMissingParams(jsonData, ["appId", "appName", "sessionId", "library", "action", "deviceId"]);
                            if (tmpErrors.length) {
                                this.send(JSON.stringify({ "action": "jsonError", "message": tmpErrors }));
                            }
                            else if (devices.map((item) => item.id == deviceId1).length > 0) {
                                const appId = jsonData['appId'];
                                const appName = jsonData['appName'];
                                const sessionId = jsonData['sessionId'];
                                const library = jsonData['library'];
                                const processID = jsonData['processID'];
                                console.log("About to attach " + appId + " app...with session id:" + sessionId);
                                const process = yield (0, utils_1.findProcesses)(deviceId1, appName);
                                if (process.length) {
                                    const processID = process[0];
                                    console.log(processID.pid);
                                    const session = yield (0, utils_1.attachApp)(deviceId1, processID['pid']);
                                    this.sessions.push({ 'id': sessionId, 'session': session });
                                    console.log(this.sessions);
                                    const channel = new channels_1.default(session, appName, sessionId, appId, library, deviceId1, processID.pid);
                                    channel.connect();
                                    if (library && library !== null) {
                                        const repl = new repl_1.default(session, sessionId, this.currentSession);
                                        repl.run_script(library);
                                    }
                                    else {
                                        this.send(JSON.stringify({ "action": "jsonError", "message": ["No library provided"] }));
                                    }
                                }
                                else {
                                    this.send(JSON.stringify({ "action": "error", "message": ["App not running!"] }));
                                }
                            }
                            else {
                                this.send(JSON.stringify({ "action": "jsonError", "message": ["No such device found!"] }));
                            }
                            break;
                        case 'startApp':
                            const deviceId2 = jsonData['deviceId'];
                            const tmpErrors2 = this.checkMissingParams(jsonData, ["appId", "appName", "sessionId", "library", "action", "deviceId"]);
                            if (tmpErrors2.length) {
                                this.send(JSON.stringify({ "action": "jsonError", "message": tmpErrors2 }));
                            }
                            else if (devices.map((item) => item.id == deviceId2).length > 0) {
                                const appId = jsonData['appId'];
                                const appName = jsonData['appName'];
                                const sessionId = jsonData['sessionId'];
                                const library = jsonData['library'];
                                console.log("About to start " + appId + " app...with session id:" + sessionId);
                                const session = yield (0, utils_1.startApp)(deviceId2, appId);
                                this.sessions.push({ 'id': sessionId, 'session': session });
                                console.log(this.sessions);
                                const channel = new channels_1.default(session, appName, sessionId, appId, library, deviceId2);
                                channel.connect();
                                if (library && library !== null) {
                                    const repl = new repl_1.default(session, sessionId, this.currentSession);
                                    repl.run_script(library);
                                }
                                else {
                                    this.send(JSON.stringify({ "action": "jsonError", "message": ["No library provided"] }));
                                }
                            }
                            else {
                                this.send(JSON.stringify({ "action": "jsonError", "message": ["No such device found!"] }));
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
                                    const repl = new repl_1.default(tmpSession[0]['session'], sessionId, this.currentSession);
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
                                    const repl = new repl_1.default(tmpSession1[0]['session'], tmpSessionId, this.currentSession);
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
                            break;
                        case 'createNewSession':
                            const tmpSessionName = jsonData['name'];
                            const tmpPayload = { 'name': tmpSessionName };
                            dbManager.newSession(tmpPayload, (lastId) => {
                                this.manager.broadcastData(JSON.stringify({ 'action': 'sessionCreated', 'session': { 'name': tmpSessionName, 'id': lastId } }));
                            });
                            break;
                        case 'chooseSession':
                            dbManager.setActiveSession(jsonData['session'].id, (id) => {
                                console.log("Active session: " + jsonData['session'].name);
                            });
                            break;
                        case 'sendToRepeater':
                            const tmpRepeaterPayload = jsonData['id'];
                            console.log("Row ID:" + tmpRepeaterPayload);
                            dbManager.sendToRepeater(tmpRepeaterPayload, (lastObj) => {
                                console.log("Entry created: " + lastObj.id);
                                this.manager.broadcastData(JSON.stringify({ 'action': 'repeaterAdd', 'message': lastObj }));
                            });
                            break;
                        case 'sessions':
                            dbManager.getSessions(-1, (sessions) => {
                                this.manager.broadcastData(JSON.stringify({ 'action': 'sessionList', 'sessions': JSON.parse(sessions) }));
                            });
                            dbManager.getActiveSession((row) => {
                                this.manager.broadcastData(JSON.stringify({ 'action': 'activeSession', 'session': JSON.parse(row) }));
                            });
                            break;
                        case 'repeaterUpdate':
                            dbManager.getRepeaterTraffic((sessions) => {
                                this.manager.broadcastData(JSON.stringify({ 'action': 'repeaterUpdate', 'message': JSON.parse(sessions) }));
                            });
                            break;
                        case 'replayRequest':
                            var replayPayload = jsonData['replay'];
                            var appData = jsonData['appData'];
                            var library = "okhttp_repeater.js";
                            console.log('Replay request: ', replayPayload);
                            const process = yield (0, utils_1.findProcesses)(appData.deviceId, appData.appName);
                            const processID = process[0];
                            const session = yield (0, utils_1.attachApp)(appData.deviceId, processID['pid']);
                            this.sessions.push({ 'id': appData.sessionId, 'session': session });
                            const channel = new channels_1.default(session, appData.appName, appData.sessionId, appData.appId, library, appData.deviceId, processID.pid);
                            channel.connect();
                            if (library && library !== null) {
                                const repl = new repl_1.default(session, appData.sessionId, this.currentSession);
                                repl.attach_script(library, replayPayload, this.manager);
                            }
                            else {
                                this.send(JSON.stringify({ "action": "jsonError", "message": ["No library provided"] }));
                            }
                            // dbManager.updateReplayedRepeater(replayPayload, (updated: any) => {
                            //      console.log("updated replayed request");
                            //      console.log(updated);                            
                            // });
                            //this.manager.broadcastData(JSON.stringify({'action': 'replayUpdate', 'replay': replayPayload}))
                            break;
                        default:
                            this.send(JSON.stringify({ "action": "jsonError", "message": ["Invalid action"] }));
                            break;
                    }
                }
            }
        });
        this.ws = ws;
        this.manager = manager;
        this.devices = [];
        this.sessions = [];
        this.currentSession = { 'name': '', 'id': -1 };
        ws.on('close', this.close);
        ws.on('message', this.message);
        this.init(ws);
    }
    init(ws) {
        console.log('Client connected');
        dbManager.getDataFromDatabase((data) => {
            console.log("fetching history");
            dbManager.getActiveSession((row) => {
                console.log(JSON.parse(row));
                ws.send(JSON.stringify({ 'action': 'trafficInit', 'message': data, 'session': JSON.parse(row) }));
            });
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
