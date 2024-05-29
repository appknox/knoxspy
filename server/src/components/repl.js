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
const script_1 = require("frida/dist/script");
const fs_1 = require("fs");
const path_1 = __importDefault(require("path"));
const ws_1 = require("ws");
const database_1 = __importDefault(require("./database"));
var dbManager = new database_1.default('./data.db');
class REPLManager {
    constructor(session, sessionId, sessionObj) {
        this.session = session;
        this.sessionId = sessionId;
        this.currentSession = sessionObj;
        console.log("REPL Constructor called!");
        this.ws = new ws_1.WebSocket('ws://localhost:8000');
        this.ws.on('open', () => {
            console.log("REPL connected to the ws server!");
        });
        this.db = new database_1.default('./data.db');
    }
    detect_libraries() {
        return __awaiter(this, void 0, void 0, function* () {
            console.log("Got request for executing code");
            const parentDir = path_1.default.join(__dirname, '..');
            const filePath = parentDir + '/agents/library_detector.js';
            const fileContent = (0, fs_1.readFileSync)(filePath, 'utf8');
            const script = yield this.session.createScript(fileContent);
            script.message.connect((message, data) => {
                console.log("Script Message: " + message.type);
                if (message.type === script_1.MessageType.Error) {
                    const { columnNumber, description, fileName, lineNumber, stack } = message;
                    console.log(columnNumber, description, fileName, lineNumber, stack);
                    this.ws.send(JSON.stringify({ 'action': 'scriptError', 'message': { "description": description, "fileName": fileName, "stack": stack, "line": lineNumber, "column": columnNumber } }));
                }
                else {
                    const { payload } = message;
                    console.log(payload);
                    var tmpJson = JSON.parse(payload);
                    if (Object.keys(tmpJson).indexOf("error") > -1) {
                        this.ws.send(JSON.stringify({ 'action': 'scriptError', 'message': { "description": tmpJson['error'] } }));
                    }
                    else {
                        this.ws.send(JSON.stringify({ 'action': 'scriptOutput', 'message': tmpJson }));
                    }
                }
                console.log(data);
            });
            script.destroyed.connect(() => {
                console.log("Script destroyed");
            });
            yield script.load();
        });
    }
    attach_script(code, payload, manager) {
        return __awaiter(this, void 0, void 0, function* () {
            const parentDir = path_1.default.join(__dirname, '..');
            const filePath = parentDir + '/libraries/' + code;
            console.log("Attach script payload:", payload);
            const ID = payload.id;
            if ((0, fs_1.existsSync)(filePath)) {
                const fileContent = (0, fs_1.readFileSync)(filePath, 'utf8');
                const script = yield this.session.createScript(fileContent);
                script.message.connect((message, data) => {
                    console.log("Script Message: " + message.type);
                    if (message.type === script_1.MessageType.Error) {
                        const { columnNumber, description, fileName, lineNumber, stack } = message;
                        console.log(columnNumber, description, fileName, lineNumber, stack);
                        this.ws.send(JSON.stringify({ 'action': 'scriptError', 'message': { "description": description, "fileName": fileName, "stack": stack, "line": lineNumber, "column": columnNumber } }));
                    }
                    else {
                        const { payload } = message;
                        var tmpJson = JSON.parse(payload);
                        tmpJson['id'] = ID;
                        console.log("Attach script updated payload: ", tmpJson);
                        dbManager.updateReplayedRepeater(tmpJson, (updated) => {
                            console.log("updated replayed request");
                            console.log(updated);
                            manager.broadcastData(JSON.stringify({ 'action': 'replayUpdate', 'replay': updated }));
                        });
                    }
                });
                script.destroyed.connect(() => {
                    console.log("Script destroyed");
                });
                yield script.load();
                if (payload) {
                    script.post({
                        type: 'sendRequest',
                        payload: { data: payload }
                    });
                }
                this.ws.send(JSON.stringify({ 'action': 'successOutput', 'message': `${code} library attached!` }));
            }
            else {
                setTimeout(() => {
                    console.log("File doesn't exists");
                    this.ws.send(JSON.stringify({ 'action': 'scriptError', 'message': { 'description': `${code} library not found!` } }));
                }, 2000);
            }
        });
    }
    run_script(code) {
        return __awaiter(this, void 0, void 0, function* () {
            console.log("Got request for executing code");
            const parentDir = path_1.default.join(__dirname, '..');
            const filePath = parentDir + '/libraries/' + code;
            if ((0, fs_1.existsSync)(filePath)) {
                const fileContent = (0, fs_1.readFileSync)(filePath, 'utf8');
                const script = yield this.session.createScript(fileContent);
                script.message.connect((message, data) => {
                    console.log("Script Message: " + message.type);
                    if (message.type === script_1.MessageType.Error) {
                        const { columnNumber, description, fileName, lineNumber, stack } = message;
                        console.log(columnNumber, description, fileName, lineNumber, stack);
                        this.ws.send(JSON.stringify({ 'action': 'scriptError', 'message': { "description": description, "fileName": fileName, "stack": stack, "line": lineNumber, "column": columnNumber } }));
                    }
                    else {
                        const { payload } = message;
                        var tmpJson = JSON.parse(payload);
                        if (Object.keys(tmpJson).indexOf("error") > -1) {
                            this.ws.send(JSON.stringify({ 'action': 'scriptError', 'message': { "description": tmpJson['error'] } }));
                        }
                        else {
                            // tmpJson['request_headers'] = JSON.stringify(tmpJson['request_headers']);
                            // tmpJson['response_headers'] = JSON.stringify(tmpJson['response_headers']);
                            // tmpJson['response_body'] = JSON.stringify(tmpJson['response_body']);
                            this.db.writeToTable(JSON.parse(payload), (lastId) => {
                                if (lastId != -1) {
                                    this.db.getRowFromDatabase(lastId, (row) => {
                                        this.ws.send(JSON.stringify({ 'action': 'trafficUpdate', 'message': JSON.parse(row) }));
                                    });
                                }
                            });
                            // this.db.getDataFromDatabase((data) => {
                            //     this.ws.send(JSON.stringify({'action':'trafficUpdate', 'message':JSON.parse(data)}))
                            // })
                        }
                    }
                    console.log(data);
                });
                script.destroyed.connect(() => {
                    console.log("Script destroyed");
                });
                yield script.load();
                this.ws.send(JSON.stringify({ 'action': 'successOutput', 'message': `${code} library attached!` }));
            }
            else {
                setTimeout(() => {
                    console.log("File doesn't exists");
                    this.ws.send(JSON.stringify({ 'action': 'scriptError', 'message': { 'description': `${code} library not found!` } }));
                }, 2000);
            }
        });
    }
}
exports.default = REPLManager;
