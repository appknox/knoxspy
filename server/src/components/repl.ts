import { Session, Script } from "frida";
import { MessageType } from "frida/dist/script";
import { readFileSync, existsSync } from "fs";
import path from "path";
import { WebSocket } from "ws";
import DBManager from "./database";
import WebSocketManager from "./websocket";
var dbManager = new DBManager('./data.db');

class REPLManager {
    session: Session
    ws: WebSocketManager
    db: DBManager
    sessionId: number

    constructor(session: Session, sessionId: number, ws: WebSocketManager) {
        this.session = session
        this.sessionId = sessionId
        this.ws = ws
        this.db = new DBManager('./data.db');
        console.log("REPL Constructor called!", sessionId);
    }

    async detect_platform() {
        console.log("Got request for checking device platform");
        const parentDir = path.join(__dirname, '..')
        const filePath = parentDir + '/agents/platform_detector.js'; 
        const fileContent = readFileSync(filePath, 'utf8');
        const script = await this.session.createScript(fileContent)

        script.message.connect((message, data) => {
            console.log("Script Message: " + message.type);
            if(message.type === MessageType.Error) {
                const { columnNumber, description, fileName, lineNumber, stack } = message
                console.log(columnNumber, description, fileName, lineNumber, stack);
                this.ws.broadcastData(JSON.stringify({'action':'scriptError', 'message':{"description": description, "fileName": fileName, "stack": stack, "line": lineNumber, "column": columnNumber}}))
            } else {
                const { payload } = message
                this.ws.broadcastData(JSON.stringify({'action':'detectPlatform', 'message': payload}))
            }
            console.log(data); 
        });

        script.destroyed.connect(() => {
            console.log("Script destroyed");            
        })

        await script.load()
    }
    
    async detect_libraries() {
        console.log("Got request for executing code");
        const parentDir = path.join(__dirname, '..')
        const filePath = parentDir + '/agents/library_detector.js'; 
        const fileContent = readFileSync(filePath, 'utf8');

        const script = await this.session.createScript(fileContent)

        script.message.connect((message, data) => {
            console.log("Script Message: " + message.type);
            if(message.type === MessageType.Error) {
                const { columnNumber, description, fileName, lineNumber, stack } = message
                console.log(columnNumber, description, fileName, lineNumber, stack);
                this.ws.broadcastData(JSON.stringify({'action':'scriptError', 'message':{"description": description, "fileName": fileName, "stack": stack, "line": lineNumber, "column": columnNumber}}))
            } else {
                const { payload } = message
                console.log(payload);
                var tmpJson = JSON.parse(payload);
                if(Object.keys(tmpJson).indexOf("error") > -1) {
                    this.ws.broadcastData(JSON.stringify({'action':'scriptError', 'message':{"description": tmpJson['error']}}))
                } else {
                    this.ws.broadcastData(JSON.stringify({'action':'scriptOutput', 'message':tmpJson}))
                }
            }
            console.log(data); 
        });

        script.destroyed.connect(() => {
            console.log("Script destroyed");            
        })

        await script.load()
    }

    async attach_script(code: string, payload: any, manager: any) {
        const parentDir = path.join(__dirname, '..')
        const filePath = parentDir + '/agents/' + code;
        console.log("Attach script payload:", payload);
        const ID = payload.id;
        if (existsSync(filePath)) {
            const fileContent = readFileSync(filePath, 'utf8');
            const script = await this.session.createScript(fileContent)
            script.message.connect((message, data) => {
                console.log("Script Message: " + message.type);
                if(message.type === MessageType.Error) {
                    const { columnNumber, description, fileName, lineNumber, stack } = message
                    console.log(columnNumber, description, fileName, lineNumber, stack);
                    this.ws.broadcastData(JSON.stringify({'action':'scriptError', 'message':{"description": description, "fileName": fileName, "stack": stack, "line": lineNumber, "column": columnNumber}}))
                } else {
                    const { payload } = message
                    var tmpJson = JSON.parse(payload);
                    tmpJson['id'] = ID;
                    console.log("Attach script updated payload: ", tmpJson);
                    this.ws.broadcastData(JSON.stringify({'action':'replayUpdate', 'replay':JSON.stringify(tmpJson)}))

                    dbManager.updateReplayedRepeater(tmpJson, (updated: any) => {
                        console.log("updated replayed request");
                         //console.log(updated);                            
                    });
                //     dbManager.updateReplayedRepeater(tmpJson, (updated: any) => {
                //         console.log("updated replayed request");
                //         console.log(updated);
                //         manager.broadcastData(JSON.stringify({'action': 'replayUpdate', 'replay': updated}))
                //    });
                }
                
            })

            script.destroyed.connect(() => {
                console.log("Script destroyed");            
            })

            await script.load()
            if (payload){
                script.post({
                    type: 'data',
                    payload: payload
                });
            }

            this.ws.broadcastData(JSON.stringify({'action':'successOutput', 'message': `${code} library attached!`}))
        } else {
            setTimeout(() => {
                console.log("File doesn't exists");            
                this.ws.broadcastData(JSON.stringify({'action':'scriptError', 'message': {'description': `${code} library not found!`}}))
            }, 2000);
        }

    }

    async run_script(code: string) {
        console.log("Got request for executing code");
        const parentDir = path.join(__dirname, '..')
        const filePath = parentDir + '/libraries/' + code; 
        if (existsSync(filePath)) {
            const fileContent = readFileSync(filePath, 'utf8');
            const script = await this.session.createScript(fileContent)
            script.message.connect((message, data) => {
                console.log("Script Message: " + message.type);
                if(message.type === MessageType.Error) {
                    const { columnNumber, description, fileName, lineNumber, stack } = message
                    console.log(columnNumber, description, fileName, lineNumber, stack);
                    this.ws.broadcastData(JSON.stringify({'action':'scriptError', 'message':{"description": description, "fileName": fileName, "stack": stack, "line": lineNumber, "column": columnNumber}}))
                } else {
                    const { payload } = message
                    var tmpJson = JSON.parse(payload);
                    if(Object.keys(tmpJson).indexOf("error") > -1) {
                        this.ws.broadcastData(JSON.stringify({'action':'scriptError', 'message':{"description": tmpJson['error']}}))
                    } else {
                        // tmpJson['request_headers'] = JSON.stringify(tmpJson['request_headers']);
                        // tmpJson['response_headers'] = JSON.stringify(tmpJson['response_headers']);
                        // tmpJson['response_body'] = JSON.stringify(tmpJson['response_body']);
                        this.db.writeToTable(JSON.parse(payload), (lastId) => {
                            if(lastId != -1) {
                                this.db.getRowFromDatabase(lastId, (row) => {
                                    this.ws.broadcastData(JSON.stringify({'action':'trafficUpdate', 'message':JSON.parse(row)}))
                                })
                            }
                        })
                        // this.db.getDataFromDatabase((data) => {
                        //     this.ws.send(JSON.stringify({'action':'trafficUpdate', 'message':JSON.parse(data)}))
                        // })
                    }
                }
                console.log(data);
                
            })

            script.destroyed.connect(() => {
                console.log("Script destroyed");            
            })


            await script.load()
            this.ws.broadcastData(JSON.stringify({'action':'successOutput', 'message': `${code} library attached!`}))
        } else {
            setTimeout(() => {
                console.log("File doesn't exists");            
                this.ws.broadcastData(JSON.stringify({'action':'scriptError', 'message': {'description': `${code} library not found!`}}))
            }, 2000);
        }
    }

    // async lifecycle(sessionId: string) {
    //     console.log("Got request for monitoring lifecycle of app: " + sessionId);
        

    //     const script = await this.session.createScript(fileContent)

    //     script.message.connect((message, data) => {
    //         console.log("Script Message: " + message.type);
    //         if(message.type === MessageType.Error) {
    //             const { columnNumber, description, fileName, lineNumber, stack } = message
    //             console.log(columnNumber, description, fileName, lineNumber, stack);
    //         } else {
    //             const { payload } = message
    //             console.log(payload);
    //             var tmpJson = JSON.parse(payload);
    //             tmpJson['id'] = "1000";
    //             this.db.writeToTable(JSON.parse(payload), (lastId) => {
    //                 if(lastId != -1) {
    //                     this.db.getRowFromDatabase(lastId, (row) => {
    //                         this.ws.send(JSON.stringify({'action':'trafficUpdate', 'message':JSON.parse(row)}))
    //                     })
    //                 }
    //             })
    //             // this.db.getDataFromDatabase((data) => {
    //             //     this.ws.send(JSON.stringify({'action':'trafficUpdate', 'message':JSON.parse(data)}))
    //             // })
    //         }
    //         console.log(data);
            
    //     })

    //     script.destroyed.connect(() => {
    //         console.log("Script destroyed");            
    //     })


    //     await script.load()
    // }
}

export default REPLManager;