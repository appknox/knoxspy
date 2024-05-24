import { Session, Script } from "frida";
import { MessageType } from "frida/dist/script";
import { readFileSync, existsSync } from "fs";
import path from "path";
import { WebSocket } from "ws";
import DBManager from "./database";

class REPLManager {
    session: Session
    ws: WebSocket
    db: DBManager
    sessionId: number
    currentSession: Object

    constructor(session: Session, sessionId: number, sessionObj: Object) {
        this.session = session
        this.sessionId = sessionId
        this.currentSession = sessionObj
        console.log("REPL Constructor called!");

        this.ws = new WebSocket('ws://localhost:8000')
        this.ws.on('open', () => {
            console.log("REPL connected to the ws server!");
        })

        this.db = new DBManager('./data.db');
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
                this.ws.send(JSON.stringify({'action':'scriptError', 'message':{"description": description, "fileName": fileName, "stack": stack, "line": lineNumber, "column": columnNumber}}))
            } else {
                const { payload } = message
                console.log(payload);
                var tmpJson = JSON.parse(payload);
                if(Object.keys(tmpJson).indexOf("error") > -1) {
                    this.ws.send(JSON.stringify({'action':'scriptError', 'message':{"description": tmpJson['error']}}))
                } else {
                    this.ws.send(JSON.stringify({'action':'scriptOutput', 'message':tmpJson}))
                }
            }
            console.log(data); 
        });

        script.destroyed.connect(() => {
            console.log("Script destroyed");            
        })

        await script.load()
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
                    this.ws.send(JSON.stringify({'action':'scriptError', 'message':{"description": description, "fileName": fileName, "stack": stack, "line": lineNumber, "column": columnNumber}}))
                } else {
                    const { payload } = message
                    console.log(payload);
                    var tmpJson = JSON.parse(payload);
                    if(Object.keys(tmpJson).indexOf("error") > -1) {
                        this.ws.send(JSON.stringify({'action':'scriptError', 'message':{"description": tmpJson['error']}}))
                    } else {
                        // tmpJson['request_headers'] = JSON.stringify(tmpJson['request_headers']);
                        // tmpJson['response_headers'] = JSON.stringify(tmpJson['response_headers']);
                        // tmpJson['response_body'] = JSON.stringify(tmpJson['response_body']);
                        this.db.writeToTable(JSON.parse(payload), (lastId) => {
                            if(lastId != -1) {
                                this.db.getRowFromDatabase(lastId, (row) => {
                                    this.ws.send(JSON.stringify({'action':'trafficUpdate', 'message':JSON.parse(row)}))
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
            this.ws.send(JSON.stringify({'action':'successOutput', 'message': `${code} library attached!`}))
        } else {
            setTimeout(() => {
                console.log("File doesn't exists");            
                this.ws.send(JSON.stringify({'action':'scriptError', 'message': {'description': `${code} library not found!`}}))
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