import { Session, Script } from "frida";
import { MessageType } from "frida/dist/script";
import { readFileSync } from "fs";
import path from "path";
import { WebSocket } from "ws";
import DBManager from "./database";

class REPLManager {
    session: Session
    ws: WebSocket
    db: DBManager

    constructor(session: Session) {
        this.session = session
        console.log("REPL Constructor called!");

        this.ws = new WebSocket('ws://localhost:8000')
        this.ws.on('open', () => {
            console.log("REPL connected to the ws server!");
        })

        this.db = new DBManager('./data.db');
    }



    async run_script(code: string) {
        console.log("Got request for executing code");
        const parentDir = path.join(__dirname, '..')
        const filePath = parentDir + '/libraries/' + 'afnetworking.js'; 
        const fileContent = readFileSync(filePath, 'utf8');

        const script = await this.session.createScript(fileContent)

        script.message.connect((message, data) => {
            console.log("Script Message: " + message.type);
            if(message.type === MessageType.Error) {
                const { columnNumber, description, fileName, lineNumber, stack } = message
                console.log(columnNumber, description, fileName, lineNumber, stack);
            } else {
                const { payload } = message
                console.log(payload);
                var tmpJson = JSON.parse(payload);
                tmpJson['id'] = "1000";
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
            console.log(data);
            
        })

        script.destroyed.connect(() => {
            console.log("Script destroyed");            
        })


        await script.load()
    }
}

export default REPLManager;