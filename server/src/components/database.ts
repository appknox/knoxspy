import { sqlite3, Database } from "sqlite3";

const sqlite = require("sqlite3")

class DBManager {
    db: Database

    constructor(file_name: string) {
        this.db = new Database(file_name, ((err) => {
            if(err) {
                console.log("Error while connecting to DB" + err?.message)
            } else {
                console.log("Connected to DB successfully!")
            }
        }))
    }

    getLibraries(callback: (data: any) => void) {
        this.db.all('SELECT * FROM library', (err: any, rows: any) => {
            if (err) {
                console.error('Error querying database:', err.message);
                callback([]);
            } else {
                const jsonData = rows.map((row: any) => ({
                    id: row.id,
                    name: row.name,
                    file: row.file,
                    platform: row.platform
                }));
                // console.log(jsonData);

                callback(JSON.stringify(jsonData));
            }
        });
    }
      
    getRowFromDatabase(rowId: number, callback: (data: any) => void) {
        this.db.all(`SELECT * FROM traffic where id=${rowId}`, (err: any, rows: any) => {
            if (err) {
                console.error('Error querying database:', err.message);
                callback([]);
            } else {
                console.log(rows);
                
                const tmpJsonData = {
                    id: rows[0].id,
                    method: rows[0].method,
                    host: rows[0].host,
                    endpoint: rows[0].endpoint,
                    status_code: rows[0].status_code,
                    request_headers: rows[0].request_headers,
                    response_headers: rows[0].response_headers,
                    response_body: rows[0].response_body,
                    request_body: rows[0].request_body,
                };
                // console.log(jsonData);

                callback(JSON.stringify(tmpJsonData));
            }
        });
    }

    getSessions(rowId: number = -1, callback: (data: any) => void) {
        if(rowId !== -1) {
            this.db.get(`SELECT * FROM sessions where id=${rowId}`, (err: any, rows: any) => {
                if (err) {
                    console.error('Error querying database:', err.message);
                    callback([]);
                } else {
                    console.log(rows);
                    
                    const tmpJsonData = {
                        id: rows[0].id,
                        method: rows[0].method,
                        host: rows[0].host,
                        endpoint: rows[0].endpoint,
                        status_code: rows[0].status_code,
                        request_headers: rows[0].request_headers,
                        response_headers: rows[0].response_headers,
                        response_body: rows[0].response_body,
                        request_body: rows[0].request_body,
                    };
                    // console.log(jsonData);

                    callback(JSON.stringify(tmpJsonData));
                }
            });
        } else {
            this.db.all(`SELECT * FROM sessions`, (err: any, rows: any) => {
                if (err) {
                    console.error('Error querying database:', err.message);
                    callback([]);
                } else {
                    console.log(rows);
                    
                    const tmpJsonData = rows.map((row: any) => ({
                        id: row.id,
                        name: row.name,
                        file: row.file,
                        platform: row.platform
                    }));
                    // console.log(jsonData);

                    callback(JSON.stringify(tmpJsonData));
                }
            });
        }
    }
        
    getDataFromDatabase(callback: (data: any) => void) {
        this.getActiveSession((rows: string) => {
            const tmpSession = JSON.parse(rows)
            console.log(tmpSession);
            this.db.all('SELECT * FROM traffic where session_id=?', tmpSession.id, (err: any, rows: any) => {
                if (err) {
                    console.error('Error querying database:', err.message);
                    callback([]);
                } else {
                    const jsonData = rows.map((row: any) => ({
                        id: row.id,
                        method: row.method,
                        host: row.host,
                        endpoint: row.endpoint,
                        status_code: row.status_code,
                        request_headers: row.request_headers,
                        response_headers: row.response_headers,
                        response_body: row.response_body,
                        request_body: row.request_body,
                    }));
                    // console.log(jsonData);

                    callback(JSON.stringify(jsonData));
                }
            });
        });
    }

    writeToTable(data: JSON, callback: (lastId: number) => void) {

        this.getActiveSession((rows: string) => {
            const tmpSession = JSON.parse(rows)
            console.log(tmpSession);

            const columns = Object.keys(data);
            var values = Object.values(data);
            values.push(tmpSession.id)
            const placeholders = columns.map(() => '?').join(',');
            const sql = `INSERT INTO traffic (${columns.join(', ')}, session_id) VALUES (${placeholders},?)`;
            console.log(sql);
            

            // Execute prepared statement
            this.db.run(sql, values, function(err: any) {
                if (err) {
                    console.error(`Error inserting data into traffic: ${err.message}`);
                    callback(-1)
                } else {
                    console.log(`Rows inserted into traffic` + this.lastID);
                    callback(this.lastID)
                    // this.getDataFromDatabase((data) => {
                    //     // broadcastData(data)
                    // })
                }
            });
        });
    }

    newSession(data: Object, callback: (lastId: number) => void) {
        const columns = Object.keys(data);
        const values = Object.values(data);
        const placeholders = columns.map(() => '?').join(',');
        const sql = `INSERT INTO sessions (${columns.join(', ')}) VALUES (${placeholders})`;

        // Execute prepared statement
        this.db.run(sql, values, function(err: any) {
            if (err) {
                console.error(`Error inserting data into sessions: ${err.message}`);
                callback(-1)
            } else {
                console.log(`Rows inserted into sessions` + this.lastID);
                callback(this.lastID)
                // this.getDataFromDatabase((data) => {
                //     // broadcastData(data)
                // })
            }
        });
    }

    setActiveSession(session_id: string, callback: (lastId: number) => void) {
        console.log("Setting session id:" + session_id);
        
        const sql = `INSERT INTO current_session (session_id) VALUES (?)`;
        console.log(sql);
        

        // Execute prepared statement
        this.db.run(sql, session_id, function(err: any) {
            if (err) {
                console.error(`Error inserting data into current_session: ${err.message}`);
                callback(-1)
            } else {
                console.log(`Rows inserted into current_session` + this.lastID);
                callback(this.lastID)
                // this.getDataFromDatabase((data) => {
                //     // broadcastData(data)
                // })
            }
        });
    }

    getActiveSession(callback: (rows: string) => void) {
        
        const sql = `select current_session.session_id as id,sessions.name from current_session inner join sessions on current_session.session_id=sessions.id order by current_session.id desc limit 1;`;
        console.log(sql);
        

        // Execute prepared statement
        this.db.all(sql, function(err: any, row: any) {
            if (err) {
                console.error(`Error getting data from current_session: ${err.message}`);
                callback(JSON.stringify({'name': null, 'id': -1}))
            } else {
                // console.log(`Rows fetched from current_session`);
                if(row.length) {
                    // console.log(row[0].id);
                    // console.log(row[0]);
                    callback(JSON.stringify(row[0]))
                } else {
                    callback(JSON.stringify({'name': null, 'id': -1}))
                }
                // this.getDataFromDatabase((data) => {
                //     // broadcastData(data)
                // })
            }
        });
    }

    getRequest(rowId: number = -1, callback: (data: any) => void) {
        this.db.get(`SELECT * FROM traffic where id=${rowId}`, (err: any, rows: any) => {
            if (err) {
                console.error('Error querying database:', err.message);
                callback([]);
            } else {
                // console.log(rows);
                
                const tmpJsonData = {
                    id: rows.id,
                    method: rows.method,
                    host: rows.host,
                    endpoint: rows.endpoint,
                    status_code: rows.status_code,
                    request_headers: rows.request_headers,
                    response_headers: rows.response_headers,
                    response_body: rows.response_body,
                    request_body: rows.request_body,
                    session_id: rows.session_id
                };
                // console.log(jsonData);

                callback(JSON.stringify(tmpJsonData));
            }
        });
    }

    getRepeaterTraffic(callback: (lastObj: any) => void) {
        this.getActiveSession((rows: string) => {
            const tmpSession = JSON.parse(rows)
            const rowId = tmpSession.id
            this.db.all(`SELECT * FROM repeater_traffic where session_id=${rowId}`, (err: any, rows: any) => {
                if (err) {
                    console.error('Error querying database:', err.message);
                    callback([]);
                } else {
                    // console.log(rows.length);
                    const jsonData = rows.map((row: any) => ({
                        id: row.id,
                        method: row.method,
                        host: row.host,
                        endpoint: row.endpoint,
                        status_code: row.status_code,
                        request_headers: row.request_headers,
                        response_headers: row.response_headers,
                        response_body: row.response_body,
                        request_body: row.request_body,
                        session_id: row.session_id
                    }));
                    // console.log(jsonData);
    
                    callback(JSON.stringify(jsonData));
                }
            });
        })

        
    }

    sendToRepeater(rowId: any, callback: (lastObj: any) => void) {
        this.getActiveSession((rows: string) => {
            const tmpSession = JSON.parse(rows)
            this.getRequest(rowId, (data: any) => {
                var tmpData = JSON.parse(data)
                delete tmpData.id
                console.log(tmpData);
                const columns = Object.keys(tmpData);
                const values = Object.values(tmpData);
                const placeholders = columns.map(() => '?').join(',');
                const sql = `INSERT INTO repeater_traffic (${columns.join(', ')}) VALUES (${placeholders})`;
                console.log(sql);
                
                this.db.run(sql, values, function(err: any) {
                    if (err) {
                        console.error(`Error inserting data into repeater_traffic: ${err.message}`);
                        callback({})
                    } else {
                        console.log(`Rows inserted into repeater_traffic` + this.lastID);
                        tmpData['id'] = this.lastID
                        callback(tmpData)
                    }
                });
            });
        })

        
    }

    close() {
        this.db.close();
    }
}

export default DBManager;



// process.on('SIGINT', () => {
//     db.close((err: any) => {
//         if (err) {
//             console.error('Error closing database:', err.message);
//         }
//         console.log('Server shutting down...');
//         process.exit(0);
//     });
// });