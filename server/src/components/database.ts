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
        
    getDataFromDatabase(callback: (data: any) => void) {
        this.db.all('SELECT * FROM traffic', (err: any, rows: any) => {
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
    }

    writeToTable(data: JSON, callback: (lastId: number) => void) {
        const columns = Object.keys(data);
        const values = Object.values(data);
        const placeholders = columns.map(() => '?').join(',');
        const sql = `INSERT INTO traffic (${columns.join(', ')}) VALUES (${placeholders})`;

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