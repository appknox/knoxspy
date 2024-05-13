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
                    url: rows[0].url,
                    status: rows[0].status,
                    length: rows[0].length,
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
                    url: row.url,
                    status: row.status,
                    length: row.length,
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