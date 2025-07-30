import { Database as SQLiteDatabase } from "sqlite3";
import path from "path";
import { existsSync, mkdirSync } from "fs";

/**
 * Database response type for standardized responses
 */
interface DatabaseResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

/**
 * Traffic data structure
 */
interface TrafficData {
  id?: number;
  method: string;
  host: string;
  endpoint: string;
  protocol?: string;
  status_code: number;
  request_headers: string;
  response_headers: string;
  response_body: string;
  request_body: string;
  session_id: number;
}

/**
 * Session data structure
 */
interface SessionData {
  id?: number;
  name: string;
  config: string;
}

/**
 * Repeater traffic data structure
 */
interface RepeaterTrafficData extends TrafficData {
  title?: string;
}

/**
 * Library data structure
 */
interface LibraryData {
  id?: number;
  name: string;
  file: string;
  platform: string;
}

/**
 * Active session data structure
 */
interface ActiveSessionData {
  id: number;
  name: string | null;
  config: any;
}

/**
 * Database manager for handling all database operations
 */
export default class DBManager {
  private db: SQLiteDatabase;
  private initialized: boolean = false;

  /**
   * Create a new database manager
   * @param dbPath Path to the SQLite database file
   */
  constructor(dbPath: string) {
    // Ensure the directory exists
    const dir = path.dirname(dbPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    this.db = new SQLiteDatabase(dbPath, (err) => {
      if (err) {
        console.error("Error connecting to database:", err.message);
      } else {
        console.log("Connected to database successfully");
        this.initializeDatabase();
      }
    });
  }

  /**
   * Initialize database tables
   */
  private initializeDatabase(): void {
    const tables = [
      `CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        config TEXT
      )`,
      `CREATE TABLE IF NOT EXISTS current_session (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER,
        FOREIGN KEY (session_id) REFERENCES sessions(id)
      )`,
      `CREATE TABLE IF NOT EXISTS traffic (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        method TEXT,
        host TEXT,
        endpoint TEXT,
        protocol TEXT,
        status_code INTEGER,
        request_headers TEXT,
        response_headers TEXT,
        response_body TEXT,
        request_body TEXT,
        session_id INTEGER,
        FOREIGN KEY (session_id) REFERENCES sessions(id)
      )`,
      `CREATE TABLE IF NOT EXISTS repeater_traffic (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        method TEXT,
        host TEXT,
        endpoint TEXT,
        protocol TEXT,
        status_code INTEGER,
        request_headers TEXT,
        response_headers TEXT,
        response_body TEXT,
        request_body TEXT,
        session_id INTEGER,
        title TEXT,
        FOREIGN KEY (session_id) REFERENCES sessions(id)
      )`,
      `CREATE TABLE IF NOT EXISTS library (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        file TEXT,
        platform TEXT
      )`,
    ];

    tables.forEach((sql) => {
      this.db.run(sql, (err) => {
        if (err) {
          console.error("Error creating table:", err.message);
        }
      });
    });

    this.initialized = true;
  }

  /**
   * Execute a query as a promise
   * @param sql SQL statement
   * @param params Parameters for the SQL statement
   * @returns Promise resolving with the result
   */
  private async execute<T>(
    sql: string,
    params: any[] = []
  ): Promise<DatabaseResponse<T>> {
    return new Promise((resolve) => {
      this.db.run(sql, params, function (err) {
        if (err) {
          console.error(`Error executing SQL: ${sql}`, err.message);
          resolve({
            success: false,
            error: err.message,
          });
        } else {
          resolve({
            success: true,
            data: { id: this.lastID, changes: this.changes } as unknown as T,
          });
        }
      });
    });
  }

  /**
   * Execute a query and get all results as a promise
   * @param sql SQL statement
   * @param params Parameters for the SQL statement
   * @returns Promise resolving with all results
   */
  private async queryAll<T>(
    sql: string,
    params: any[] = []
  ): Promise<DatabaseResponse<T[]>> {
    return new Promise((resolve) => {
      this.db.all(sql, params, (err, rows) => {
        if (err) {
          console.error(`Error executing SQL: ${sql}`, err.message);
          resolve({
            success: false,
            error: err.message,
          });
        } else {
          resolve({
            success: true,
            data: rows as T[],
          });
        }
      });
    });
  }

  /**
   * Execute a query and get a single result as a promise
   * @param sql SQL statement
   * @param params Parameters for the SQL statement
   * @returns Promise resolving with a single result
   */
  private async queryGet<T>(
    sql: string,
    params: any[] = []
  ): Promise<DatabaseResponse<T>> {
    return new Promise((resolve) => {
      this.db.get(sql, params, (err, row) => {
        if (err) {
          console.error(`Error executing SQL: ${sql}`, err.message);
          resolve({
            success: false,
            error: err.message,
          });
        } else {
          resolve({
            success: true,
            data: row as T,
          });
        }
      });
    });
  }

  /**
   * Get all libraries
   * @returns Promise resolving with all libraries
   */
  async getLibraries(): Promise<LibraryData[]> {
    const response = await this.queryAll<LibraryData>("SELECT * FROM library");
    return response.success ? response.data || [] : [];
  }

  /**
   * Get a traffic record by ID
   * @param rowId Traffic record ID
   * @returns Promise resolving with the traffic record
   */
  async getTrafficById(rowId: number): Promise<TrafficData | null> {
    const response = await this.queryGet<TrafficData>(
      `SELECT * FROM traffic WHERE id = ?`,
      [rowId]
    );
    return response.success ? response.data || null : null;
  }

  /**
   * Get all sessions or a specific session
   * @param rowId Optional session ID
   * @returns Promise resolving with sessions
   */
  async getSessions(rowId?: number): Promise<SessionData[]> {
    let sql = "SELECT * FROM sessions";
    let params: any[] = [];

    if (rowId !== undefined) {
      sql += " WHERE id = ?";
      params = [rowId];
    }

    const response = await this.queryAll<SessionData>(sql, params);
    return response.success ? response.data || [] : [];
  }

  /**
   * Get all traffic data for the current session
   * @returns Promise resolving with traffic data
   */
  async getSessionTraffic(): Promise<TrafficData[]> {
    const activeSession = await this.getActiveSessionPromise();

    if (!activeSession || activeSession.id === -1) {
      return [];
    }

    const response = await this.queryAll<TrafficData>(
      `SELECT * FROM traffic WHERE session_id = ?`,
      [activeSession.id]
    );

    return response.success ? response.data || [] : [];
  }

  /**
   * Get all traffic data for a specific session
   * @param rowId Session ID
   * @returns Promise resolving with traffic data
   */
  async getTrafficBySession(rowId: number): Promise<TrafficData[]> {
    const response = await this.queryAll<TrafficData>(
      `SELECT * FROM traffic WHERE session_id = ?`,
      [rowId]
    );
    return response.success ? response.data || [] : [];
  }

  /**
   * Save traffic data to the database
   * @param data Traffic data to save
   * @returns Promise resolving with the inserted ID
   */
  async saveTraffic(data: any): Promise<number> {
    const activeSession = await this.getActiveSessionPromise();

    if (!activeSession || activeSession.id === -1) {
      return -1;
    }

    // Add session ID to the data
    const trafficData = { ...data, session_id: activeSession.id };
    console.log("Traffic data to save:", trafficData);

    // Ensure headers are stored as strings
    if (Array.isArray(trafficData.request_headers)) {
      trafficData.request_headers = JSON.stringify(trafficData.request_headers);
    }

    if (Array.isArray(trafficData.response_headers)) {
      trafficData.response_headers = JSON.stringify(trafficData.response_headers);
    }

    const columns = Object.keys(trafficData);
    const values = Object.values(trafficData);
    const placeholders = columns.map(() => "?").join(",");

    const sql = `INSERT INTO traffic (${columns.join(
      ", "
    )}) VALUES (${placeholders})`;

    const response = await this.execute<{ id: number }>(sql, values);
    return response.success ? response.data?.id || -1 : -1;
  }

  /**
   * Create a new session
   * @param data Session data
   * @returns Promise resolving with the inserted ID
   */
  async createSession(data: Partial<SessionData>): Promise<number> {
    const sessionConfig = {
      session: "No",
      device: "No",
      app: "No",
      library: "No",
    };

    // Add default config if not provided
    const sessionData = {
      ...data,
      config: data.config || JSON.stringify(sessionConfig),
    };

    const columns = Object.keys(sessionData);
    const values = Object.values(sessionData);
    const placeholders = columns.map(() => "?").join(",");

    const sql = `INSERT INTO sessions (${columns.join(
      ", "
    )}) VALUES (${placeholders})`;

    const response = await this.execute<{ id: number }>(sql, values);
    return response.success ? response.data?.id || -1 : -1;
  }

  /**
   * Set the active session
   * @param sessionId Session ID
   * @returns Promise resolving with operation success
   */
  async setActiveSession(sessionId: number): Promise<boolean> {
    // First clear current active sessions
    await this.clearActiveSession();

    const sql = `INSERT INTO current_session (session_id) VALUES (?)`;
    const response = await this.execute(sql, [sessionId]);

    return response.success;
  }

  /**
   * Clear the active session
   * @returns Promise resolving with operation success
   */
  async clearActiveSession(): Promise<boolean> {
    const sql = `DELETE FROM current_session WHERE id > 0`;
    const response = await this.execute(sql);

    return response.success;
  }

  /**
   * Delete a session
   * @param sessionId Session ID
   * @returns Promise resolving with operation success
   */
  async deleteSession(sessionId: number): Promise<boolean> {
    const sql = `DELETE FROM sessions WHERE id = ?`;
    const response = await this.execute(sql, [sessionId]);

    return response.success;
  }

  /**
   * Internal Promise-based getActiveSession implementation
   * @returns Promise resolving with active session data
   */
  private async getActiveSessionPromise(): Promise<ActiveSessionData> {
    const sql = `
      SELECT 
        current_session.session_id as id,
        sessions.name, 
        sessions.config as config 
      FROM current_session 
      INNER JOIN sessions ON current_session.session_id = sessions.id 
      ORDER BY current_session.id DESC 
      LIMIT 1
    `;

    const response = await this.queryGet<ActiveSessionData>(sql);

    if (response.success && response.data) {
      // Parse config if it's a string
      try {
        if (typeof response.data.config === "string") {
          response.data.config = JSON.parse(response.data.config);
        }
      } catch (e) {
        console.error("Error parsing session config:", e);
        response.data.config = {};
      }
      return response.data;
    }

    return { id: -1, name: null, config: {} };
  }

  /**
   * Get the active session - Promise version
   * @returns Promise resolving with active session data
   */
  async getActiveSession(): Promise<ActiveSessionData>;
  /**
   * Get the active session - Callback version
   * @param callback Callback with session data
   */
  getActiveSession(callback: (data: string) => void): void;
  /**
   * Implementation that handles both overloads
   */
  getActiveSession(callback?: (data: string) => void): Promise<ActiveSessionData> | void {
    if (callback) {
      // Callback version
      const sql = `
        SELECT 
          current_session.session_id as id,
          sessions.name, 
          sessions.config as config 
        FROM current_session 
        INNER JOIN sessions ON current_session.session_id = sessions.id 
        ORDER BY current_session.id DESC 
        LIMIT 1
      `;

      this.db.get(sql, (err, row) => {
        if (err) {
          console.error("Error getting active session:", err.message);
          callback(JSON.stringify({ id: -1, name: null, config: {} }));
        } else if (!row) {
          callback(JSON.stringify({ id: -1, name: null, config: {} }));
        } else {
          callback(JSON.stringify(row));
        }
      });
      return;
    } else {
      // Promise version
      return this.getActiveSessionPromise();
    }
  }

  /**
   * Update the configuration of the active session
   * @param config New configuration
   * @returns Promise resolving with operation success
   */
  async updateActiveSessionConfig(config: string | object): Promise<boolean> {
    const activeSession = await this.getActiveSessionPromise();

    if (!activeSession || activeSession.id === -1) {
      return false;
    }

    const configStr =
      typeof config === "string" ? config : JSON.stringify(config);
    const sql = `UPDATE sessions SET config = ? WHERE id = ?`;

    const response = await this.execute(sql, [configStr, activeSession.id]);
    return response.success;
  }

  /**
   * Get a request from traffic by ID
   * @param rowId Traffic record ID
   * @returns Promise resolving with the traffic data
   */
  async getRequest(rowId: number): Promise<TrafficData | null> {
    return this.getTrafficById(rowId);
  }

  /**
   * Get a repeater request by ID
   * @param rowId Repeater record ID
   * @returns Promise resolving with the repeater data
   */
  async getRepeaterRequest(rowId: number): Promise<RepeaterTrafficData | null> {
    const response = await this.queryGet<RepeaterTrafficData>(
      `SELECT * FROM repeater_traffic WHERE id = ?`,
      [rowId]
    );
    return response.success ? response.data || null : null;
  }

  /**
   * Get all repeater traffic for the current session
   * @returns Promise resolving with repeater traffic data
   */
  async getRepeaterTraffic(): Promise<RepeaterTrafficData[]> {
    const activeSession = await this.getActiveSessionPromise();

    if (!activeSession || activeSession.id === -1) {
      return [];
    }

    const response = await this.queryAll<RepeaterTrafficData>(
      `SELECT * FROM repeater_traffic WHERE session_id = ?`,
      [activeSession.id]
    );

    return response.success ? response.data || [] : [];
  }

  /**
   * Get all repeater traffic for a specific session
   * @param sessionId Session ID
   * @returns Promise resolving with repeater traffic data
   */
  async getRepeaterTrafficBySession(sessionId: number): Promise<RepeaterTrafficData[]> {
    const response = await this.queryAll<RepeaterTrafficData>(
      `SELECT * FROM repeater_traffic WHERE session_id = ?`,
      [sessionId]
    );
    return response.success ? response.data || [] : [];
  }

  /**
   * Send traffic to repeater
   * @param rowId Traffic record ID to send to repeater
   * @returns Promise resolving with the created repeater record
   */
  async sendToRepeater(rowId: number): Promise<RepeaterTrafficData | null> {
    const trafficData = await this.getTrafficById(rowId);
    console.log("Traffic data:", trafficData, rowId);
    if (!trafficData) {
      return null;
    }

    // Copy to repeater_traffic
    delete (trafficData as any).id;

    const columns = Object.keys(trafficData);
    const values = Object.values(trafficData);
    const placeholders = columns.map(() => "?").join(",");

    const sql = `INSERT INTO repeater_traffic (${columns.join(
      ", "
    )}) VALUES (${placeholders})`;

    const response = await this.execute<{ id: number }>(sql, values);

    if (!response.success) {
      return null;
    }

    return this.getRepeaterRequest(response.data?.id || 0);
  }

  /**
   * Duplicate a repeater request
   * @param rowId Repeater record ID
   * @returns Promise resolving with the duplicated record
   */
  async duplicateRepeater(rowId: number): Promise<RepeaterTrafficData | null> {
    const repeaterData = await this.getRepeaterRequest(rowId);

    if (!repeaterData) {
      return null;
    }

    // Duplicate the record
    delete (repeaterData as any).id;

    const columns = Object.keys(repeaterData);
    const values = Object.values(repeaterData);
    const placeholders = columns.map(() => "?").join(",");

    const sql = `INSERT INTO repeater_traffic (${columns.join(
      ", "
    )}) VALUES (${placeholders})`;

    const response = await this.execute<{ id: number }>(sql, values);

    if (!response.success) {
      return null;
    }

    return this.getRepeaterRequest(response.data?.id || 0);
  }

  /**
   * Update a replayed repeater request - Promise version
   * @param data Updated repeater data
   * @returns Promise resolving with operation success
   */
  async updateReplayedRepeater(data: RepeaterTrafficData): Promise<boolean>;
  /**
   * Update a replayed repeater request - Callback version
   * @param data Updated repeater data
   * @param callback Callback function with update status
   */
  updateReplayedRepeater(data: any, callback: (success: boolean) => void): void;

  // Implementation that handles both overloads
  updateReplayedRepeater(
    data: any,
    callback?: (success: boolean) => void
  ): Promise<boolean> | void {
    // Ensure id is available
    if (!data.id) {
      if (callback) {
        console.error("Error in updateReplayedRepeater: No ID provided");
        callback(false);
        return;
      }
      return Promise.resolve(false);
    }

    const id = data.id;
    const dataCopy = { ...data };
    delete dataCopy.id;

    // Ensure headers are stored as strings
    if (Array.isArray(dataCopy.request_headers)) {
      dataCopy.request_headers = JSON.stringify(dataCopy.request_headers);
    }

    if (Array.isArray(dataCopy.response_headers)) {
      dataCopy.response_headers = JSON.stringify(dataCopy.response_headers);
    }

    const columns = Object.keys(dataCopy);
    const values = [...Object.values(dataCopy), id];

    const setClause = columns.map((col) => `${col} = ?`).join(", ");
    const sql = `UPDATE repeater_traffic SET ${setClause} WHERE id = ?`;

    // Callback-based version
    if (callback) {
      this.db.run(sql, values, function (err) {
        if (err) {
          console.error("Error updating replayed repeater:", err.message);
          callback(false);
        } else {
          callback(true);
        }
      });
      return;
    }

    // Promise-based version
    return this.execute(sql, values).then((response) => response.success);
  }

  /**
   * Update the title of a repeater request
   * @param rowId Repeater record ID
   * @param title New title
   * @returns Promise resolving with operation success
   */
  async updateRepeaterTitle(rowId: number, title: string): Promise<boolean> {
    const sql = `UPDATE repeater_traffic SET title = ? WHERE id = ?`;
    const response = await this.execute(sql, [title, rowId]);

    return response.success;
  }

  /**
   * Delete a repeater tab
   * @param rowId Repeater record ID
   * @returns Promise resolving with operation success
   */
  async deleteRepeaterTab(rowId: number): Promise<boolean> {
    const sql = `DELETE FROM repeater_traffic WHERE id = ?`;
    const response = await this.execute(sql, [rowId]);

    return response.success;
  }

  /**
   * Create a new library - Promise version
   * @param data Library data
   * @returns Promise resolving with the created library
   */
  async createNewLibrary(
    data: Partial<LibraryData>
  ): Promise<LibraryData | null>;
  /**
   * Create a new library - Callback version
   * @param data Library data
   * @param callback Callback with inserted ID
   */
  createNewLibrary(data: any, callback: (id: number) => void): void;

  // Implementation that handles both overloads
  createNewLibrary(
    data: any,
    callback?: (id: number) => void
  ): Promise<LibraryData | null> | void {
    const libraryData = typeof data === "string" ? JSON.parse(data) : data;

    const columns = Object.keys(libraryData);
    const values = Object.values(libraryData);
    const placeholders = columns.map(() => "?").join(",");

    const sql = `INSERT INTO library (${columns.join(
      ", "
    )}) VALUES (${placeholders})`;

    // Callback-based version
    if (callback) {
      this.db.run(sql, values, function (err) {
        if (err) {
          console.error("Error creating new library:", err.message);
          callback(-1);
        } else {
          callback(this.lastID);
        }
      });
      return;
    }

    // Promise-based version
    return (async () => {
      const response = await this.execute<{ id: number }>(sql, values);

      if (!response.success) {
        return null;
      }

      const libraryId = response.data?.id;

      if (!libraryId) {
        return null;
      }

      // Return the created library
      const getResponse = await this.queryGet<LibraryData>(
        `SELECT * FROM library WHERE id = ?`,
        [libraryId]
      );

      return getResponse.success ? getResponse.data || null : null;
    })();
  }

  /**
   * Write traffic data to table (callback version for compatibility)
   * @param data Traffic data
   * @param callback Callback with inserted ID
   */
  writeToTable(data: any, callback: (id: number) => void): void {
    this.saveTraffic(data)
      .then((id) => {
        callback(id);
      })
      .catch((err) => {
        console.error("Error in writeToTable:", err);
        callback(-1);
      });
  }

  /**
   * Get a row from the database by ID (callback version for compatibility)
   * @param rowId Row ID
   * @param callback Callback with the row data
   */
  getRowFromDatabase(rowId: number, callback: (row: string) => void): void {
    this.getTrafficById(rowId)
      .then((data) => {
        callback(JSON.stringify(data));
      })
      .catch((err) => {
        console.error("Error in getRowFromDatabase:", err);
        callback("null");
      });
  }

  /**
   * Get data from database (callback version for compatibility)
   * @param callback Callback with data
   */
  getDataFromDatabase(callback: (data: string) => void): void {
    this.getSessionTraffic()
      .then((data) => {
        callback(JSON.stringify(data));
      })
      .catch((err) => {
        console.error("Error in getDataFromDatabase:", err);
        callback("[]");
      });
  }

  /**
   * Delete a library
   * @param libraryId Library ID
   * @returns Promise resolving with operation success
   */
  async deleteLibraryUsingId(libraryId: number): Promise<boolean> {
    const sql = `DELETE FROM library WHERE id = ?`;
    const response = await this.execute(sql, [libraryId]);

    return response.success;
  }

  /**
   * Delete a library (callback version for compatibility)
   * @param libraryId Library ID
   * @param callback Callback with operation success
   */
  deleteLibrary(libraryId: number, callback: (success: boolean) => void): void {
    this.deleteLibraryUsingId(libraryId)
      .then((success) => {
        callback(success);
      })
      .catch((err) => {
        console.error("Error in deleteLibrary:", err);
        callback(false);
      });
  }

  /**
   * Close the database connection
   */
  close(): void {
    this.db.close((err) => {
      if (err) {
        console.error("Error closing database:", err.message);
      } else {
        console.log("Database closed successfully");
      }
    });
  }
}
