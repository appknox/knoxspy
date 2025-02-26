import { WebSocketServer, WebSocket } from "ws";
import { Server as HttpServer } from "http";
import DBManager from "./database";
import { FridaManager } from "./fridamanager";
import Channels from "./channels";
import { Session } from "frida";
import REPLManager from "./repl";
import { DeviceDetails } from "./types";

/**
 * WebSocket message action types
 */
enum WebSocketAction {
  DEVICES = "devices",
  PROCESSES = "processes",
  APPS = "apps",
  ATTACH_APP = "attachApp",
  START_APP = "startApp",
  REPLAY_REQUEST = "replayRequest",
  ERROR = "error",
  JSON_ERROR = "jsonError",
  TRAFFIC_INIT = "trafficInit",
  TRAFFIC_UPDATE = "trafficUpdate",
  DEVICE_UPDATE = "deviceUpdate",
  SCRIPT_ERROR = "scriptError",
  SCRIPT_OUTPUT = "scriptOutput",
  SUCCESS_OUTPUT = "successOutput",
  DETECT_PLATFORM = "detectDevicePlatform",
  DETECT_LIBRARIES = "detectLibraries",
}

/**
 * Response message structure
 */
interface WebSocketResponse {
  action: WebSocketAction | string;
  message?: any;
  [key: string]: any;
}

/**
 * Session tracking interface
 */
interface SessionInfo {
  id: number;
  session: Session;
}

// Database manager singleton
const dbManager = new DBManager("./data.db");

// FridaManager singleton - for handling Frida operations
const fridaManager = new FridaManager();

/**
 * Handles an individual WebSocket client connection
 */
class WebSocketClient {
  private ws: WebSocket;
  private manager: WebSocketManager;
  private sessions: SessionInfo[] = [];
  private currentSession: { name: string; id: number } = { name: "", id: -1 };

  /**
   * Create a new WebSocket client handler
   */
  constructor(ws: WebSocket, manager: WebSocketManager) {
    this.ws = ws;
    this.manager = manager;

    // Use arrow functions to preserve 'this' context
    ws.on("close", () => this.close());
    ws.on("message", (message) => this.handleMessage(message.toString()));

    // Initialize client with data
    this.initialize();
  }

  /**
   * Initialize the client with existing data
   */
  private async initialize(): Promise<void> {
    try {
      const trafficData = await this.getDataFromDatabase();
      const sessionData = await this.getActiveSession();

      this.send({
        action: WebSocketAction.TRAFFIC_INIT,
        message: trafficData,
        session: sessionData,
      });
    } catch (error) {
      console.error("Error initializing WebSocket client:", error);
      this.sendError("Failed to initialize client");
    }
  }

  /**
   * Get data from the database
   */
  private async getDataFromDatabase(): Promise<any> {
    const response = await dbManager.getSessionTraffic();
    return response;
  }

  /**
   * Get active session from the database
   */
  private async getActiveSession(): Promise<any> {
    const session = await dbManager.getActiveSession();
    return session;
  }

  /**
   * Send a message to the client
   */
  public send(data: WebSocketResponse): void {
    if (this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data));
    }
  }

  /**
   * Send an error message to the client
   */
  private sendError(message: string | string[]): void {
    this.send({
      action: WebSocketAction.ERROR,
      message,
    });
  }

  /**
   * Send a JSON format error to the client
   */
  private sendJsonError(message: string | string[]): void {
    this.send({
      action: WebSocketAction.JSON_ERROR,
      message,
    });
  }

  /**
   * Validate if a string is valid JSON
   */
  private isValidJSON(str: string): boolean {
    try {
      JSON.parse(str);
      return true;
    } catch (e) {
      return false;
    }
  }

  /**
   * Check for missing parameters in a request
   */
  private checkMissingParams(data: any, requiredParams: string[]): string[] {
    const missingParams: string[] = [];

    for (const param of requiredParams) {
      if (!(param in data)) {
        missingParams.push(`${param} not provided`);
      }
    }

    return missingParams;
  }

  /**
   * Handle an incoming message
   */
  private async handleMessage(message: string): Promise<void> {
    if (!this.isValidJSON(message)) {
      return this.sendJsonError(["Payload is not a valid JSON!"]);
    }
    const data = JSON.parse(message);
    if (!data.action) {
      return this.sendJsonError(["Action is missing"]);
    }
    console.log("Action:", data.action);

    let devices: DeviceDetails[] = await fridaManager.getAllDevices();

    try {
      switch (data.action) {
        case "sessions":
          const sessions = await dbManager.getSessions();
          this.send({
            action: "sessionList",
            sessions,
          });
          break;

        case "createNewSession":
          if (!data.name) {
            return this.sendJsonError(["Session name is required"]);
          }
          const sessionData = {
            name: data.name,
            config: JSON.stringify({
              session: "No",
              device: "No",
              app: "No",
              library: "No",
            }),
          };
          const sessionId = await dbManager.createSession(sessionData);
          if (sessionId > 0) {
            await dbManager.setActiveSession(sessionId);
            const newSession = (await dbManager.getSessions(sessionId))[0];
            this.send({
              action: "activeSession",
              session: newSession,
            });
          } else {
            this.sendJsonError(["Failed to create session"]);
          }
          break;

        case "chooseSession":
          if (!data.session || !data.session.id) {
            return this.sendJsonError(["Invalid session selected"]);
          }
          await dbManager.setActiveSession(data.session.id);
          const activeSession = await dbManager.getActiveSession();
          this.send({
            action: "activeSession",
            session: activeSession,
          });
          break;

        case "clearActiveSession":
          const cleared = await dbManager.clearActiveSession();
          this.send({
            action: "clearActiveSession",
            status: !cleared,
          });
          break;

        case "deleteSession":
          if (!data.session || !data.session.id) {
            return this.sendJsonError(["Invalid session selected"]);
          }
          const deleted = await dbManager.deleteSession(data.session.id);
          this.send({
            action: "deleteSession",
            status: deleted,
            session: data.session.id,
            message: deleted,
          });
          break;

        case WebSocketAction.DEVICES:
          // Get all available devices
          devices = await fridaManager.getAllDevices();
          this.handleGetDevices(devices);
          break;
        case WebSocketAction.PROCESSES:
          await this.handleGetProcesses(data, devices);
          break;
        case WebSocketAction.APPS:
          await this.handleGetApps(data, devices);
          break;
        case WebSocketAction.ATTACH_APP:
          await this.handleAttachApp(data, devices);
          break;
        case WebSocketAction.START_APP:
          await this.handleStartApp(data, devices);
          break;
        case WebSocketAction.REPLAY_REQUEST:
          await this.handleReplayRequest(data);
          break;
        case WebSocketAction.DETECT_LIBRARIES:
          await this.handleDetectLibraries(data);
          break;
        case "changeLibrary":
          //console.log("Changing libraries");
          const tmpSessionId = data["sessionId"];
          const tmpLibrary = data["library"]["file"];
          //console.log(this.sessions);
          const tmpSession1 = this.sessions.map((item) => {
            if (item.id == tmpSessionId) {
              return item;
            }
          });
          if (tmpSession1.length > 0) {
            if (tmpSession1[0]) {
              //console.log(tmpSession1[0]);
              const repl = new REPLManager(
                tmpSession1[0]["session"],
                tmpSessionId,
                this.manager
              );
              repl.run_script(tmpLibrary);
              //console.log("changedLibrary already");
            }
          }
          break;
        case "sendToRepeater":
          const rowId = data["id"];
          //console.log("Row ID:" + tmpRepeaterPayload);
          dbManager.sendToRepeater(rowId).then((lastObj) => {
            //console.log("Entry created: " + lastObj.id);
            this.manager.broadcastData(
              JSON.stringify({ action: "repeaterAdd", message: lastObj })
            );
          });
          break;
        case "duplicateRepeater":
          const rowId1 = data["id"];
          //console.log("Row ID:" + tmpRepeaterPayload);
          dbManager.duplicateRepeater(rowId1).then((lastObj) => {
            //console.log("Entry created: " + lastObj.id);
            this.manager.broadcastData(
              JSON.stringify({ action: "repeaterAdd", message: lastObj })
            );
          });
          break;
        case "repeaterUpdate":
          dbManager.getRepeaterTraffic();
          break;
        case "replayRequest":
          var replayPayload = data["replay"];
          const tmpPlatform = data["platform"];
          var appData = data["appData"];
          var library = "iOS_makeAPIRequest.js";
          if (tmpPlatform.toLowerCase() === "android") {
            library = "okhttp_repeater.js";
          }
          //console.log('Replay request: ', replayPayload);
          const process = await fridaManager.findProcesses(
            appData.deviceId,
            appData.appName
          );
          const processID = process[0];
          const session = await fridaManager.attachToApp(
            appData.deviceId,
            processID["pid"]
          );
          console.log("Replay payload:", replayPayload);

          // this.sessions.push({'id': appData.sessionId, 'session': session})
          // const channel = new Channels(session, appData.appName, appData.sessionId, appData.appId, library, appData.deviceId, this.manager, processID.pid);
          // channel.connect()
          // if(library && library !== null) {
          const repl = new REPLManager(
            session,
            appData.sessionId,
            this.manager
          );
          repl.attach_script(library, replayPayload, this.manager);
          // }
          // else {
          //     this.send(JSON.stringify({"action":"jsonError", "message": ["No library provided"]}))
          // }

          //this.manager.broadcastData(JSON.stringify({'action': 'replayUpdate', 'replay': replayPayload}))
          break;
        case "setRepeaterTabTitle":
          //console.log("Row ID:" + tmpRepeaterPayload);
          dbManager
            .updateRepeaterTitle(data["id"], data["title"])
            .then((lastObj: any) => {
              this.manager.broadcastData(
                JSON.stringify({
                  action: "repeaterTabTitleUpdate",
                  message: lastObj,
                })
              );
            });
          break;
        case "deleteRepeaterTab":
          console.log("Repeater Deletion ID:" + data["id"]);
          dbManager.deleteRepeaterTab(data["id"]).then((status: any) => {
            this.manager.broadcastData(
              JSON.stringify({
                action: "deleteRepeaterTabUpdate",
                message: status,
                id: data["id"],
              })
            );
          });
          break;
        default:
          this.sendJsonError(["Unknown action"]);
      }
    } catch (error) {
      console.error(
        `Error handling WebSocket message (${data.action}):`,
        error
      );
      this.sendError(
        `Failed to handle request: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }

  /**
   * Handle the 'devices' action - get all available devices
   */
  private handleGetDevices(devices: DeviceDetails[]): void {
    console.log("Sending", devices);
    this.send({
      action: WebSocketAction.DEVICES,
      devices,
    });
  }

  /**
   * Handle the 'processes' action - get all processes on a device
   */
  private async handleGetProcesses(
    data: any,
    availableDevices: DeviceDetails[]
  ): Promise<void> {
    const deviceId = data.deviceId;

    if (!deviceId) {
      return this.sendJsonError("deviceId not provided");
    }

    const deviceExists = availableDevices.some(
      (device) => device.id === deviceId
    );

    if (!deviceExists) {
      return this.sendError("No such device found!");
    }

    const processes = await fridaManager.findProcesses(deviceId, "");
    this.send({
      action: WebSocketAction.PROCESSES,
      processes,
    });
  }

  /**
   * Handle the 'apps' action - get all apps on a device
   */
  private async handleGetApps(
    data: any,
    availableDevices: DeviceDetails[]
  ): Promise<void> {
    const deviceId = data.deviceId;

    if (!deviceId) {
      return this.sendJsonError("deviceId not provided");
    }

    const deviceExists = availableDevices.some(
      (device) => device.id === deviceId
    );

    if (!deviceExists) {
      return this.sendError("No such device found!");
    }

    const [apps, error] = await fridaManager.getApplications(deviceId);

    if (error) {
      return this.sendError(error);
    }

    this.send({
      action: WebSocketAction.APPS,
      apps,
    });
  }

  /**
   * Handle the 'attachApp' action - attach to a running app
   */
  private async handleAttachApp(
    data: any,
    availableDevices: DeviceDetails[]
  ): Promise<void> {
    const requiredParams = [
      "appId",
      "appName",
      "sessionId",
      "library",
      "deviceId",
    ];
    const missingParams = this.checkMissingParams(data, requiredParams);

    if (missingParams.length > 0) {
      return this.sendJsonError(missingParams);
    }

    const deviceId = data.deviceId;
    const deviceExists = availableDevices.some(
      (device) => device.id === deviceId
    );

    if (!deviceExists) {
      return this.sendError("No such device found!");
    }

    const { appId, appName, sessionId, library } = data;

    // Find the process by name
    const processes = await fridaManager.findProcesses(deviceId, appName);

    if (!processes.length) {
      return this.sendError(["App not running!"]);
    }

    const processId = processes[0].pid;

    // Attach to the process
    try {
      const session = await fridaManager.attachToApp(deviceId, processId);

      // Track the session
      const sessionInfo: SessionInfo = { id: sessionId, session };
      this.sessions.push(sessionInfo);

      // Create a channel to monitor the app
      const channel = new Channels(
        session,
        appName,
        sessionId,
        appId,
        library,
        deviceId,
        this.manager,
        processId
      );

      channel.connect();

      // Run the requested script
      if (library) {
        const repl = new REPLManager(session, sessionId, this.manager);
        await repl.run_script(library);
      } else {
        this.sendJsonError(["No library provided"]);
      }
    } catch (error) {
      console.error("Error attaching to app:", error);
      this.sendError(
        `Failed to attach to app: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }

  /**
   * Handle the 'startApp' action - launch an app
   */
  private async handleStartApp(
    data: any,
    availableDevices: DeviceDetails[]
  ): Promise<void> {
    const requiredParams = [
      "appId",
      "appName",
      "sessionId",
      "library",
      "deviceId",
    ];
    const missingParams = this.checkMissingParams(data, requiredParams);

    if (missingParams.length > 0) {
      return this.sendJsonError(missingParams);
    }

    const deviceId = data.deviceId;
    const deviceExists = availableDevices.some(
      (device) => device.id === deviceId
    );

    if (!deviceExists) {
      return this.sendError("No such device found!");
    }

    const { appId, appName, sessionId, library } = data;

    // Launch the app
    try {
      const result = await fridaManager.launchApp(deviceId, appId);

      if (!result.status) {
        return this.sendError(result.error || "Failed to launch app");
      }

      const session = result.output;

      // Track the session
      const sessionInfo: SessionInfo = { id: sessionId, session };
      this.sessions.push(sessionInfo);

      // Create a channel to monitor the app
      const channel = new Channels(
        session,
        appName,
        sessionId,
        appId,
        library,
        deviceId,
        this.manager
      );

      channel.connect();

      // Run the requested script
      if (library) {
        const repl = new REPLManager(session, sessionId, this.manager);
        await repl.run_script(library);
      } else {
        this.sendJsonError(["No library provided"]);
      }
    } catch (error) {
      console.error("Error launching app:", error);
      this.sendError(
        `Failed to launch app: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }

  /**
   * Handle the 'detectLibraries' action - detect libraries in the app
   */
  private async handleDetectLibraries(data: any): Promise<void> {
    console.log("Detecting libraries");
    const sessionId = data["sessionId"];
    console.log(this.sessions);
    const tmpSession = this.sessions.map((item) => {
      if (item.id == sessionId) {
        return item;
      }
    });
    if (tmpSession.length > 0) {
      if (tmpSession[0]) {
        //console.log(tmpSession[0]);
        const repl = new REPLManager(
          tmpSession[0]["session"],
          sessionId,
          this.manager
        );
        repl.detect_libraries();
      }
    }
  }

  /**
   * Handle the 'replayRequest' action - replay a previous request
   */
  private async handleReplayRequest(data: any): Promise<void> {
    const replayPayload = data.replay;
    const platform = data.platform;
    const appData = data.appData;

    // Select the appropriate script based on platform
    const library =
      platform.toLowerCase() === "android"
        ? "okhttp_repeater.js"
        : "iOS_makeAPIRequest.js";

    try {
      // Find the process
      const processes = await fridaManager.findProcesses(
        appData.deviceId,
        appData.appName
      );

      if (!processes.length) {
        return this.sendError("App not running");
      }

      const processId = processes[0].pid;

      // Attach to the app
      const session = await fridaManager.attachToApp(
        appData.deviceId,
        processId
      );

      console.log("Replay payload:", replayPayload);

      // Create REPL manager and attach the script
      const repl = new REPLManager(session, appData.sessionId, this.manager);
      await repl.attach_script(library, replayPayload, this.manager);
    } catch (error) {
      console.error("Error replaying request:", error);
      this.sendError(
        `Failed to replay request: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }

  /**
   * Handle client disconnection
   */
  private close(): void {
    console.log("Client disconnected");

    // Clean up any attached sessions
    this.sessions.forEach((sessionInfo) => {
      try {
        fridaManager
          .detachSession(sessionInfo.session)
          .catch((err) =>
            console.error(`Error detaching session ${sessionInfo.id}:`, err)
          );
      } catch (error) {
        console.error(
          `Error during session cleanup for ${sessionInfo.id}:`,
          error
        );
      }
    });
  }
}

/**
 * WebSocket server manager
 */
export default class WebSocketManager {
  private wss: WebSocketServer;

  /**
   * Create a new WebSocket server
   */
  constructor(server: HttpServer) {
    this.wss = new WebSocketServer({ server });

    this.wss.on("connection", (ws: WebSocket) => {
      console.log("New WebSocket client connected");
      new WebSocketClient(ws, this);
    });

    this.wss.on("error", (error) => {
      console.error("WebSocket server error:", error);
    });

    console.log("WebSocket server initialized");
  }

  /**
   * Broadcast a message to all connected clients
   */
  public broadcastData(data: string | object): void {
    const message = typeof data === "string" ? data : JSON.stringify(data);

    let clientCount = 0;
    this.wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
        clientCount++;
      }
    });

    console.log(`Broadcast message sent to ${clientCount} clients`);
  }

  /**
   * Gracefully close the server and all connections
   */
  public close(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.wss.close((err) => {
        if (err) {
          console.error("Error closing WebSocket server:", err);
          reject(err);
        } else {
          console.log("WebSocket server closed");
          resolve();
        }
      });
    });
  }
}
