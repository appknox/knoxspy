import { WebSocketServer, WebSocket } from "ws";
import { Server as HttpServer } from "http";
import DBManager from "./database";
import { FridaManager } from "./fridamanager";
import Channels from "./channels";
import { Session } from "frida";
import REPLManager from "./repl";
import { DeviceDetails, SessionInfo, App, AndroidUsersInfo } from "./types";

/**
 * WebSocket message action types
 */
enum WebSocketAction {
	DEVICES = "devices",
	PROCESSES = "processes",
	APPS = "apps",
	SESSIONS = "sessions",
	CREATE_NEW_SESSION = "createNewSession",
	ATTACH_APP = "attachApp",
	START_APP = "spawnApp",
	REPLAY_REQUEST = "replayRequest",
	ERROR = "error",
	JSON_ERROR = "jsonError",
	TRAFFIC_INIT = "trafficInit",
	TRAFFIC_UPDATE = "trafficUpdate",
	REPEATER_UPDATE = "repeaterUpdate",
	REPLAY_UPDATE = "replayUpdate",
	REPEATER_INIT = "repeaterInit",
	SEND_TO_REPEATER = "sendToRepeater",
	DUPLICATE_REPEATER = "duplicateRepeater",
	DEVICE_UPDATE = "deviceUpdate",
	SCRIPT_ERROR = "scriptError",
	SCRIPT_OUTPUT = "scriptOutput",
	SUCCESS_OUTPUT = "successOutput",
	DETECT_PLATFORM = "detectDevicePlatform",
	DETECT_LIBRARIES = "detectLibraries",
	FIND_APP = "findApp",
	LIBRARIES = "libraries",
	CHANGE_LIBRARY = "changeLibrary",
	CHOOSE_SESSION = "chooseSession",
	CLEAR_ACTIVE_SESSION = "clearActiveSession",
	GET_ACTIVE_SESSION = "getActiveSession",
	DELETE_SESSION = "deleteSession",
	CONNECTED_APP = "connectedApp",
	GET_TRAFFIC = "getTraffic",
	DELETE_REPEATER_TAB = "deleteRepeaterTab",
	REPEATER_TAB_DELETED = "repeaterTabDeleted",
	DELETE_LIBRARY = "deleteLibrary",
	LIBRARY_DELETED = "libraryDeleted",
	GET_ALL_DEVICE_INFO = "getAllDeviceInfo",
	DEVICE_INFO = "deviceInfo",
	DISCONNECT_APP = "disconnectApp",
	APP_DISCONNECTED = "appDisconnected"
}

/**
 * Response message structure
 */
interface WebSocketResponse {
	action: WebSocketAction | string;
	message?: any;
	[key: string]: any;
}

// Global active session for all clients
let activeSession: SessionInfo = { session: null, app: null, status: false };


// FridaManager singleton - for handling Frida operations
const fridaManager = new FridaManager(activeSession);

/**
 * Handles an individual WebSocket client connection
 */
class WebSocketClient {
	private ws: WebSocket;
	private manager: WebSocketManager;
	private sessions: SessionInfo[] = [];
	private dbManager: DBManager;

	/**
	 * Create a new WebSocket client handler
	 */
	constructor(ws: WebSocket, manager: WebSocketManager, dbManager: DBManager) {
		this.ws = ws;
		this.manager = manager;
		this.dbManager = dbManager;

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
			const trafficData: Object = await this.getDataFromDatabase();
			this.send({
				action: WebSocketAction.TRAFFIC_INIT,
				message: JSON.stringify(trafficData),
			});
			const repeaterData: Object = await this.dbManager.getRepeaterTraffic();
			this.send({
				action: WebSocketAction.REPEATER_INIT,
				message: JSON.stringify(repeaterData),
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
		const response = await this.dbManager.getSessionTraffic();
		return response;
	}

	/**
	 * Get active session from the database
	 */
	private async getActiveSession(): Promise<any> {
		const session = await this.dbManager.getActiveSession();
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

		let devices: DeviceDetails[] = await fridaManager.getAllDevices();

		try {
			console.log("Trying to handle action:", data.action);
			switch (data.action) {
				case WebSocketAction.SESSIONS:
					const sessions = await this.dbManager.getSessions();
					this.send({
						action: "sessionList",
						sessions,
					});
					break;
				case WebSocketAction.CREATE_NEW_SESSION:
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
					const sessionId = await this.dbManager.createSession(sessionData);
					if (sessionId > 0) {
						await this.dbManager.setActiveSession(sessionId);
						const newSession = (await this.dbManager.getSessions(sessionId))[0];
						this.send({
							action: "activeSession",
							created: true,
							session: newSession,
						});
					} else {
						this.sendJsonError(["Failed to create session"]);
					}
					break;
				case WebSocketAction.CHOOSE_SESSION:
					if (!data.session || !data.session.id) {
						return this.sendJsonError(["Invalid session selected"]);
					}
					await this.dbManager.setActiveSession(data.session.id);
					const t_session = await this.dbManager.getActiveSession();
					this.send({
						action: "activeSession",
						session: t_session,
					});
					break;
				case WebSocketAction.CLEAR_ACTIVE_SESSION:
					const cleared = await this.dbManager.clearActiveSession();
					this.send({
						action: "clearActiveSession",
						status: cleared,
					});
					break;
				case WebSocketAction.DELETE_SESSION:
					if (!data.session || !data.session.id) {
						return this.sendJsonError(["Invalid session selected"]);
					}
					const deleted = await this.dbManager.deleteSession(data.session.id);
					this.send({
						action: "deleteSession",
						status: deleted,
						session: data.session.id,
						message: deleted,
					});
					break;
				case WebSocketAction.GET_ACTIVE_SESSION:
					this.send({
						action: "activeSession",
						session: await this.dbManager.getActiveSession(),
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
				case WebSocketAction.REPEATER_UPDATE:
					await this.handleRepeaterUpdate(data);
					break;
				case WebSocketAction.SEND_TO_REPEATER:
					await this.handleSendToRepeater(data);
					break;
				case WebSocketAction.DUPLICATE_REPEATER:
					await this.handleDuplicateRepeater(data);
					break;
				case WebSocketAction.REPEATER_INIT:
					await this.handleRepeaterInit(data);
					break;
				case WebSocketAction.TRAFFIC_INIT:
					await this.handleTrafficInit(data);
					break;
				case WebSocketAction.LIBRARIES:
					await this.handleGetLibraries(data);
					break;
				case WebSocketAction.CHANGE_LIBRARY:
					const tmpLibrary = data["library"]["file"];
					if (!activeSession) {
						return this.sendError(["No active session"]); 
					}
					activeSession.app!.library = data["library"]["file"];
					const repl = new REPLManager(activeSession, this.manager, this.dbManager);
					repl.run_script(tmpLibrary);
					break;
				case WebSocketAction.FIND_APP:
					await this.handleFindApp(data.deviceId, data.packageName);
					break;
				case WebSocketAction.CONNECTED_APP:
					await this.handleConnectedApp(data);
					break;
				case WebSocketAction.GET_TRAFFIC:
					await this.handleGetTraffic(data);
					break;
				case WebSocketAction.DELETE_REPEATER_TAB:
					await this.handleDeleteRepeaterTab(data);
					break;
				case WebSocketAction.DELETE_LIBRARY:
					await this.handleDeleteLibrary(data);
					break;
				case WebSocketAction.GET_ALL_DEVICE_INFO:
					await this.handleGetAllDeviceInfo(data);
					break;
				case WebSocketAction.DISCONNECT_APP:
					await this.handleDisconnectApp(data);
					break;
				default:
					this.sendJsonError(["Unknown action: " + data.action]);
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

	private async handleDisconnectApp(data: any): Promise<void> {
		console.log("Disconnecting app", data);
		activeSession = { session: null, app: null, status: false };
		await fridaManager.saveActiveSession(null);
		this.send({
			action: WebSocketAction.APP_DISCONNECTED,
			status: true,
		});
	}

	private async handleGetAllDeviceInfo(data: any): Promise<void> {
		console.log("Getting all device info for", data.deviceId);
		const t_users = await fridaManager.getDeviceUsers(data.deviceId);
		let t_apps: any = {};
		t_apps = await fridaManager.getAndroidUsersInfo(data.deviceId);
		this.send({
			action: WebSocketAction.DEVICE_INFO,
			users: t_users,
			apps: t_apps,
		});
	}

	private async handleDeleteLibrary(data: any): Promise<void> {
		console.log("Deleting library", data);
		this.dbManager.deleteLibrary(data.libraryId, (success) => {
			if (success) {
				console.log("Library deleted successfully", data.libraryId);
				this.send({
					action: WebSocketAction.LIBRARY_DELETED,
					id: data.libraryId,
				});
			}
		});
	}

	private async handleDeleteRepeaterTab(data: any): Promise<void> {
		console.log("Deleting repeater tab", data);
		await this.dbManager.deleteRepeaterTab(data.id);
		this.send({
			action: WebSocketAction.REPEATER_TAB_DELETED,
			id: data.id,
		});
	}

	private async handleGetTraffic(data: any): Promise<void> {
		const traffic = await this.dbManager.getTrafficBySession(data.session);
		this.send({
			action: WebSocketAction.TRAFFIC_INIT,
			message: JSON.stringify(traffic),
		});
		const replayTraffic = await this.dbManager.getRepeaterTrafficBySession(data.session);
		this.send({
			action: WebSocketAction.REPEATER_INIT,
			message: JSON.stringify(replayTraffic),
		});
	}

	private async sessionEventCallback(session: SessionInfo): Promise<void> {
		console.log(`Session event: connected=${session.status}, session=`, session);
		if(session.status === true && session.session) {
			console.log("Session connected");
			activeSession = { session: session.session, app: session.app, status: true};
			await fridaManager.saveActiveSession(session.session);
		} else {
			console.log("Session disconnected");
			activeSession = { session: null, app: null, status: false };
			await fridaManager.saveActiveSession(null);
		}
		// this.send({
		// 	action: WebSocketAction.CONNECTED_APP,
		// 	status: isConnected,
		// 	app: activeSession,
		// });
	}

	private async handleConnectedApp(data: any): Promise<void> {
		this.send({
			action: WebSocketAction.CONNECTED_APP,
			status: activeSession.session ? true : false,
			app: activeSession.app,
			session: activeSession.session,
		});
	}

	private async handleGetLibraries(data: any): Promise<void> {
		const libraries = await this.dbManager.getLibraries();
		this.send({
			action: WebSocketAction.LIBRARIES,
			libraries,
		});
	}

	private async handleTrafficInit(data: any): Promise<void> {
		const traffic = await this.dbManager.getSessionTraffic();
		this.send({
			action: WebSocketAction.TRAFFIC_INIT,
			traffic,
		});
	}

	private async handleRepeaterInit(data: any): Promise<void> {
		const traffic = await this.dbManager.getRepeaterTraffic();
		this.send({
			action: WebSocketAction.REPEATER_INIT,
			traffic,
		});
	}

	private async handleDuplicateRepeater(data: any): Promise<void> {
		const traffic = await this.dbManager.getRepeaterTraffic();
		this.send({
			action: WebSocketAction.DUPLICATE_REPEATER,
			traffic,
		});
	}

	private async handleSendToRepeater(data: any): Promise<void> {
		const output = await this.dbManager.sendToRepeater(data.id);
		this.send({
			action: WebSocketAction.REPEATER_UPDATE,
			traffic: JSON.stringify(output),
		});
	}

	private async handleRepeaterUpdate(data: any): Promise<void> {
		const traffic = await this.dbManager.getRepeaterTraffic();
		this.send({
			action: WebSocketAction.REPEATER_UPDATE,
			traffic: JSON.stringify(traffic),
		});
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

		let otherUserApps: AndroidUsersInfo[] = [];
		if(data.platform.toLowerCase() === "android") {
			otherUserApps = await fridaManager.getAndroidUsersInfo(deviceId);
		}

		this.send({
			action: WebSocketAction.APPS,
			apps,
			usersInfo: otherUserApps,
		});
	}

	private async handleFindApp(
		deviceId: string,
		packageName: string
	): Promise<any> {
		if (!deviceId) {
			return this.sendJsonError("deviceId not provided");
		}
		const devices = await fridaManager.getAllDevices();
		const foundDevice = devices.find((device) => device.id === deviceId);
		if (!foundDevice) {
			return this.sendError("No such device found!");
		}
		const [apps, error] = await fridaManager.getApplications(deviceId);
		if (error) {
			return this.sendError(error);
		}
		if (!apps.length) {
			return this.sendError("No apps found!");
		}
		const app = apps.find((app) => app.id === packageName);
		if (!app) {
			return this.sendError("App not found!");
		}
		this.send({
			action: WebSocketAction.FIND_APP,
			app: app,
			device: foundDevice,
		});
	}

	/**
	 * Handle the 'attachApp' action - attach to a running app
	 */
	private async handleAttachApp(
		data: any,
		availableDevices: DeviceDetails[]
	): Promise<void> {
		console.log("handleAttachApp", data);
		const requiredParams: string[] = [
			"appId",
			"appName",
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

		const { appId, appName, sessionId, library, platform, user } = data;

		// Find the process by name
		const processes = await fridaManager.findProcesses(deviceId, appName);

		if (!processes.length) {
			return this.sendError(["App not running!"]);
		}

		console.log("Found processes:", processes);

		const processId = processes[0].pid;
		console.log("Attaching to process:", processId);

		// Attach to the process
		try {
			const session = await fridaManager.attachToApp(deviceId, processId);

			// Track the session
			activeSession = { session, app: null, status: false };
			await fridaManager.saveActiveSession(session);

			// Create a channel to monitor the app
			const channel = new Channels(
				session,
				appName,
				appId,
				library,
				deviceId,
				platform,
				user,
				this.manager,
				processId,
				this.sessionEventCallback
			);

			channel.connect();

			// Run the requested script
			if (library) {
				const repl = new REPLManager(activeSession, this.manager, this.dbManager);
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
		const requiredParams = ["appId", "appName", "library", "deviceId", "user"];
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

		console.log("Starting app:", data);
		const { appId, appName, device, library, platform, user } = data;

		// Launch the app
		try {
			const result = await fridaManager.launchApp(deviceId, appId, user);

			if (!result.status) {
				return this.sendError(result.error || "Failed to launch app");
			}

			const session = result.output;

			const t_app: App = {
				identifier: appId,
				platform: platform,
				deviceId: deviceId,
				name: appName,
				user: user,
				library: library,
			};

			// Track the session
			activeSession = { session: session, app: t_app, status: true };
			console.log("New Session:", activeSession);
			await fridaManager.saveActiveSession(session);
			// console.log(activeSession);
			

			// Create a channel to monitor the app
			const channel = new Channels(
				session,
				appName,
				appId,
				library,
				deviceId,
				platform,
				user,
				this.manager,
				-1,
				this.sessionEventCallback
			);

			channel.connect();

			// Run the requested script
			if (library) {
				const repl = new REPLManager(activeSession, this.manager, this.dbManager);
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
		// const sessionId = data["sessionId"];
		// console.log(this.sessions);
		// const tmpSession = this.sessions.map((item) => {
		// 	if (item.id == sessionId) {
		// 		return item;
		// 	}
		// });
		// if (tmpSession.length > 0) {
		// 	if (tmpSession[0]) {
		// 		//console.log(tmpSession[0]);
		// 		const repl = new REPLManager(
		// 			tmpSession[0]["session"],
		// 			this.manager
		// 		);
		// 		repl.detect_libraries();
		// 	}
		// }
	}

	/**
	 * Handle the 'replayRequest' action - replay a previous request
	 */
	private async handleReplayRequest(data: any): Promise<void> {
		const replayPayload = data.replay;
		const platform = data.platform;

		// Select the appropriate script based on platform
		const library =
			platform.toLowerCase() === "android"
				? "android_makeAPIRequest.js"
				: "iOS_makeAPIRequest.js";

		try {
			// Find the process
			const deviceId = activeSession!.app!.deviceId;
			const appName = activeSession!.app!.name;
			console.log("Searching for process", deviceId, appName);
			const processes = await fridaManager.findProcesses(
				deviceId,
				appName
			);
			console.log("Found process", processes);

			if (!processes.length) {
				return this.sendError("App not running");
			}

			const processId = processes[0].pid;

			// Attach to the app
			const session = await fridaManager.attachToApp(
				deviceId,
				processId
			);

			activeSession.session = session;

			console.log("Replay payload:", replayPayload);

			// Create REPL manager and attach the script
			const repl = new REPLManager(activeSession, this.manager, this.dbManager);
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
					.detachSession(sessionInfo.session!)
					.catch((err) =>
						console.error(`Error detaching session:`, err)
					);
			} catch (error) {
				console.error(
					`Error during session cleanup:`,
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
	constructor(server: HttpServer, dbManager: DBManager) {
		this.wss = new WebSocketServer({ server });

		this.wss.on("connection", (ws: WebSocket) => {
			console.log("New WebSocket client connected");
			new WebSocketClient(ws, this, dbManager);
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

	public getActiveSession(): SessionInfo | null {
		return activeSession;
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
