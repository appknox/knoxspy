import { WebSocketServer, WebSocket } from "ws";
import { Server as HttpServer } from "http";
import DBManager from "./database";
import { FridaManager } from "./fridamanager";
import Channels from "./channels";
import { Session } from "frida";
import REPLManager from "./repl";
import { DeviceDetails, SessionInfo, App, DashboardData, DeviceInfo, AppsDetails } from "./types";

/**
 * WebSocket message action types
 */
enum WebSocketAction {
	DASHBOARD_INIT = "dashboard.init",

	SESSION_CREATE = "session.create",
	SESSION_DELETE = "session.delete",
	SESSION_CHOOSE = "session.choose",
	SESSION_CLEAR = "session.clear",

	TRAFFIC_INIT = "traffic.init",
	
	REPEATER_INIT = "repeater.init",
	REPEATER_ADD = "repeater.add",
	REPEATER_DUPLICATE = "repeater.duplicate",
	REPEATER_DELETE = "repeater.delete",
	REPEATER_UPDATE = "repeater.update",
	REPEATER_REPLAY = "repeater.replay",
	REPEATER_TAB_UPDATE = "repeater.tab.update",
	
	DEVICES_INIT = "devices.init",
	DEVICES_REFRESH = "devices.refresh",
	
	APPS_INIT = "apps.init",
	APPS_REFRESH = "apps.refresh",
	APP_SPAWN = "app.spawn",
	APP_ATTACH = "app.attach",
	APP_DISCONNECT = "app.disconnect",

	LIBRARY_CHANGE = "library.change",
	LIBRARY_LIST = "library.list",
	LIBRARY_DELETE = "library.delete",
	

	ERROR_GENERAL = "error.general",
	JSON_ERROR = "error.json",
}

enum WebSocketResponses {
	RSP_DASHBOARD_INIT = "dashboard.init.ack",
	RSP_TRAFFIC_INIT = "traffic.init.ack",
	RSP_REPEATER_INIT = "repeater.init.ack",
	RSP_REPEATER_ADD = "repeater.add.ack",
	RSP_REPEATER_DUPLICATE = "repeater.duplicate.ack",
	RSP_REPEATER_DELETE = "repeater.delete.ack",
	RSP_REPEATER_UPDATE = "repeater.update.ack",
	RSP_REPEATER_REPLAY = "repeater.replay.ack",
	RSP_REPEATER_TAB_UPDATE = "repeater.tab.update.ack",
	RSP_DEVICES_INIT = "devices.init.ack",
	RSP_DEVICES_REFRESH = "devices.refresh.ack",
	RSP_APPS_INIT = "apps.init.ack",
	RSP_APPS_REFRESH = "apps.refresh.ack",
	RSP_APP_CONNECTION = "app.connection",
	RSP_LIBRARY_CHANGE = "library.change.ack",
	RSP_LIBRARY_LIST = "library.list.ack",
	RSP_LIBRARY_DELETE = "library.delete.ack",

	RSP_GENERAL_ACK = "general.ack",
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
let activeSession: SessionInfo = { session: null, app: null, status: false, channel: null };


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
				action: WebSocketResponses.RSP_TRAFFIC_INIT,
				message: JSON.stringify(trafficData),
			});
			const repeaterData: Object = await this.dbManager.getRepeaterTraffic();
			this.send({
				action: WebSocketResponses.RSP_REPEATER_INIT,
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
	 * Clear the active session
	 */
	private clearActiveSession(): void {
		activeSession = { session: null, app: null, status: false, channel: null };
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
			action: WebSocketAction.ERROR_GENERAL,
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
		let required_params: string[] = [];
		let missing_params: string[] = [];

		try {
			console.log("Trying to handle action:", data.action);
			switch (data.action) {
				case WebSocketAction.DASHBOARD_INIT:
					await this.handleDashboardInit(data);
					break;
				case WebSocketAction.SESSION_CREATE:
					if (!data.name) {
						return this.sendJsonError(["Session name is required"]);
					}
					await this.handleSessionCreate(data);
					break;
				case WebSocketAction.SESSION_CHOOSE:
					if (!data.session || !data.session.id) {
						return this.sendJsonError(["Invalid session selected"]);
					}
					await this.handleSessionChoose(data);
					break;
				case WebSocketAction.SESSION_CLEAR:
					await this.handleSessionClear(data);
					break;
				case WebSocketAction.SESSION_DELETE:
					if (!data.session || !data.session.id) {
						return this.sendJsonError(["Invalid session selected"]);
					}
					await this.handleSessionDelete(data);
					break;
				case WebSocketAction.DEVICES_INIT:
					await this.handleDevicesInit(data);
					break;
				case WebSocketAction.DEVICES_REFRESH:
					await this.handleDevicesInit(data, true);
					break;
				case WebSocketAction.APPS_INIT:
					if (!data.device) {
						return this.sendJsonError(["Device is required"]);
					}
					await this.handleAppsInit(data);
					break;
				case WebSocketAction.APPS_REFRESH:
					if (!data.device) {
						return this.sendJsonError(["Device is required"]);
					}
					await this.handleAppsInit(data, true);
					break;
				case WebSocketAction.APP_SPAWN:
					required_params = ["deviceId", "appId", "platform", "appName", "user"];
					missing_params = this.checkMissingParams(data, required_params);
					if (missing_params.length > 0) {
						return this.sendJsonError(missing_params);
					}
					await this.handleAppSpawn(data);
					break;
				case WebSocketAction.APP_ATTACH:
					required_params = ["deviceId", "appId", "platform", "appName", "user"];
					missing_params = this.checkMissingParams(data, required_params);
					if (missing_params.length > 0) {
						return this.sendJsonError(missing_params);
					}
					await this.handleAppAttach(data);
					break;
				case WebSocketAction.APP_DISCONNECT:
					await this.handleAppDisconnect(data);
					break;
				case WebSocketAction.LIBRARY_CHANGE:
					await this.handleLibraryChange(data);
					break;
				case WebSocketAction.LIBRARY_LIST:
					await this.handleLibraryList(data);
					break;
				case WebSocketAction.LIBRARY_DELETE:
					await this.handleLibraryDelete(data);
					break;
				case WebSocketAction.TRAFFIC_INIT:
					await this.handleTrafficInit(data);
					break;
				case WebSocketAction.REPEATER_INIT:
					await this.handleRepeaterInit(data);
					break;
				case WebSocketAction.REPEATER_ADD:
					await this.handleRepeaterAdd(data);
					break;
				case WebSocketAction.REPEATER_DUPLICATE:
					await this.handleRepeaterDuplicate(data);
					break;
				case WebSocketAction.REPEATER_DELETE:
					await this.handleRepeaterDelete(data);
					break;
				case WebSocketAction.REPEATER_UPDATE:
					await this.handleRepeaterUpdate(data);
					break;
				case WebSocketAction.REPEATER_REPLAY:
					await this.handleRepeaterReplay(data);
					break;
				case WebSocketAction.REPEATER_TAB_UPDATE:
					await this.handleRepeaterTabUpdate(data);
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

	private async handleLibraryChange(data: any): Promise<void> {
		const tmpLibrary = data.library.file;
		if (!activeSession) {
			return this.sendError("No active session"); 
		}
		activeSession.app!.library = tmpLibrary;
		const repl = new REPLManager(activeSession, this.manager, this.dbManager);
		await repl.run_script(tmpLibrary);
	}

	private async handleLibraryList(data: any): Promise<void> {
		const libraries = await this.dbManager.getLibraries();
		this.send({
			action: WebSocketResponses.RSP_LIBRARY_LIST,
			libraries: libraries,
		});
	}

	private async handleLibraryDelete(data: any): Promise<void> {
		this.dbManager.deleteLibrary(data.libraryId, (deleted: boolean) => {
			if (!deleted) {
				this.sendError("Failed to delete library");
			} else {
				this.send({
					action: WebSocketResponses.RSP_LIBRARY_DELETE,
					status: true,
					libraryId: data.libraryId,
					message: "Library deleted successfully",
				});
			}
		});
	}

	private async handleAppSpawn(data: any): Promise<void> {
		if(activeSession.channel) {
			activeSession.channel.disconnect();
			console.log("[handleAppSpawn] Disconnected active session");
		}

		let result = await fridaManager.launchApp(data.deviceId, data.appId, data.user);
		if(!result.status) {
			this.sendError(result.error?.toString() || "Failed to launch app");
			return;
		}

		const session = result.output;
		const t_app: App = {
			id: data.appId,
			name: data.appName,
			platform: data.platform,
			deviceId: data.deviceId,
			user: data.user,
			library: data.library,
		};

		const channel = new Channels(
			session,
			data.appName,
			data.appId,
			data.library,
			data.deviceId,
			data.platform,
			data.user,
			this.manager,
			-1,
			this.sessionEventCallback,
			data.sessionId
		);

		channel.connect();

		activeSession = { session: session, app: t_app, status: true, channel: channel };
		await fridaManager.saveActiveSession(session);

		if (data.library) {
			console.log("[REPL] (handleAppSpawn) Running script: " + data.library);
			const repl = new REPLManager(activeSession, this.manager, this.dbManager);
			await repl.run_script(data.library);
		} else {
			this.sendJsonError(["No library provided"]);
		}

	}

	private async handleAppAttach(data: any): Promise<void> {
		const t_process = await fridaManager.findProcesses(data.deviceId, data.appName);
		if(!t_process.length) {
			this.sendError("Process not found");
			return;
		}

		console.log("[handleAppAttach] Process:", t_process);


		const session = await fridaManager.attachToApp(data.deviceId, t_process[0].pid);

		const t_app: App = {
			id: data.appId,
			name: data.appName,
			platform: data.platform,
			deviceId: data.deviceId,
			user: data.user,
			library: data.library,
		};

		const channel = new Channels(
			session,
			data.appName,
			data.appId,
			data.library,
			data.deviceId,
			data.platform,
			data.user,
			this.manager,
			-1,
			this.sessionEventCallback,
			data.sessionId
		);

		channel.connect();

		activeSession = { session: session, app: t_app, status: true, channel: channel };
		await fridaManager.saveActiveSession(session);

		if (data.library) {
			console.log("[REPL] (handleAppSpawn) Running script: " + data.library);
			const repl = new REPLManager(activeSession, this.manager, this.dbManager);
			await repl.run_script(data.library);
		} else {
			this.sendJsonError(["No library provided"]);
		}
	}

	private async handleDashboardInit(data: any): Promise<void> {
		let sessionsData: any[] = await this.dbManager.getSessions();
		let devicesData: any[] = await fridaManager.getAllDevices();
		let librariesData: any[] = await this.dbManager.getLibraries();

		let devices: DeviceInfo[] = [];
		for (let device of devicesData) {
			let users = [];
			if(device.platform.toLowerCase() == "android") {
				users = await fridaManager.getAndroidUsersInfo(device.id);
			} else {
				users = await fridaManager.getApplications(device.id);
			}
			devices.push({
				id: device.id,
				name: device.name,
				type: device.type,
				platform: device.platform,
				users: users,
			});
		}

		let dashboardData: DashboardData = {
			sessions: sessionsData,
			devices: devices,
			libraries: librariesData,
			activeSession: await this.dbManager.getActiveSession(),
		};
		this.send({
			action: WebSocketResponses.RSP_DASHBOARD_INIT,
			data: dashboardData,
		});
	}

	private async handleSessionCreate(data: any): Promise<void> {
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
				action: "session.create.ack",
				created: true,
				session: newSession,
			});
		} else {
			this.sendJsonError(["Failed to create session"]);
		}
	}

	private async handleSessionChoose(data: any): Promise<void> {
		if (!data.session || !data.session.id) {
			return this.sendJsonError(["Invalid session selected"]);
		}
		await this.dbManager.setActiveSession(data.session.id);
		const t_session = await this.dbManager.getActiveSession();
		this.send({
			action: "session.choose.ack",
			session: t_session,
		});
	}

	private async handleSessionClear(data: any): Promise<void> {
		const cleared = await this.dbManager.clearActiveSession();
		this.send({
			action: "session.clear.ack",
			status: cleared,
		});
	}

	private async handleSessionDelete(data: any): Promise<void> {
		if (!data.session || !data.session.id) {
			return this.sendJsonError(["Invalid session selected"]);
		}
		const deleted = await this.dbManager.deleteSession(data.session.id);
		this.send({
			action: "session.delete.ack",
			status: deleted,
			session: data.session.id,
			message: deleted,
		});
	}

	private async handleDevicesInit(data: any, refresh: boolean = false): Promise<void> {
		let devicesData: any[] = await fridaManager.getAllDevices();
		let devices: DeviceInfo[] = [];
		for (let device of devicesData) {
			let users = [];
			if(device.platform.toLowerCase() == "android") {
				users = await fridaManager.getAndroidUsersInfo(device.id);
			} else {
				users = await fridaManager.getApplications(device.id);
			}
			devices.push({
				id: device.id,
				name: device.name,
				type: device.type,
				platform: device.platform,
				users: users,
			});
		}
		this.send({
			action: refresh ? WebSocketResponses.RSP_DEVICES_REFRESH : WebSocketResponses.RSP_DEVICES_INIT,
			data: devices,
		});
	}

	private async handleAppsInit(data: any, refresh: boolean = false): Promise<void> {
		const t_device = data.device;
		const t_platform = data.platform;
		let users;
		if(t_platform.toLowerCase() == "android") {
			users = await fridaManager.getAndroidUsersInfo(t_device);
		} else {
			users = await fridaManager.getApplications(t_device);
		}
		this.send({
			action: refresh ? WebSocketResponses.RSP_APPS_REFRESH : WebSocketResponses.RSP_APPS_INIT,
			platform: t_platform,
			data: users,
		});
	}

	private async handleAppDisconnect(data: any): Promise<void> {
		console.log("[handleAppDisconnect] App disconnected");
		if(activeSession.channel) {
			activeSession.channel.disconnect();
		}
		activeSession = { session: null, app: null, status: false, channel: null };
		await fridaManager.saveActiveSession(null);
		console.log("[handleAppDisconnect] Active session cleared");
		this.send({
			action: WebSocketResponses.RSP_APP_CONNECTION,
			status: true,
		});
	}

	private async handleTrafficInit(data: any): Promise<void> {
		const trafficData: Object = await this.getDataFromDatabase();
		this.send({
			action: WebSocketResponses.RSP_TRAFFIC_INIT,
			message: JSON.stringify(trafficData),
		});
	}

	private async handleRepeaterInit(data: any): Promise<void> {
		const traffic = await this.dbManager.getRepeaterTraffic();
		this.send({
			action: WebSocketResponses.RSP_REPEATER_INIT,
			message: JSON.stringify(traffic),
		});
	}

	private async handleRepeaterDuplicate(data: any): Promise<void> {
		const traffic = await this.dbManager.getRepeaterTraffic();
		this.send({
			action: WebSocketResponses.RSP_REPEATER_DUPLICATE,
			traffic,
		});
	}

	private async handleRepeaterDelete(data: any): Promise<void> {
		await this.dbManager.deleteRepeaterTab(data.id);
		this.send({
			action: WebSocketResponses.RSP_REPEATER_DELETE,
			id: data.id,
		});
	}

	private async handleRepeaterAdd(data: any): Promise<void> {
		const output = await this.dbManager.sendToRepeater(data.id);
		this.send({
			action: WebSocketResponses.RSP_REPEATER_ADD,
			traffic: JSON.stringify(output),
		});
	}

	private async handleRepeaterUpdate(data: any): Promise<void> {
		const traffic = await this.dbManager.getRepeaterTraffic();
		this.send({
			action: WebSocketResponses.RSP_REPEATER_UPDATE,
			traffic: JSON.stringify(traffic),
		});
	}

	private async handleRepeaterReplay(data: any): Promise<void> {
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

	private async handleRepeaterTabUpdate(data: any): Promise<void> {
		const result = await this.dbManager.updateRepeaterTitle(data.id, data.title);
		if (result) {
			this.send({
				action: WebSocketResponses.RSP_REPEATER_TAB_UPDATE,
				id: data.id,
				title: data.title,
			});
		}
	}

	private async sessionEventCallback(session: SessionInfo): Promise<void> {
		console.log(`Session event: connected=${session.status}, session=`, session);
		if(session.status === true && session.session) {
			console.log("Session connected");
			activeSession = { session: session.session, app: session.app, status: true, channel: session.channel};
			await fridaManager.saveActiveSession(session.session);
		} else {
			console.log("Session disconnected");
			activeSession = { session: null, app: null, status: false, channel: null };
			await fridaManager.saveActiveSession(null);
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
