import * as frida from 'frida';
import { DeviceManager, Session, SessionDetachReason } from 'frida';
import WebSocketManager from './websocket';
import { SessionInfo, App } from './types';

/**
 * Message structure for WebSocket communication
 */
interface ChannelMessage {
	action: string;
	message: string;
	appName: string;
	appId: string;
	library: string;
	deviceId: string;
	processId?: number;
	error?: string;
}

/**
 * Channels class manages communication between Frida sessions and WebSocket clients
 */
export default class Channels {
	private session: Session;
	private changedSignal!: frida.DevicesChangedHandler;
	private name: string;
	private appId: string;
	private library: string;
	private deviceId: string;
	private ws: WebSocketManager;
	private processId: number;
	private connected: boolean = false;
	private deviceManager: DeviceManager;
	private sessionCallback: (sessionInfo: SessionInfo) => void;

	/**
	 * Create a new Channels instance
	 * @param session Frida session
	 * @param name Application name
	 * @param sessionId Session ID
	 * @param appId Application ID
	 * @param library Library to use
	 * @param deviceId Device ID
	 * @param ws WebSocket manager
	 * @param processId Process ID (optional)
	 * @param sessionCallback Callback function for session events
	 */
	constructor(
		session: Session,
		name: string,
		appId: string,
		library: string,
		deviceId: string,
		ws: WebSocketManager,
		processId: number = -1,
		sessionCallback: (sessionInfo: SessionInfo) => void
	) {
		this.session = session;
		this.name = name;
		this.appId = appId;
		this.library = library;
		this.deviceId = deviceId;
		this.ws = ws;
		this.processId = processId;
		this.deviceManager = frida.getDeviceManager();
		this.sessionCallback = sessionCallback;
		
		console.log(`Channel for ${name} has been set up!`);
	}

	/**
	 * Handle device changes
	 */
	private onchange(): void {
		try {
			console.log("Device state changed");
			this.broadcastMessage({
				action: 'deviceStateChanged',
				message: 'Device state changed'
			});
		} catch (error) {
			console.error("Error handling device change:", error);
			this.broadcastMessage({
				action: 'error',
				message: 'Error handling device change',
				error: error instanceof Error ? error.message : String(error)
			});
		}
	}

	/**
	 * Disconnect from device manager events
	 */
	public disconnect(): void {
		try {
			if (this.connected && this.changedSignal) {
				this.deviceManager.changed.disconnect(this.changedSignal);
				this.connected = false;
				
				// this.broadcastMessage({
				// 	action: 'deviceUpdate',
				// 	message: 'Disconnected'
				// });
				
				console.log(`Channel for ${this.name} disconnected`);
			}
		} catch (error) {
			console.error("Error during disconnect:", error);
		}
	}

	/**
	 * Connect to device manager events and set up session monitoring
	 */
	public connect(): void {
		try {
			// Bind the onchange handler and connect to device manager events
			this.changedSignal = this.onchange.bind(this);
			this.deviceManager.changed.connect(this.changedSignal);
			this.connected = true;
			
			// Notify that the channel is connected
			this.broadcastMessage({
				action: 'deviceUpdate',
				message: 'Connected'
			});

			// Monitor session detachment
			this.session.detached.connect((reason: SessionDetachReason, crash) => {
				console.log(`Session detached: ${reason}`);
				
				// Send detailed information about the detachment
				const detachMessage: ChannelMessage = {
					action: 'deviceUpdate',
					message: 'Disconnected',
					appName: this.name,
					appId: this.appId,
					library: this.library,
					deviceId: this.deviceId,
				};
				
				// Include crash information if available
				if (crash) {
					detachMessage.error = `Process crashed: ${crash.summary}`;
					console.error("Process crashed:", crash);
				}
				
				this.ws.broadcastData(JSON.stringify(detachMessage));

				this.sessionCallback({ session: null, app: null, status: false });
				
				// Clean up the connection
				this.disconnect();
			});
		} catch (error) {
			console.error("Error connecting to device events:", error);
			this.broadcastMessage({
				action: 'error',
				message: 'Failed to connect to device events',
				error: error instanceof Error ? error.message : String(error)
			});
		}
	}

	/**
	 * Send a message with all channel details
	 * @param baseMessage Base message to send
	 */
	private broadcastMessage(baseMessage: Partial<ChannelMessage>): void {
		const message: ChannelMessage = {
			...baseMessage,
			appName: this.name,
			appId: this.appId,
			library: this.library,
			deviceId: this.deviceId,
			action: baseMessage.action || 'deviceUpdate',
			message: baseMessage.message || ''
		};
		
		if (this.processId > 0) {
			message.processId = this.processId;
		}
		if(baseMessage.message === 'Disconnected') {
			this.sessionCallback({ session: null, app: null, status: false });
		} else if (baseMessage.message === 'Connected') {
			const t_app: App = {
				name: this.name,
				identifier: this.appId,
				library: this.library,
				platform: "",
				deviceId: this.deviceId
			};
			this.sessionCallback({ session: this.session, app: t_app, status: true });
		}
		
		this.ws.broadcastData(JSON.stringify(message));
	}
	
	/**
	 * Get the session
	 * @returns The Frida session
	 */
	public getSession(): Session {
		return this.session;
	}
	
	/**
	 * Check if the channel is connected
	 * @returns True if connected
	 */
	public isConnected(): boolean {
		return this.connected;
	}
}