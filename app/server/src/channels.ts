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
	sessionId?: string;
	appId: string;
	library: string;
	deviceId: string;
	platform: string;
	user: string;
	processId?: number;
	error?: string;
	extra?: string;
}

/**
 * Channels class manages communication between Frida sessions and WebSocket clients
 */
export default class Channels {
	private session: Session;
	private changedSignal!: frida.DevicesChangedHandler;
	private name: string;
	private sessionId: string;
	private appId: string;
	private library: string;
	private deviceId: string;
	private platform: string;
	private user: string;
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
	 * @param platform Platform
	 * @param user User
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
		platform: string,
		user: string,
		ws: WebSocketManager,
		processId: number = -1,
		sessionCallback: (sessionInfo: SessionInfo) => void,
		sessionId: string = '',
	) {
		this.session = session;
		this.name = name;
		this.sessionId = sessionId;
		this.appId = appId;
		this.library = library;
		this.deviceId = deviceId;
		this.platform = platform;
		this.user = user;
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
				action: 'device.update',
				message: 'Changed'
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
				action: 'device.update',
				message: 'Connected',
				sessionId: this.sessionId,
				extra: 'Connected to ' + this.name
			});

			// Monitor session detachment
			this.session.detached.connect((reason: SessionDetachReason, crash) => {
				console.log(`Session detached: ${reason}`);
				
				// Send detailed information about the detachment
				const detachMessage: ChannelMessage = {
					action: 'device.update',
					message: 'Disconnected',
					appName: this.name,
					appId: this.appId,
					library: this.library,
					deviceId: this.deviceId,
					platform: this.platform,
					user: this.user,
					sessionId: this.sessionId
				};
				
				// Include crash information if available
				if (crash) {
					detachMessage.error = `Process crashed: ${crash.summary}`;
					console.error("Process crashed:", crash);
				}
				
				this.ws.broadcastData(JSON.stringify(detachMessage));

				this.sessionCallback({ session: null, app: null, status: false, channel: null });
				
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
			platform: this.platform,
			user: this.user,
			action: baseMessage.action || 'device.update',
			message: baseMessage.message || '',
			extra: baseMessage.extra || ''
		};
		
		if (this.processId > 0) {
			message.processId = this.processId;
		}
		if(baseMessage.message === 'Disconnected') {
			this.sessionCallback({ session: null, app: null, status: false, channel: null });
		} else if (baseMessage.message === 'Connected') {
			const t_app: App = {
				name: this.name,
				id: this.appId,
				library: this.library,
				platform: this.platform,
				deviceId: this.deviceId,
				user: this.user
			};
			this.sessionCallback({ session: this.session, app: t_app, status: true, channel: this });
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