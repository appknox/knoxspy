import * as frida from "frida";
import { Scope } from "frida/dist/device";
import { AppsDetails, DeviceDetails, SessionInfo, AndroidUsersInfo } from "./types";
import Adb from "@devicefarmer/adbkit";

const client = Adb.createClient();

/**
 * Represents the result of an operation that may succeed or fail
 */
interface OutputResult<T> {
	output: T;
	status: boolean;
	error?: string;
}

/**
 * Options for device operations
 */
interface OperationOptions {
	timeout?: number;
	scope?: Scope;
}

/**
 * Convert byte array to image URI for app icons
 */
function bytesToImageURI(byteBuffer: Buffer): string {
	const base64String = Buffer.from(byteBuffer).toString('base64');
	return "data:image/png;base64," + base64String;
}

/**
 * Compare apps by type for sorting
 */
function compareByType(a: AppsDetails, b: AppsDetails): number {
	if (a.type < b.type) return -1;
	if (a.type > b.type) return 1;
	return a.name.localeCompare(b.name); // Secondary sort by name
}

/**
 * Manager class for Frida operations
 */
export class FridaManager {
	private deviceManager: frida.DeviceManager;
	private sessions: Map<string, frida.Session>;
	private readonly DEFAULT_TIMEOUT = 10000; // 10 seconds
	private activeSession: SessionInfo = { session: null, app: null, status: false, channel: null };

	constructor(activeSession: SessionInfo | null = null) {
		this.deviceManager = frida.getDeviceManager();
		this.sessions = new Map();
		this.activeSession.session = activeSession?.session || null;
	}

	async saveActiveSession(session: frida.Session | null): Promise<void> {
		this.activeSession.session = session;
	}

	/**
	 * Get all users on a device
	 * @param deviceId The ID of the device
	 * @returns List of users
	 */
	async getDeviceUsers(deviceId: string): Promise<DeviceDetails[]> {
		try {
			const device = client.getDevice(deviceId);
			return device.shell('pm list users | grep -v Users:').then(Adb.util.readAll).then((output: string) => {
				const users = output
					.toString()
					.trim()
					.split('\n')
					.map((line: any) => {
						const match = line.match(/UserInfo\{(\d+):(.+?):\w+\}/);
						return {
							id: match?.[1],
							name: match?.[2],
						};
					});
				return users;
			});
		} catch (error) {
			console.error(`Error getting users for device ${deviceId}:`, error);
			return [];
		}
	}

	/**
	 * Get all applications for a user on a device
	 * @param deviceId The ID of the device
	 * @param userId The ID of the user
	 * @returns List of applications
	 */
	async getDeviceUserApplications(device: any, user: any): Promise<AppsDetails[]> {
		let t_packages: AppsDetails[] = [];
		try {
			const t_fetched_packages = await device.getPackages("--user " + user.id + " -3");
			for (const pkg of t_fetched_packages) {
				t_packages.push({
					icon: "",
					id: pkg,
					name: pkg,
					type: user.id == "0" ? "user" : "work",
				});
			}
		} catch (error) {
			console.error(`Error getting applications for user ${user.id} on device ${device.id}:`, error);
		}
		return t_packages;
	}

	/**
	 * Get all users info on an android device
	 * @param deviceId The ID of the device
	 * @returns List of users info with their apps
	 */
	async getAndroidUsersInfo(deviceId: string): Promise<AndroidUsersInfo[]> {
		try {
			const device = client.getDevice(deviceId);
			const users = await this.getDeviceUsers(deviceId);
			let androidUsersInfo: AndroidUsersInfo[] = [];
			for (const user of users) {
				if( user.id === "0") {
					continue;
				}
				const packages = await this.getDeviceUserApplications(device, user);
				androidUsersInfo.push({
					id: user.id,
					name: user.name,
					apps: packages,
				});
			}

			const t_main_user = users.find((user: any) => user.id === "0");
			const [t_main_apps, error] = await this.getApplications(deviceId);
			const t_main_user_obj = {
				id: t_main_user?.id || "0",
				name: t_main_user?.name || "android",
				apps: t_main_apps,
			}
			androidUsersInfo = [t_main_user_obj, ...androidUsersInfo];
			return androidUsersInfo;
		} catch (error) {
			console.error(`Error getting applications for device ${deviceId}:`, error);
			return [];
		}
	}


	/**
	 * Find a device by its ID
	 * @param deviceId The ID of the device to find
	 * @param options Operation options
	 * @returns The device or null if not found
	 */
	async getDeviceById(
		deviceId: string,
		options: OperationOptions = {}
	): Promise<frida.Device | null> {
		try {
			const timeout = options.timeout || this.DEFAULT_TIMEOUT;

			// Use Promise.race to implement timeout
			const devicePromise = this.deviceManager
				.enumerateDevices()
				.then((devices) => devices.find((dev) => dev.id === deviceId) || null);

			const timeoutPromise = new Promise<null>((_, reject) => {
				setTimeout(
					() =>   reject(new Error(`Timeout getting device ${deviceId}`)),
					timeout
				);
			});

			return await Promise.race([devicePromise, timeoutPromise]);
		} catch (error) {
			console.error(`Error finding device ${deviceId}:`, error);
			return null;
		}
	}

	/**
	 * Get all available devices with platform information
	 * @returns List of devices with platform information
	 */
	async getAllDevices(): Promise<DeviceDetails[]> {
		const supportedPlatforms = ["Android", "iOS", "iPhone OS"];
		try {
			const devices = await this.deviceManager.enumerateDevices();
			const deviceDetails: DeviceDetails[] = [];

			// Process each device to get its platform
			for (const device of devices) {
				const platform = await this.getDevicePlatform(device);
				if (supportedPlatforms.includes(platform)) {
					deviceDetails.push({
						id: device.id,
						name: device.name,
						type: device.type.toString(),
						platform: platform,
					});
				}
			}

			return deviceDetails;
		} catch (error) {
			console.error("Error enumerating devices:", error);
			return [];
		}
	}

	/**
	 * Get the platform of a device
	 * @param device The device
	 * @returns The platform name
	 */
	async getDevicePlatform(device: frida.Device): Promise<string> {
		try {
			const params = await device.querySystemParameters();
			return params.os?.name || "Unknown";
		} catch (error) {
			return "Unknown";
		}
	}

	/**
	 * Find processes on a device, optionally filtered by app name
	 * @param deviceId The device ID
	 * @param appName Optional app name filter
	 * @returns List of processes
	 */
	async findProcesses(deviceId: string, appName: string = ""): Promise<any[]> {
		try {
			const device = await this.getDeviceById(deviceId);
			if (!device) {
				throw new Error(`Device with ID ${deviceId} not found`);
			}

			const processes = await device.enumerateProcesses({ scope: Scope.Full });
			// console.log("[findProcesses] Processes:", processes);

			if (appName.trim() !== "") {
				return processes.filter((proc) => proc.name === appName);
			}

			return processes;
		} catch (error) {
			console.error(`Error finding processes on device ${deviceId}:`, error);
			return [];
		}
	}

	/**
	 * Find process PIDs by user ID
	 * @param deviceId The device ID
	 * @param appName The application name to filter by
	 * @param targetUid The user ID to filter by
	 * @returns List of process PIDs
	 */
	async findProcessPidsByUid(deviceId: string, appName: string, targetUid: number): Promise<string[]> {
		const device = client.getDevice(deviceId);

		// Filter ps output for processes whose USER column starts with u{targetUid}_
		const shellCmd = `ps -A | grep ${appName} | grep -E "^u${targetUid}_"`;

		return device.shell(shellCmd)
			.then(Adb.util.readAll)
			.then((output: string) => {
				const lines = output.toString().trim().split("\n").filter(Boolean);

				if (lines.length === 0) {
					return [];
				}

				// Extract PID from column 2 (index 1) of each line
				const pids = lines.map(line => {
					const parts = line.trim().split(/\s+/);
					return { pid: parts[1] }; // PID column
				});

				return pids;
			});
	}


	/**
	 * Find applications on a device
	 * @param deviceId The device ID
	 * @returns Tuple of [apps, error]
	 */
	async getApplications(deviceId: string): Promise<[AppsDetails[], string]> {
		let error = "";
		const filteredApplications: AppsDetails[] = [];

		try {
			const device = await this.getDeviceById(deviceId);
			if (!device) {
				throw new Error(`Device with ID ${deviceId} not found`);
			}

			const applications = await device.enumerateApplications({
				scope: Scope.Full,
			});

			for (const app of applications) {
				const params = app.parameters;
				if (params.icons?.length) {
					const imageData = bytesToImageURI(params.icons[0].image);
					const appsDetails: AppsDetails = {
						icon: imageData,
						id: app.identifier,
						name: app.name,
						type: "user",
					};
					filteredApplications.push(appsDetails);
				}
			}

			filteredApplications.sort(compareByType);
		} catch (e: any) {
			console.error(`Error finding apps on device ${deviceId}:`, e);
			error = e.message;
		}

		return [filteredApplications, error];
	}

	/**
	 * Launch an application on a device
	 * @param deviceId The device ID
	 * @param appId The application ID
	 * @param user The user ID to launch the app under
	 * @returns Result with session or error
	 */
	async launchApp(
		deviceId: string,
		appId: string,
		user: string
	): Promise<OutputResult<frida.Session>> {
		if (this.activeSession) {
			console.log("Active session already exists. Will try to attach to app instead!");
		}
			
		const tmpOutput: OutputResult<frida.Session> = {
			output: null as unknown as frida.Session,
			status: false,
		};

		try {
			const device = await this.getDeviceById(deviceId);

			if (!device) {
				throw new Error(`Device with ID ${deviceId} not found`);
			}

			const pid = await device.spawn(appId, { uid: parseInt(user)} );
			device.resume(pid);
			const session = await device.attach(pid);

			// Store session for later cleanup
			const sessionKey = `${deviceId}-${appId}-${pid}`;
			this.sessions.set(sessionKey, session);

			tmpOutput.output = session;
			tmpOutput.status = true;
		} catch (e: any) {
			console.error(`Error launching app ${appId} on device ${deviceId}:`, e);
			tmpOutput.output = null as unknown as frida.Session;
			tmpOutput.error = `Error launching app: ${e.message}`;
			tmpOutput.status = false;
		}

		return tmpOutput;
	}

	/**
	 * Attach to a running process on a device
	 * @param deviceId The device ID
	 * @param processID The process ID
	 * @returns Frida session
	 */
	async attachToApp(deviceId: string, processID: string): Promise<frida.Session> {
		try {
			const device = await frida.getDevice(deviceId);

			if (!device) {
				throw new Error(`Device with ID ${deviceId} not found`);
			}

			const session = await device.attach(parseInt(processID));

			// Store session for later cleanup
			// const sessionKey = `${deviceId}-pid-${processID}`;
			// this.sessions.set(sessionKey, session);

			return session;
		} catch (error) {
			console.error(
				`Error attaching to process ${processID} on device ${deviceId}:`,
				error
			);
			throw error;
		}
	}

	/**
	 * Detach from a session
	 * @param session The session to detach from
	 */
	async detachSession(session: frida.Session): Promise<boolean> {
		try {
			await session.detach();

			// Remove from tracked sessions
			for (const [key, value] of this.sessions.entries()) {
				if (value === session) {
					this.sessions.delete(key);
					break;
				}
			}

			return true;
		} catch (error) {
			console.error("Error detaching session:", error);
			return false;
		}
	}

	/**
	 * Clean up all active sessions
	 */
	async cleanup(): Promise<void> {
		const detachPromises: Promise<void>[] = [];

		for (const [key, session] of this.sessions.entries()) {
			detachPromises.push(
				session.detach().catch((err) => {
					console.error(`Error detaching session ${key}:`, err);
				})
			);
		}

		await Promise.allSettled(detachPromises);
		this.sessions.clear();
	}
}
