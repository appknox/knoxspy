import * as frida from "frida";
import { execSync } from "child_process";
import { Scope } from "frida/dist/device";
import { AppsDetails, DeviceDetails, SessionInfo, AndroidUsersInfo } from "./types";
import Adb from "@devicefarmer/adbkit";
import { platform } from "os";

const client = Adb.createClient();



const defaultPng = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAHgAAAB4CAYAAAA5ZDbSAAAAAXNSR0IArs4c6QAAAGxlWElmTU0AKgAAAAgABAEaAAUAAAABAAAAPgEbAAUAAAABAAAARgEoAAMAAAABAAIAAIdpAAQAAAABAAAATgAAAAAAAACQAAAAAQAAAJAAAAABAAKgAgAEAAAAAQAAAHigAwAEAAAAAQAAAHgAAAAAYsi86AAAAAlwSFlzAAAWJQAAFiUBSVIk8AAAABxpRE9UAAAAAgAAAAAAAAA8AAAAKAAAADwAAAA8AAAS0isa0akAABKeSURBVHgB7NzXkhxFFgbgjuVmr7nc+30LHoLYJ1i9CjwEwWAGK7xAeDcMAuHd4I0YBi+sMIMRQlJtfhVztLmpLNddsxELmxGl7q6qPOb/T548mVWjxWIf2ptvvnnhs88+e9Hm5uY/77333kvuuuuutVtuueXwDTfccPT666/fWl9f377yyiuPX3755SfSsZuOk+k4tba2djodZ9P35n/xYDsf+JIOPu2m3yf4yufrrrtuCwawOHTo0No999xzCYxgBbN9oGIekR9//PHfXnrppQMvvvjiwXRsp6NZ5bj77rubBErz3HPPrSSntIE8chOws8mdWSbsDsISpvOws6SUpmkuSEZcvLW1tfHII480KTqbFJWN78nA5o033mjef//95rPPPmu+/vrr5vvvv29+/vnn5tdff21OnjzZnD17tj2SnPMaYlLEN7/99tt511Y5QR655M/VxsjkK59/+eWXFgNYwOTzzz9vMUqjt8Xs0UcfbTGE5UMPPcTOjZ2dnYuTrRcsSdNy3RKB/zh8+PCxBx54oHn++eebDz74oDWcs7///ntz+vTp9jhz5kwvkV0g/9EI7vIT8TBywAx2MDQQPvzwwzYQH3744QbWMF+OrQm9Pvnkk78/8cQTR9LRPPXUU80777zTfPrpp813333XGsngOdqfheAurOBolBvhx44da44ePdqkebp5+eWXj+BgAmXjb93e3j7w2GOP7Uofm5ubbYSJvP1of3aCc0xh/NFHHzUvvPBCI2M+/vjju++9996B8cwN3JmU/SWliMvMDwoK84hUsl/kcu7/BOcUN+dSuHnclIiLtDK5DDcD9PVfTgXJX6+44opDRu2tt95qLmgjCQH7efyJq+heXI1iHKRlVnPttdc2uMFRP4sd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"

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
	private activeSession: SessionInfo = { session: null, app: null, status: false };

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
				const packages = await this.getDeviceUserApplications(device, user);
				androidUsersInfo.push({
					id: user.id,
					name: user.name,
					apps: packages,
				});
			}
			return androidUsersInfo;
		} catch (error) {
			console.error(`Error getting applications for user ${platform} on device ${deviceId}:`, error);
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

	async getWorkApplications(deviceId: string): Promise<[AppsDetails[], string]> {
		let error = "";
		const workApplications: AppsDetails[] = [];
		

		try {
			let output = execSync("adb shell su -c 'pm list packages --user 10 -3'", { encoding: 'utf8' });			
			const packages = output
				.split('\n')
				.map(line => line.trim())
				.filter(line => line.startsWith('package:'))
				.map(line => line.replace('package:', ''));

			console.log('User-installed apps in Work Profile:');
			packages.forEach(async (pkg) => {
				const isWorkApp = await this.validateWorkApp(deviceId, pkg);
				if (isWorkApp) {
					workApplications.push({
						"id": pkg,
						"name": pkg,
						"icon": "",
						"type": "work",
					});
				}
			});
		} catch (e: any) {
			console.error(`Error finding apps on device ${deviceId}:`, e);
			error = e.message;
		}

		return [workApplications, error];
	}

	async validateWorkApp(deviceId: string, appId: string): Promise<boolean> {
		try {
			let output = execSync("adb shell su -c \"dumpsys package " + appId + " | grep -E \'User [0-9]+:|installed=true\' | grep -v \'User 0\' \"", { encoding: 'utf8' });
			// console.log("Work app output: " + output);
			if(output.length > 0) {
				return true;
			}
			return false;
		} catch (e: any) {
			console.error(`Error finding apps on device ${deviceId}:`, e);
			return false;
		}
	}

	/**
	 * Launch an application on a device
	 * @param deviceId The device ID
	 * @param appId The application ID
	 * @param user The user ID
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

			const pid = await device.spawn(appId, { uid: parseInt(user) });
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
	async attachToApp(deviceId: string, processID: number): Promise<frida.Session> {
		try {
			const device = await this.getDeviceById(deviceId);

			if (!device) {
				throw new Error(`Device with ID ${deviceId} not found`);
			}

			const session = await device.attach(processID);

			// Store session for later cleanup
			const sessionKey = `${deviceId}-pid-${processID}`;
			this.sessions.set(sessionKey, session);

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
