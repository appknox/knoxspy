import * as frida from "frida";
import { Scope } from "frida/dist/device";
import { AppsDetails, DeviceDetails } from "./types";

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

  constructor() {
    this.deviceManager = frida.getDeviceManager();
    this.sessions = new Map();
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
          () => reject(new Error(`Timeout getting device ${deviceId}`)),
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
    try {
      const devices = await this.deviceManager.enumerateDevices();
      const deviceDetails: DeviceDetails[] = [];

      // Process each device to get its platform
      for (const device of devices) {
        const platform = await this.getDevicePlatform(device);
        deviceDetails.push({
          id: device.id,
          name: device.name,
          type: device.type.toString(),
          platform: platform,
        });
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
      console.error(`Error getting platform for device ${device.id}:`, error);
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

  /**
   * Launch an application on a device
   * @param deviceId The device ID
   * @param appId The application ID
   * @returns Result with session or error
   */
  async launchApp(
    deviceId: string,
    appId: string
  ): Promise<OutputResult<frida.Session>> {
    const tmpOutput: OutputResult<frida.Session> = {
      output: null as unknown as frida.Session,
      status: false,
    };

    try {
      const device = await this.getDeviceById(deviceId);

      if (!device) {
        throw new Error(`Device with ID ${deviceId} not found`);
      }

      const pid = await device.spawn(appId);
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
  async attachApp(deviceId: string, processID: number): Promise<frida.Session> {
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
