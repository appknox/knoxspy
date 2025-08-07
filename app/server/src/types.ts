
import { Session } from "frida";

export type AppsDetails = {
  icon: string;
  id: string;
  name: string;
  type: string;
};

export type DeviceDetails = {
  id: string;
  name: string;
  type: string;
  platform: string;
};

export interface LibraryData {
  id?: number;
  name: string;
  file: string;
  platform: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface App {
  id: string;
  name: string;
  platform: string;
  user: string;
  library: string;
  deviceId: string;
}

export interface SessionInfo {
  session: Session | null;
  app: App | null;
  status: boolean;
  channel: any | null;
  dashboard_data?: any;
}

export interface User {
  id: string;
  name: string;
}

export interface DeviceInfo {
  id: string;
  name: string;
  type: string;
  platform: string;
  users: any[];
}

export interface DashboardData {
  sessions: any[];
  devices: DeviceInfo[];
  libraries: LibraryData[];
  activeSession: any;
}

export interface AndroidUsersInfo {
  id: string;
  name: string;
  apps: AppsDetails[];
}

export interface DashboardQueryParams {
  sessionId?: string;
  device?: string;
  user?: string | "-1";
  app?: string;
  platform?: string;
  library?: string | "";
  action?: string | "spawn";
}