
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
  name: string;
  identifier: string;
  platform: string;
  library: string;
  deviceId: string;
}

export interface SessionInfo {
  session: Session | null;
  app: App | null;
  status: boolean;
}

export interface AndroidUsersInfo {
  id: string;
  name: string;
  apps: AppsDetails[];
}