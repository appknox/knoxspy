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
