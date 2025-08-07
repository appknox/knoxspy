export interface DashboardData {
	sessions: any[];
	devices: any[];
	libraries: any[];
	apps: any[];
	users: any[];
}

export interface DashboardSelectedData {
	session: any;
	device: any;
	user: any;
	app: any;
	apps: any[];
	platform: string;
	library: any;
	action: string;
	sessionId: string;
}

export interface DashboardStatus {
	sessionStatus: boolean;
	appStatus: boolean;
	dashboardStatus: boolean;
	sidebarStatus: boolean;
	appConnectingStatus: boolean;
	appConnectionTime: number;
}

export interface ConnectedApp {
	app: any;
	session: any;
	status: boolean;
}
