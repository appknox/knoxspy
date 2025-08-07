import { defineStore } from "pinia"
import { ref } from "vue";
import { onUnmounted } from "vue";
import { DashboardData, DashboardSelectedData, DashboardStatus, ConnectedApp } from "../types";

export const useAppStore = defineStore('current_session', {

    state: () => ({
        data: {
            sessions: [],
            apps: [],
            devices: [],
            libraries: [],
            users: [],
        } as DashboardData,
        selection: {
            sessionId: "",
            session: {},
            device: {},
            user: {},
            app: {},
            apps: [],
            platform: "",
            library: {},
        } as DashboardSelectedData,
        status: {
            dashboardStatus: false,
            sessionStatus: false,
            appStatus: false,
            appConnectingStatus: false,
            appConnectionTime: 0,
            sidebarStatus: false,
        } as DashboardStatus,
        connectedApp: {
            status: false,
            app: {},
            session: {},
        } as ConnectedApp,
    }),
    getters: {
        getData: (state) => state.data,
        getSelection: (state) => state.selection,
        getStatus: (state) => state.status,
        getConnectedApp: (state) => state.connectedApp,
    },
    actions: {
        setData(data: DashboardData) {
            this.data = data;
        },
        setDataKey(key: keyof DashboardData, value: any) {
            this.data[key] = value;
        },
        setSelection(data: DashboardSelectedData) {
            this.selection = data;
        },
        setSelectionKey(key: keyof DashboardSelectedData, value: any) {
            this.selection[key] = value;
            // console.log(`Session(setSelectionKey): Updated selection key ${key} with value`, value);
        },
        setStatus(data: DashboardStatus) {
            this.status = data;
        },
        setStatusKey<K extends keyof DashboardStatus>(key: K, value: DashboardStatus[K]) {
            this.status[key] = value;
        },
        setConnectedApp(data: ConnectedApp) {
            this.connectedApp = data;
        },
        async syncBackSelection(callback?: () => void) {
            console.log("Session(updateSelectionFromServer): Updating selection from server");
            await fetch("http://localhost:8000/api/sync/selection", {
                method: "GET",
                headers: {
                    "Content-Type": "application/json",
                },
            }).then((response) => response.json()).then((data) => {
                console.log("Session(syncBackSelection): Data synced from server", data);
                if(data.status) {
                    this.setSelectionKey("sessionId", data.selection.sessionId || "");
                    const t_query_params = {
                        app: data.selection.app,
                        device: data.selection.device,
                        platform: data.selection.platform,
                        user: data.selection.user,
                        library: data.selection.library || "",
                        action: data.selection.action,
                    }
                    this.updateSelectionFromServer(t_query_params);

                    if(callback) {
                        callback();
                    }
                }
            });
        },
        async syncConnectedApp() {
            await fetch("http://localhost:8000/api/connected", {
                method: "GET",
                headers: {
                    "Content-Type": "application/json",
                },
            }).then((response) => response.json()).then((data) => {
                this.connectedApp = data;
            });
            return this.connectedApp;
        },
        async syncSelection() {
            let t_selection_minimal = {
                app: "",
                device: "",
                platform: "",
                user: "-1",
                library: "",
                action: "spawn",
                sessionId: ""
            };
            if(this.getSelection.app.id) {
                t_selection_minimal["app"] = this.getSelection.app.id;
            }
            if(this.getSelection.device.id) {
                t_selection_minimal["device"] = this.getSelection.device.id;
            }
            if(this.getSelection.platform) {
                t_selection_minimal["platform"] = this.getSelection.platform;
            }
            if(this.getSelection.user.id) {
                t_selection_minimal["user"] = this.getSelection.user.id;
            }
            if(this.getSelection.library.file) {
                t_selection_minimal["library"] = this.getSelection.library.file;
            }
            if(this.getSelection.action) {
                t_selection_minimal["action"] = this.getSelection.action;
            }
            if(this.getSelection.sessionId) {
                t_selection_minimal["sessionId"] = this.getSelection.sessionId;
            }
            console.log("Session(syncSelection): Syncing selection to server", t_selection_minimal);
            await fetch("http://localhost:8000/api/sync/selection", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(t_selection_minimal),
            });
        },


        // General Actions
        checkRequiredQueryParams(queryParams: any) {
            console.log("Session(checkRequiredQueryParams): Checking required query params", queryParams);
            if(queryParams.app && queryParams.action && queryParams.device && queryParams.platform && queryParams.user) {
                return true;
            }
            return false;
        },
        checkRequiredSelection() {
            console.log("Session(checkRequiredSelection): Checking required selection");
            if(this.getSelection.app.id && this.getSelection.device.id && this.getSelection.platform && (this.getSelection.platform.toLowerCase() === "android" && this.getSelection.user.id || true)) {
                return true;
            }
            return false;
        },
        updateSelectionFromServer(queryParams: any) {
            console.log("Session(updateSelectionFromServer): Updating selection from server");
            const t_app = queryParams.app;
            const t_device = queryParams.device;
            const t_action = queryParams.action;
            const t_platform = queryParams.platform;
            const t_user = queryParams.user;
            const t_library = queryParams.library || "";
            console.log("Session(updateSelectionUsingQueryParams): Data ", this.getData);
            
            const t_device_obj = this.getData.devices.filter((device: any) => device.id === t_device)[0];
            if(!t_device_obj) {
                console.log("Session(updateSelectionUsingQueryParams): Device not found in data", t_device);
                return false;
            } else {
                this.setDefaultDevice();
            }
            console.log("Session(updateSelectionUsingQueryParams): Device object", t_device_obj);
            
            this.setSelectionKey("device", t_device_obj);
            this.setSelectionKey("platform", t_platform);
            this.setSelectionKey("action", t_action);
            let t_user_obj = {};
            let t_apps_obj = [];
            let t_app_obj = {};
            let t_users_obj = [];
            if(t_platform.toLowerCase() === "android") {
                t_user_obj = t_device_obj.users.filter((user: any) => user.id === t_user)[0];
                t_apps_obj = t_device_obj.users.filter((user: any) => user.id === t_user)[0].apps;
                t_app_obj = t_apps_obj.filter((app: any) => app.id === t_app)[0];
                t_users_obj = t_device_obj.users;
                this.setSelectionKey("user", t_user_obj);
                this.setSelectionKey("apps", t_apps_obj);
                this.setSelectionKey("app", t_app_obj);
                this.setDataKey("users", t_users_obj);
                // console.log("Session(updateSelectionUsingQueryParams): Updating user using query params", t_user_obj);
            } else {
                t_apps_obj = t_device_obj.users[0];
                t_app_obj = t_apps_obj.filter((app: any) => app.id === t_app)[0];
                // console.log("Session(updateSelectionUsingQueryParams): Updating user using query params", t_apps_obj);
                this.setSelectionKey("user", t_user_obj);
                this.setSelectionKey("apps", t_apps_obj);
                this.setSelectionKey("app", t_app_obj);
                this.setDataKey("users", []);   
            }

            if(t_library) {
                // console.log("Session(updateSelectionUsingQueryParams): Updating library using query params", t_library);
                const t_library_obj = this.getData.libraries.filter((library: any) => library.file === t_library)[0];
                this.setSelectionKey("library", t_library_obj);
            }
            return true;
        },
        updateSelectionUsingQueryParams(queryParams: any) {
            // console.log("Session(updateSelectionUsingQueryParams): Updating selection using query params", queryParams);
            if (!this.getSelection.device) {
                console.log("Session(updateSelectionUsingQueryParams): No device selected, cannot update selection using query params");
                return false;
            }
            const t_app = queryParams.app;
            const t_device = queryParams.device;
            const t_action = queryParams.action;
            const t_platform = queryParams.platform;
            const t_user = queryParams.user;
            const t_library = queryParams.library || "";
            console.log("Session(updateSelectionUsingQueryParams): Data ", this.getData);
            
            // console.log("Session(updateSelectionUsingQueryParams): Updating selection using query params", t_app, t_device, t_action, t_platform, t_user, t_library);
            const t_device_obj = this.getData.devices.filter((device: any) => device.id === t_device)[0];
            if(!t_device_obj) {
                console.log("Session(updateSelectionUsingQueryParams): Device not found in data", t_device);
                return false;
            } else {
                this.setDefaultDevice();
            }
            console.log("Session(updateSelectionUsingQueryParams): Device object", t_device_obj);
            
            this.setSelectionKey("device", t_device_obj);
            this.setSelectionKey("platform", t_platform);
            this.setSelectionKey("action", t_action);
            let t_user_obj = {};
            let t_apps_obj = [];
            let t_app_obj = {};
            let t_users_obj = [];
            if(t_platform.toLowerCase() === "android") {
                t_user_obj = t_device_obj.users.filter((user: any) => user.id === t_user)[0];
                t_apps_obj = t_device_obj.users.filter((user: any) => user.id === t_user)[0].apps;
                t_app_obj = t_apps_obj.filter((app: any) => app.id === t_app)[0];
                t_users_obj = t_device_obj.users;
                this.setSelectionKey("user", t_user_obj);
                this.setSelectionKey("apps", t_apps_obj);
                this.setSelectionKey("app", t_app_obj);
                this.setDataKey("users", t_users_obj);
                // console.log("Session(updateSelectionUsingQueryParams): Updating user using query params", t_user_obj);
            } else {
                t_apps_obj = t_device_obj.users[0];
                t_app_obj = t_apps_obj.filter((app: any) => app.id === t_app)[0];
                // console.log("Session(updateSelectionUsingQueryParams): Updating user using query params", t_apps_obj);
                this.setSelectionKey("user", t_user_obj);
                this.setSelectionKey("apps", t_apps_obj);
                this.setSelectionKey("app", t_app_obj);
                this.setDataKey("users", []);   
            }

            if(t_library) {
                // console.log("Session(updateSelectionUsingQueryParams): Updating library using query params", t_library);
                const t_library_obj = this.getData.libraries.filter((library: any) => library.file === t_library)[0];
                this.setSelectionKey("library", t_library_obj);
            }
            return true;
        },
        resetSelectedApp() {
            this.setSelectionKey("sessionId", "");
            this.setStatusKey("appStatus", false);
            this.syncConnectedApp();
        },
        setDefaultDevice() {
            console.log("Session(setDefaultDevice): Setting default device");
            
            if (this.getData.devices.length === 0) {
                console.log("Session(setDefaultDevice): No devices found, cannot set default device");
                return;
            }
            const t_device = this.getData.devices[0];
            this.setSelectionKey("device", t_device);
            this.setSelectionKey("platform", t_device.platform);
            let t_apps = [];
            if(t_device.platform.toLowerCase() === "android") {
                t_apps = t_device.users.filter((user: any) => user.id == "0")[0].apps;
                this.setDataKey("users", t_device.users);
                this.setSelectionKey("user", t_device.users.filter((user: any) => user.id == "0")[0]);
            } else {
                t_apps = t_device.users[0];
                this.setDataKey("users", []);
                this.setSelectionKey("user", {});
            }
            this.setSelectionKey("apps", t_apps);
        },
        setSelectedAppFromConnectedApp() {
            console.log("Session(setSelectedAppFromConnectedApp): Setting selected app from connected app");
            this.setSelectionKey("app", this.getConnectedApp.app);
        },

        // Timer actions
        startAppConnectionTimer() {
            console.log("Session(startAppConnectionTimer): Starting app connection timer");
            this.setStatusKey("appConnectionTime", 0);
            const interval = setInterval(() => {
                if (this.getStatus.appConnectionTime) {
                    this.setStatusKey("appConnectionTime", this.getStatus.appConnectionTime + 1);
                } else {
                    clearInterval(interval);
                }
            }
            , 1000);
            return interval;
        },
        stopAppConnectionTimer(interval: any) {
            console.log("Session(stopAppConnectionTimer): Stopping app connection timer");
            clearInterval(interval);
            this.setStatusKey("appConnectionTime", 0);
        }
    }
});
export const useWebSocketStore = defineStore('websocket', () => {
    const ws = ref(null);
    const data = ref(null);
    const isConnected = ref(false);
    const messageCallback = ref(null);
    const openCallback = ref(null);
    const onOpenHandlers = ref<(() => void)[]>([]);
    const onMessageHandlers = ref<((message: any) => void)[]>([]);
    const shouldReconnect = ref(true);
    const retryDelay = ref(1000);
    const maxRetryDelay = 30000;

    const connect = (url: string) => {
        if (!ws.value || ws.value.readyState === WebSocket.CLOSED) {
            ws.value = new WebSocket(url);

            ws.value.onopen = () => {
                isConnected.value = true;
                retryDelay.value = 1000;
                console.log('Sessions: WebSocket connected');
                onOpenHandlers.value.forEach(handler => handler());
            };

            ws.value.onmessage = (event: any) => {
                onMessageHandlers.value.forEach(handler => handler(event.data));
            };

            ws.value.onclose = () => {
                isConnected.value = false;
                console.log('Session: WebSocket disconnected');
                scheduleReconnect(url);
            };

            ws.value.onerror = (error: any) => {
                console.error('Session: WebSocket error:', error);
                isConnected.value = false;
                scheduleReconnect(url);
            };
        }
    };

    const disconnect = () => {
        if (ws.value && ws.value.readyState === WebSocket.OPEN) {
            ws.value.close();
        }
        shouldReconnect.value = false;
        isConnected.value = false;
        ws.value = null;
    };

    const send = (message: any) => {
        if (ws.value && ws.value.readyState === WebSocket.OPEN) {
            ws.value.send(typeof message === 'string' ? message : JSON.stringify(message));
        } else {
            console.warn('WebSocket is not connected. Cannot send message.');
        }
    };

    const setMessageCallback = (callback: any) => {
        messageCallback.value = callback;
    };

    const setOpenCallback = (callback: any) => {
        // console.log('Session: Setting open callback');
        openCallback.value = callback;
    };

    const addOnOpenHandler = (callback: () => void) => {
        onOpenHandlers.value.push(callback);
        // console.log('Session: Added onOpen handler onOpen handlers:', onOpenHandlers.value.length);
    };

    const addOnMessageHandler = (callback: (message: any) => void) => {
        onMessageHandlers.value.push(callback);
        // console.log('Session: Added onMessage handler onMessage handlers:', onMessageHandlers.value.length);
    };

    const scheduleReconnect = (url: string) => {
        if (!shouldReconnect.value) return;
    
        // console.log(`Session: Attempting to reconnect in ${retryDelay.value / 1000}s...`);
        setTimeout(() => {
            if (!isConnected.value && shouldReconnect.value) {
                connect(url);
                retryDelay.value = Math.min(retryDelay.value * 2, maxRetryDelay); // exponential backoff
            }
        }, retryDelay.value);
    };
    

    onUnmounted(() => {
        disconnect();
    });

    const removeMessageCallback = (callback: any) => {
        // console.log('Session: Removing onMessage handler');
        const index = onMessageHandlers.value.indexOf(callback);
        if (index > -1) {
            onMessageHandlers.value.splice(index, 1);
            // console.log('Session: Removed onMessage handler');
        }
        // console.log('Session: onMessage handlers:', onMessageHandlers.value.length);
    };

    const removeOpenCallback = (callback: any) => {
        // console.log('Session: Removing onOpen handler');
        const index = onOpenHandlers.value.indexOf(callback);
        if (index > -1) {
            onOpenHandlers.value.splice(index, 1);
            // console.log('Session: Removed onOpen handler');
        }
        // console.log('Session: onOpen handlers:', onOpenHandlers.value.length);
    };

    return { ws, data, isConnected, connect, disconnect, send, setMessageCallback, setOpenCallback, addOnOpenHandler, addOnMessageHandler, removeMessageCallback, removeOpenCallback };
});


// // ────────────────────────────────────────────────────────────────
// // Dev helper: log every mutation and action of the session store
// // ────────────────────────────────────────────────────────────────
// if (import.meta.env.DEV) {
//   // Delay to make sure Pinia is fully initialised
//   setTimeout(() => {
//     const store = useAppStore();

//     // 1️⃣  log every state change
//     store.$subscribe((mutation) => {
//       const events = mutation.events
//         ? (Array.isArray(mutation.events) ? mutation.events : [mutation.events])
//         : [];

//       events.forEach((e: any) =>
//         console.log(
//           `[SessionStore] %c${e.key}`,
//           'color:#03A9F4',
//           e.oldValue,
//           '→',
//           e.newValue,
//         )
//       );
//     });

//     // 2️⃣  log every action call / result
//     store.$onAction(({ name, args, after, onError }) => {
//       console.log(`[SessionStore] Action «${name}» called with`, args);
//       after((result) =>
//         console.log(`[SessionStore] Action «${name}» resolved`, (result ? result : "No result")),
//       );
//       onError((err) =>
//         console.error(`[SessionStore] Action «${name}» errored`, err),
//       );
//     });
//   }, 0);
// }
