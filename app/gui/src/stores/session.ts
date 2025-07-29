import { defineStore } from "pinia"
import { ref } from "vue";
import { onUnmounted } from "vue";

function getSession() {
    return JSON.parse(localStorage.getItem('selectedSession') || '{}')
}

export const useAppStore = defineStore('current_session', {

    state: () => ({
        app: {
            isConnected: false,
            appConnectionPhase: "disconnected",
            isDashboardReady: false,
            dashboardLoadedItems: {
                sessions: false,
                devices: false,
                apps: false,
                libraries: false,
            },
            isSessionActive: false,
            isDeviceReady: false,
            wsConnected: false,
            selectedApp: null,
            selectedDevice: null,
            selectedLibrary: null,
            selectedSession: getSession(),
            sessionsList: [],
            devices: [],
            apps: [],
            connectedApp: null,
            libraries: [
                { name: "AFNetworking", file: "afnetworking.js", platform: "iOS" },
                { name: "TrustKit", file: "trustkit.js", platform: "iOS" },
                { name: "AlamoFire", file: "alamofire.js", platform: "iOS" },
                { name: "OkHTTP", file: "okhttp.js", platform: "android" }
            ],
            currentSessionId: -1
        }
    }),
    getters: {
        getSelectedSession(): Object {
            return this.app.selectedSession;
        },
        getSelectedApp(): Object {
            return this.app.selectedApp;
        },
        getLibraries(): Object {
            return this.app.libraries;
        },
        getSelectedLibrary(base64: boolean = false): Object {
            if(base64) {
                return btoa(this.app.selectedLibrary.file);
            } else {
                return this.app.selectedLibrary;
            }
        },
        getDashboardPhase(item: keyof typeof this.app.dashboardLoadedItems): boolean {
            return this.app.dashboardLoadedItems[item];
        },
        getAppConnectionPhase(): string {
            return this.app.appConnectionPhase;
        }
    },
    actions: {
        setDashboardPhase(item: keyof typeof this.app.dashboardLoadedItems, value: boolean) {
            this.app.dashboardLoadedItems[item] = value
            if(Object.values(this.app.dashboardLoadedItems).every((v: boolean) => v)) {
                this.app.isDashboardReady = true
            }
        },
        setAppConnectionPhase(phase: string) {
            this.app.appConnectionPhase = phase
        },
        getLibraryObject(name: string): Object {
            return this.app.libraries.find((l: any) => l.file === name);
        },
        async getConnectedApp(): Promise<Object> {
            console.log("Checking active session", import.meta.env.VITE_SERVER_IP);
            const response = await fetch('http://' + import.meta.env.VITE_SERVER_IP + ':8000/api/connected');
            const data = await response.json();
            this.app.connectedApp = data
            return data
        },
        setSelectedSession(session: any) {
            this.app.selectedSession = session
            localStorage.setItem('selectedSession', JSON.stringify(session))
            if(session.id != -1) {
                this.app.isSessionActive = true
            } else {
                this.app.isSessionActive = false
            }
        },
        clearSelectedSession() {
            this.app.selectedSession = null
            localStorage.removeItem('selectedSession')
            console.log('Selected session cleared')
        },
        setDevices(devices: any) {
            this.app.devices = devices
        },
        setSelectedDevice(device: any, id: boolean = false) {
            if(id) {
                this.app.selectedDevice = this.app.devices.find((d: any) => d.id === device)
                console.log(this.app.selectedDevice)
            } else {
                this.app.selectedDevice = device
            }
        },
        setLibraries(libraries: any) {
            this.app.libraries = libraries
        },
        setApps(apps: any) {
            this.app.apps = apps
        },
        setSelectedApp(app: any, custom: boolean = false) {
            console.log("App selected:", app, custom)
            if(custom) {
                this.app.selectedApp = app
            } else {
                this.app.selectedApp = this.app.apps.find((a: any) => a.id === app)
            }
            console.log(this.app.selectedApp)
        },
        setSelectedLibrary(library: any) {
            console.log("changing library",  library, this.app.libraries.find((l: any) => l.file === library))
            this.app.selectedLibrary = this.app.libraries.find((l: any) => l.file === library)
        },
        // dump() {
        //     this.storeSelectedApp()
        // },
        storeSelectedApp() {
            if(this.app.selectedApp) {
                localStorage.setItem('selectedApp', JSON.stringify(this.app.selectedApp))
            }
        },
        setAppConnected(status: boolean) {
            this.app.isConnected = status
        },
        setSessionActive(status: boolean) {
            this.app.isSessionActive = status
        },
        setConnectedApp(app: any) {
            this.app.connectedApp = app
        },
        checkDeviceReady() {
            if(this.app.selectedDevice && this.app.selectedApp && this.app.apps.length > 0) {
                this.app.isDeviceReady = true
                console.log("[SessionStore] Device ready");
            } else {
                this.app.isDeviceReady = false
                console.log("[SessionStore] Device not ready");
            }
        },
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
        console.log('Session: Setting open callback');
        openCallback.value = callback;
    };

    const addOnOpenHandler = (callback: () => void) => {
        onOpenHandlers.value.push(callback);
        console.log('Session: Added onOpen handler onOpen handlers:', onOpenHandlers.value.length);
    };

    const addOnMessageHandler = (callback: (message: any) => void) => {
        onMessageHandlers.value.push(callback);
        console.log('Session: Added onMessage handler onMessage handlers:', onMessageHandlers.value.length);
    };

    const scheduleReconnect = (url: string) => {
        if (!shouldReconnect.value) return;
    
        console.log(`Session: Attempting to reconnect in ${retryDelay.value / 1000}s...`);
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
        console.log('Session: Removing onMessage handler');
        const index = onMessageHandlers.value.indexOf(callback);
        if (index > -1) {
            onMessageHandlers.value.splice(index, 1);
            console.log('Session: Removed onMessage handler');
        }
        console.log('Session: onMessage handlers:', onMessageHandlers.value.length);
    };

    const removeOpenCallback = (callback: any) => {
        console.log('Session: Removing onOpen handler');
        const index = onOpenHandlers.value.indexOf(callback);
        if (index > -1) {
            onOpenHandlers.value.splice(index, 1);
            console.log('Session: Removed onOpen handler');
        }
        console.log('Session: onOpen handlers:', onOpenHandlers.value.length);
    };

    return { ws, data, isConnected, connect, disconnect, send, setMessageCallback, setOpenCallback, addOnOpenHandler, addOnMessageHandler, removeMessageCallback, removeOpenCallback };
});
export const usePageReadyEmitter = defineStore("emitter", () => {
    const emitterDashboard = ref(null);
    const emitDashboard = (data: any) => {
        emitterDashboard.value = data;
    }

    const emitterAppManager = ref(null);
    const emitAppManager = (data: any) => {
        emitterAppManager.value = data;
    }

    const emitterHTTPTraffic = ref(null);
    const emitHTTPTraffic = (data: any) => {
        emitterHTTPTraffic.value = data;
    }

    const emitterSidebar = ref(null);
    const emitSidebar = (data: any) => {
        emitterSidebar.value = data;
    }
    return { emitterDashboard, emitDashboard, emitterAppManager, emitAppManager, emitterHTTPTraffic, emitHTTPTraffic, emitterSidebar, emitSidebar };
});

// ────────────────────────────────────────────────────────────────
// Dev helper: log every mutation and action of the session store
// ────────────────────────────────────────────────────────────────
if (import.meta.env.DEV) {
  // Delay to make sure Pinia is fully initialised
  setTimeout(() => {
    const store = useAppStore();

    // 1️⃣  log every state change
    store.$subscribe((mutation) => {
      const events = mutation.events
        ? (Array.isArray(mutation.events) ? mutation.events : [mutation.events])
        : [];

      events.forEach((e: any) =>
        console.log(
          `[SessionStore] %c${e.key}`,
          'color:#03A9F4',
          e.oldValue,
          '→',
          e.newValue,
        )
      );
    });

    // 2️⃣  log every action call / result
    store.$onAction(({ name, args, after, onError }) => {
      console.log(`[SessionStore] Action «${name}» called with`, args);
      after((result) =>
        console.log(`[SessionStore] Action «${name}» resolved`, (result ? result : "No result")),
      );
      onError((err) =>
        console.error(`[SessionStore] Action «${name}» errored`, err),
      );
    });
  }, 0);
}
