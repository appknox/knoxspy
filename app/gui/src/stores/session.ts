import { defineStore } from "pinia"

export const useSessionStore = defineStore('session', {
    state: () => ({
        app: {
            isConnected: false,
            name: '',
            identifier: '',
            platform: '',
            library: null,
            deviceId: null,
            status: '',
            sessionId: -1,
            restart: false
        },
        session: {
            name: '',
            id: -1
        },
        startupAppConfig: {
            isConnected: false,
            name: '',
            identifier: '',
            platform: '',
            library: null,
            deviceId: null,
            status: '',
            sessionId: -1,
            restart: false
        },
        error: null
    }),
    getters: {
        getSession(): Object {
            return this.session;
        }
    },
    actions: {
        setSession(session: Object) {
            this.session = session
        },
        restartApp(sessionId: number) {
            this.app.sessionId = sessionId
            this.app.restart = true
        }
    },
});