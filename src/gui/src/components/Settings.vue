<template>
	<div class="page page-library-manager">
        <h1>Settings</h1>
        <Panel header="Startup" style="max-width: 1000px; margin: 0 auto;" toggleable>
            <p class="m-0">
                
            </p>
            <div style="display: flex; flex-direction: column;" class="settings_table">
                <div style="display: flex; align-items: center; gap: 10px" class="settings_table_row">
                    <p>Restore Last Session</p>
                    <SelectButton v-model="restoreLastSession" :allow-empty="false" @change="changeLastSession($event, 'lastSession')" :options="restoreLastSessionOptions" aria-labelledby="basic" />
                </div>
                <div style="display: flex; align-items: center; gap: 10px" class="settings_table_row">
                    <p>Select Last Used Device</p>
                    <SelectButton :disabled="!postSessionActions" :allow-empty="false" v-model="restoreLastDevice" @change="changeLastSession($event, 'lastDevice')" :options="restoreLastSessionOptions" aria-labelledby="basic" />
                </div>
                <div style="display: flex; align-items: center; gap: 10px" class="settings_table_row">
                    <p>Launch Last Opened App</p>
                    <SelectButton :disabled="!postSessionActions" :allow-empty="false" v-model="restoreLastApp" @change="changeLastSession($event, 'lastApp')" :options="restoreLastSessionOptions" aria-labelledby="basic" />
                </div>
                <div style="display: flex; align-items: center; gap: 10px" class="settings_table_row">
                    <p>Attach Last Used Library</p>
                    <SelectButton :disabled="!postSessionActions" :allow-empty="false" v-model="restoreLastLibrary" @change="changeLastSession($event, 'lastLibrary')" :options="restoreLastSessionOptions" aria-labelledby="basic" />
                </div>
            </div>
        </Panel>

	</div>
</template>

<script lang="ts">
import { defineComponent } from "vue";
import {useSessionStore} from '../stores/session';
import Panel from "primevue/panel";
import SelectButton from "primevue/selectbutton";

export default defineComponent({
	name: 'LibraryManager',
    components: {
        Panel,
        SelectButton
    },
    data() {
        return {
            restoreLastDevice: "Yes",
            restoreLastSession: "Yes",
            restoreLastApp: "Yes",
            restoreLastLibrary: "Yes",
            postSessionActions: true,
            restoreLastSessionOptions: ["Yes", "No"],
            sess: null,
            ws: null
        }
    },
    created() {
        this.sess = useSessionStore()

        const url = 'ws://' + import.meta.env.VITE_SERVER_IP + ':8000';
        this.ws = new WebSocket(url);

        this.ws.onopen = () => {
            console.log('Connected to WebSocket server');
            // const json = {"action":"active"}
            // this.ws.send(JSON.stringify(json))
        };

        this.ws.onmessage = (event: { data: string; }) => {
            const message = JSON.parse(event.data);
            if(message['action'] === 'lastSessionConfigUpdate') {
                if(!message['status']) {
                    alert(message['message'])
                } 
            } else if(message['action'] === 'trafficInit') {
                const sessionConfig = JSON.parse(message['session']['config']);
                console.log(sessionConfig);
                this.restoreLastSession = sessionConfig.session;
                this.restoreLastDevice = sessionConfig.device;
                this.restoreLastApp = sessionConfig.app;
                this.restoreLastLibrary = sessionConfig.library;
                if(sessionConfig.session === "No") {
                    this.postSessionActions = false;
                }
            }
        };

        this.ws.onerror = (error: any) => {
            console.error('WebSocket error:', error);
        };

        this.ws.onclose = () => {
            console.log('WebSocket connection closed');
            this.sess.$patch({app: {isConnected: false}})
        };
    },
    methods: {
        changeLastSession(event: any, key: string) {
            const value = event.value;
            console.log("Switching:", key, "to", value);
            if(key === "lastSession") {
                if(value === "Yes") {
                    this.postSessionActions = true;
                } else {
                    this.postSessionActions = false;
                    this.restoreLastApp = "No";
                    this.restoreLastLibrary = "No";
                    this.restoreLastDevice = "No";
                }
            }
            this.ws.send(JSON.stringify({
                "action": "lastSessionConfig",
                "session": {
                    "session": this.restoreLastSession,
                    "device": this.restoreLastDevice,
                    "app": this.restoreLastApp,
                    "library": this.restoreLastLibrary,
                    "sessionStoreApp": this.sess.app,
                    "sessionStoreSession": this.sess.session
                }
            })) 
        }
    },
});
</script>

<style>
.settings_table {

}
.settings_table_row {

}
.settings_table_row > * {
    flex-grow: 1;
    flex-basis: 0;
    text-align: left;
    /* outline: 1px solid #aaa; */
}
.page {
    overflow: hidden;
    /* flex-grow: 1; */
	height: 100%;
	background-color: #222831;
    background-color: #fff;
}
.page-library-manager {
    padding: 30px;
}
.page h1 {
    margin: 0;
    padding: 0;
    height: 100px;
    font: 35px "Fira Code";
    font-variant: small-caps;
}
.page h5 {
    margin: 0 0 10px;
    padding: 10px 0;
    font-size: 20px;
    font-weight: 400;
    border-radius: 10px;
    background-color: #eee;
}
.p-stepper {
    flex-basis: 50rem;
}
</style>
