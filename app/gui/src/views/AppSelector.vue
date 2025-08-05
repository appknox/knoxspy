<template>
    <div class="page">
        <div id="app-wrapper">
            <Card style="width: 25rem; overflow: hidden">
                <template #content v-if="!isConnecting && currentSession.app.connectedApp">
                    <img :src="currentSession.app.connectedApp.app ? (currentSession.app.connectedApp.app.icon || defaultPng) : defaultPng" style="width: 150px; height: 150px;">
                    <p class="m-0" style="font-size: 20px; margin-bottom: 5px;"><b>{{ currentSession.app.connectedApp.app ? currentSession.app.connectedApp.app.name : "" }}</b></p>
                    <p class="m-0 p-0" style="margin: 0;">{{ currentSession.app.connectedApp.app ? currentSession.app.connectedApp.app.id : "" }}</p>
                    <div style="background-color: #efefef; padding: 3px; border-radius: 10px; margin-top: 40px;">
                        <p class="m-0"><b style="margin-right: 10px;">Library</b>
                            <Dropdown placeholder="Select a Library" v-model="selectedLibrary" :options="libraryList" optionLabel="name" class="w-full md:w-14rem" @change="setLibrary"/>
                        </p>
                    </div>
                </template>
                <template #content v-if="isConnecting || !currentSession.app.selectedApp">
                    <div class="flex flex-column align-items-center">
                        <Skeleton shape="circle" size="150px" style="margin: 0 auto;" class="mb-3" />
                        <Skeleton width="10rem" height="1.25rem" class="mb-2" style="margin: 25px auto 10px;" />
                        <Skeleton width="8rem" height="1rem" class="mb-4" style="margin: 5px auto 10px;" />
                        <div style="background-color: #efefef; padding: 10px; border-radius: 10px; width: 100%; margin-top: 20px;">
                            <Skeleton height="2.5rem" width="100%" />
                        </div>
                        <div style="display: flex; flex-direction: row; justify-content: center; gap: 10px; width: 100%; margin-top: 20px; border-top: 1px solid #eee; padding-top: 20px;">
                            <Skeleton height="2.5rem" width="5rem" />
                            <Skeleton height="2.5rem" width="5rem" />
                        </div>
                    </div>
                </template>
                <template #footer v-if="!isSpawned && isLoaded && currentSession.app.selectedApp">
                    <div class="flex gap-4 mt-1" style="border-top: 1px solid #eee; padding-top: 20px;">
                        <Button @click="actionHandler({ value: 'spawn' })" label="Spawn" severity="primary" class="w-full" style="margin-right: 10px;"/>
                        <Button @click="actionHandler({ value: 'attach' })" label="Attach" class="w-full" outlined />
                    </div>
                </template>
                <template #footer v-if="isSpawned && currentSession.app.selectedApp">
                    <div class="flex gap-4 mt-1" style="border-top: 1px solid #eee; padding-top: 20px;">
                        <Button @click="showTraffic" label="Switch to Traffic" outlined severity="info" :disabled="!selectedLibrary" style="margin-right: 0px;"/>
                        <Button @click="actionHandler({ value: 'disconnect' })" label="Disconnect" severity="danger" class="w-full" style="margin-left: 10px;"/>
                    </div>
                </template>
                <template #footer v-if="isLoaded && isConnecting">
                    <p v-if="action === 'spawn'">Spawning...</p>
                    <p v-if="action === 'attach'">Attaching...</p>
                </template>
            </Card>
        </div>
    </div>
    <Footer @appConnected="showConnectedApp(true)" @libraryUpdated="updateLibraryInfo" @appDisconnected="showConnectedApp(false)" @dashboardUpdated="dashboardUpdated"></Footer>
</template>

<script lang="ts">
import { defineComponent } from "vue";
import Dropdown from "primevue/dropdown";
import Button from "primevue/button";
import Card from 'primevue/card';
import { useAppStore, useWebSocketStore } from "../stores/session";
import Footer from '../components/Footer.vue';
import Skeleton from 'primevue/skeleton';
import defaultPng from "../../public/default.png";


export default defineComponent({
    name: "AppSelector",
    components: { Dropdown, Button, Card, Footer, Skeleton },
    data() {
        return {
            defaultPng: defaultPng,
            action: "",
            isLoaded: false,
            isSpawned: false,
            selectedLibrary: null,
            selectedLibraryB64: "",
            isConnecting: false,
            connectionSessionId: -1,
            libraryList: [],
            currentSession: useAppStore(),
            ws: useWebSocketStore(),
            package_name: this.$route.query.app || "",
            action_name: this.$route.query.action || "",
            needToConnectApp: false,
        };
    },
    created() {
        console.log("AppSelector(created): Page created");
        this.ws.addOnOpenHandler(this.wsReady);
        this.ws.addOnMessageHandler(this.wsMessage);
    },
    async mounted() {
        if(!this.currentSession.app.selectedSession) {
            this.$router.push('/');
        }
        console.log("AppSelector(mounted): Page mounted");
        console.log("AppSelector(mounted): is websocket connected?", this.ws.isConnected);
        console.log("AppSelector(mounted): is dashboard ready?", this.currentSession.app.isDashboardReady);

        if(this.ws.isConnected && this.currentSession.app.isDashboardReady) {
            this.appCheck();
        }
    },
    methods: {
        async dashboardUpdated(isDashboardReady: boolean) {
            console.log("AppSelector(dashboardUpdated): Dashboard ready", isDashboardReady);
            if(isDashboardReady) {
                this.appCheck();
            } else {

            }
        },
        async appCheck() {
            await this.checkAppConnected();
            if(this.ws.isConnected) {
                console.log("AppSelector(mounted): Page switch");
                await this.currentSession.getConnectedApp();
                await this.pageSetup();
            } else {
                console.log("AppSelector(mounted): Page just loaded");
            }
        },
        async wsReady() {
            console.log("AppSelector(wsReady): WebSocket ready");
            await this.currentSession.getConnectedApp();
            console.log("AppSelector(wsReady): Connected app:", this.currentSession.app.connectedApp.app);
        },
        async checkAppConnected() {
            await this.currentSession.getConnectedApp();
            if(this.currentSession.app.connectedApp && this.currentSession.app.connectedApp.status) {
                console.log("AppSelector(checkAppConnected): App is connected");
                this.needToConnectApp = false;
                // if(this.currentSession.app.connectedApp.app.identifier === this.currentSession.app.selectedApp.id) {
                //     console.log("AppSelector(checkAppConnected): App is connected");
                //     this.needToConnectApp = false;
                // } else {
                //     console.log("AppSelector(checkAppConnected): App is connected but not the same");
                //     this.needToConnectApp = true;
                // }
            } else {
                console.log("AppSelector(checkAppConnected): App is not connected");
                this.needToConnectApp = true;
            }
        },
        async pageSetup() {
            if(this.currentSession.app.connectedApp && this.currentSession.app.connectedApp.status) {
                if(this.currentSession.app.connectedApp.app) { // && this.currentSession.app.connectedApp.app.identifier === this.currentSession.app.selectedApp.id) {
                    console.log("AppSelector(pageSetup): App is connected");
                    this.isLoaded = true;
                    this.isSpawned = true;
                    this.selectedLibrary = this.currentSession.app.selectedLibrary;
                    if(this.$route.query.app && this.$route.query.app != this.currentSession.app.connectedApp.app.identifier) {
                        this.$toast.add({
                            severity: "error",
                            summary: "App Selector",
                            detail: "An app is already connected. Please disconnect it first.",
                            life: 3000
                        });
                    }
                    console.log("AppSelector(pageSetup): Selected app set", this.currentSession.app.connectedApp.app)
                    if(this.currentSession.app.connectedApp.app.platform.toLowerCase() === "android") {
                        this.currentSession.setSelectedUser(this.currentSession.app.connectedApp.app.user);
                        if(this.currentSession.app.connectedApp.app.user >= "10") {
                            this.currentSession.setSelectedApp(this.currentSession.app.connectedApp.app.identifier, false, true)
                        } else {
                            this.currentSession.setSelectedApp(this.currentSession.app.connectedApp.app.identifier, false, false)
                        }
                    } else {
                        this.currentSession.setSelectedApp(this.currentSession.app.connectedApp.app)
                    }
                } else {
                    console.log("AppSelector(pageSetup): App is connected but not the same");
                    this.setupPageUsingQueryParams()
                }
                this.ws.send(JSON.stringify({ action: "libraries"}));
            } else if(this.$route.query.app && this.$route.query.action && this.$route.query.device && this.$route.query.app) {
                console.log("AppSelector(pageSetup): Query params are present");
                this.ws.send(JSON.stringify({ action: "libraries"}));
                this.setupPageUsingQueryParams();
            } else {
                console.log("AppSelector(pageSetup): No app connected and no query params");
                this.$router.push("/apps");
            }
        },
        async wsMessage(message: any) {
            message = JSON.parse(message);
            if(message.action === "deviceUpdate") {
                console.log("AppSelector(wsMessage): Message:", message, message.action);
                if(message.message === "Connected") {
                    await this.currentSession.getConnectedApp();
                    this.isSpawned = true;
                    this.isLoaded = true;
                    this.isConnecting = false;
                    let t_user = this.$route.query.user || '0';
                    let t_user_flag = t_user === '0' ? false : true;
                    if(this.currentSession.app.selectedDevice.platform.toLowerCase() !== "android") {
                        t_user_flag = false;
                    }
                    console.log("AppSelector(wsMessage): Device update received");
                    console.log("AppSelector(wsMessage): Connected app:", this.currentSession.app.connectedApp, "Selected app:", this.currentSession.app.selectedApp);
                    this.currentSession.setSelectedApp(this.currentSession.app.connectedApp.app.identifier, false, t_user_flag);
                }
            } else if(message.action === "libraries") {
                console.log("AppSelector(wsMessage): Message:", message, message.action);
                this.libraryList = message.libraries;
            } else if(message.action === "appDisconnected") {
                console.log("AppSelector(wsMessage): Message:", message, message.action);
                this.isSpawned = false;
                this.isLoaded = false;
                this.isConnecting = false;
                this.currentSession.app.connectedApp = null;
                this.$router.push("/apps");
            }
        },
        async setupPageUsingQueryParams() {
            console.log("AppSelector(setupPageUsingQueryParams): Setting page using query params");
            let queryParams = {
                app: this.$route.query.app as string,
                device: this.$route.query.device as string,
                action: this.$route.query.action as string,
                user: this.$route.query.user as string,
                platform: this.$route.query.platform as string,
                library: ""
            }
            console.log("AppSelector(setupPageUsingQueryParams): Query params:", queryParams);
            const t_platform = this.$route.query.platform as string;
            const t_user = this.$route.query.user as string;
            if(t_platform.toLowerCase() === "android") {
                console.log("AppSelector(setupPageUsingQueryParams): Setting user", t_user);
                this.currentSession.setSelectedUser(t_user);
            }
            this.currentSession.setSelectedApp(queryParams.app);
            this.currentSession.setSelectedDevice(queryParams.device, true);
            if(this.$route.query.library) {
                this.currentSession.setSelectedLibrary(this.$route.query.library as string);
                queryParams.library = this.$route.query.library as string;
            } else {
                delete queryParams.library;
            }

            console.log("AppSelector(setupPageUsingQueryParams):\nSelected App: ", this.currentSession.app.selectedApp, "\nSelected Device: ", this.currentSession.app.selectedDevice, "\nSelected Library: ", this.currentSession.app.selectedLibrary);
            
            this.startApp(queryParams.app, queryParams.action + "App", queryParams.device);
        },
        showConnectedApp(isConnected: boolean) {
            console.log("AppSelector(showConnectedApp): Connected app", isConnected);
            if(!isConnected) {
                this.isSpawned = false;
                this.isLoaded = true;
                this.isConnecting = false;
                this.action = "";
            } else {
                this.isSpawned = true;
                this.isLoaded = true;
                this.isConnecting = false;
                this.action = "connected";
            }
        },
        actionHandler(event: any) {
            console.log("AppSelector(actionHandler): Action handler", event);
            if(event.value === 'spawn' || event.value === 'attach') {
                const t_app = (this.currentSession.app.selectedApp ? this.currentSession.app.selectedApp.id : (this.$route.query.app ? this.$route.query.app : ""));
                if(t_app) {
                    this.startApp(t_app, event.value + "App");
                } else {
                    console.log("AppSelector(actionHandler): No app selected");
                }
            } else if(event.value === "disconnect") {
                this.ws.send(JSON.stringify({
                    "action": "disconnectApp"
                }))
            }
        },
        startApp(packageName: string, action: string, device: string = "") {
            console.log("AppSelector(startApp): Starting app", packageName, action);
            this.isConnecting = true;
            let t_device = this.currentSession.app.selectedDevice.id;
            if(device) {
                t_device = device;
            }   
            if(this.currentSession.app.selectedLibrary && !this.selectedLibrary) {
                this.selectedLibrary = this.currentSession.app.selectedLibrary;
            }
            this.ws.send(JSON.stringify({
                "action": action,
                "deviceId": t_device,
                "appId": packageName,
                "user": this.$route.query.user && this.currentSession.app.selectedDevice.platform.toLowerCase() === "android" ? this.$route.query.user : 0,
                "platform": this.currentSession.app.selectedDevice ? this.currentSession.app.selectedDevice.platform : "NA",
                "appName": this.currentSession.app.selectedApp ? this.currentSession.app.selectedApp.name : packageName,
                "library": this.currentSession.app.selectedLibrary ? this.currentSession.app.selectedLibrary.file : null
            }))
        },
        setLibrary($event: any) {
            this.currentSession.setSelectedLibrary($event.value.file)
            this.ws.send(JSON.stringify({
                "action": "changeLibrary",
                "library": $event.value
            }))
            this.updateURL($event.value.file, "library")
        },
        showTraffic() {
            this.$router.push({ path: "/traffic", query: this.$route.query })
        },
        updateLibraryInfo(library: any) {
            console.log("AppSelector(updateLibraryInfo): Library updated", library);
            if(!library) {
                return;
            }
            this.selectedLibrary = library
            this.updateURL(library.file, "library")
        },
        updateURL(value: any, key: string) {
            this.$router.push({path: "/app", query: {
                ...this.$route.query,
                [key]: value
            }})
        },
    },
	unmounted() {
		console.log("Unmounting AppSelector");
		this.ws.removeMessageCallback(this.wsMessage);
		this.ws.removeOpenCallback(this.wsReady);
	},
});
</script>

<style scoped>
.page {
    flex-direction: column;
    padding: 2em;
    background: #eee;
    min-height: 100vh;
    font-family: 'Inter', sans-serif;
    background: linear-gradient(to bottom right, #f7fafc, #edf2f7); /* bg-gradient-to-br from-gray-50 to-gray-100 */
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: 1rem; /* p-4 */
}
</style>
