<template>
    <div class="page">
        <div id="app-wrapper">
            <div style="display: none;">
                <p>App Connection Status: {{  cs.getStatus.appConnectingStatus }}</p>
                <p>App Status: {{ (cs.getStatus.appStatus ? cs.getStatus.appStatus : false ) }}</p>
                <p>Selected App: {{ cs.getSelection.app }}</p>
                <p>First check: {{ cs.getSelection.app ||  (cs.getStatus.appStatus ? cs.getStatus.appStatus : false ) }}</p>
                <!-- 
                First check:
                - If app is not being connected to (cs.getStatus.appConnectingStatus is false)
                    - If app data is present on dashboard (cs.getSelection.app exists) (show spawn/attach buttons)
                    - If app is connected (cs.getStatus.appStatus is true) (show traffic/disconnect buttons)
                -->
            </div>
            <Card style="width: 25rem; overflow: hidden">
                <template #content v-if="!cs.getStatus.appConnectingStatus && (cs.getSelection.app || (cs.getStatus.appStatus ? cs.getStatus.appStatus : false ))">
                    <div>
                        <img :src="cs.getSelection.app.icon || defaultPng" style="width: 150px; height: 150px;">
                        <p class="m-0" style="font-size: 20px; margin-bottom: 5px;"><b>{{ cs.getSelection.app.name }}</b></p>
                        <p class="m-0 p-0" style="margin: 0;">{{ cs.getSelection.app.id }}</p>
                        <div style="background-color: #efefef; padding: 3px; border-radius: 10px; margin-top: 40px;">
                            <p class="m-0"><b style="margin-right: 10px;">Library</b>
                                <Dropdown placeholder="Select a Library" v-model="cs.getSelection.library" :options="cs.getData.libraries" optionLabel="name" class="w-full md:w-14rem" @change="setLibrary"/>
                            </p>
                        </div>
                    </div>
                    <div v-if="!cs.getStatus.appStatus" class="flex gap-4 mt-1" style="border-top: 1px solid #eee; padding-top: 20px; margin-top: 20px">
                        <Button @click="actionHandler({ value: 'spawn' })" label="Spawn" severity="primary" class="w-full" style="margin-right: 10px;"/>
                        <Button @click="actionHandler({ value: 'attach' })" label="Attach" class="w-full" outlined />
                    </div>
                    <div v-else class="flex gap-4 mt-1" style="border-top: 1px solid #eee; padding-top: 20px; margin-top: 20px">
                        <Button @click="showTraffic" label="Switch to Traffic" outlined severity="info" :disabled="!cs.getSelection.library" style="margin-right: 0px;"/>
                        <Button @click="actionHandler({ value: 'disconnect' })" label="Disconnect" severity="danger" class="w-full" style="margin-left: 10px;"/>
                    </div>
                </template>
                <template #content v-else>
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
            </Card>
        </div>
    </div>
    <Footer @dashboardReady="dashboardReady"></Footer>
</template>

<script lang="ts">
import { defineComponent } from "vue";
import Dropdown from "primevue/dropdown";
import Button from "primevue/button";
import Card from 'primevue/card';
import { useAppStore, useWebSocketStore } from "../stores/session";
import Footer from '../components/Footer.vue';
import Skeleton from 'primevue/skeleton';
import defaultPng from '../../public/default.png';

export default defineComponent({
    name: "AppSelector",
    components: { Dropdown, Button, Card, Footer, Skeleton },
    data() {
        return {
            defaultPng,
            cs: useAppStore(),
            ws: useWebSocketStore(),
            needToConnectApp: false,
        };
    },
    created() {
        this.ws.addOnMessageHandler(this.wsMessage);
    },
    async mounted() {
        const t_requiredQueryParams = this.cs.checkRequiredQueryParams(this.$route.query);
        console.log("AppSelector(mounted): Required query params:", t_requiredQueryParams);
        if(!t_requiredQueryParams) {
            this.$router.push("/apps");
        }
        if(this.ws.isConnected && this.cs.getStatus.dashboardStatus) {
            console.log("AppSelector(mounted): Page switch");
            if(this.cs.checkRequiredQueryParams(this.$route.query)) {
                this.cs.updateSelectionUsingQueryParams(this.$route.query);
            }
            this.checkAppConnected();
            console.log("AppSelector(mounted): Connected app:", this.cs.getConnectedApp);
        } else {
            console.log("AppSelector(mounted): Page just loaded", this.cs.getConnectedApp.status);
        }
    },
    methods: {
        dashboardReady(isDashboardReady: boolean) {
            console.log("AppSelector(dashboardReady): Dashboard ready", isDashboardReady);
            if(isDashboardReady) {
                this.checkAppConnected();
            }
        },
        checkAppConnected() {
            if(this.cs.getConnectedApp.status) {
                console.log("AppSelector(checkAppConnected): Connected app:", this.cs.getConnectedApp.app.id);
                console.log("AppSelector(checkAppConnected): Selected app:", this.cs.getSelection.app.id);
                if(this.cs.getConnectedApp.app.id === this.cs.getSelection.app.id) {
                    console.log("AppSelector(checkAppConnected): App is connected");
                    this.needToConnectApp = false;
                } else {
                    console.log("AppSelector(checkAppConnected): App is connected but not the same");
                    this.cs.setSelectionKey("library", {})
                    // remove library from query params
                    this.updateURL("", "library");
                    this.needToConnectApp = true;
                }
            } else {
                console.log("AppSelector(checkAppConnected): App is not connected");
                this.needToConnectApp = true;
            }
            console.log("AppSelector(checkAppConnected): Need to connect app:", this.needToConnectApp);
            this.checkAppStart(this.needToConnectApp);
        },
        checkAppStart(needToConnectApp: boolean) {
            if(needToConnectApp) {
                console.log("AppSelector(checkAppStart): Need to connect app");
                this.startApp()
            } else {
                console.log("AppSelector(checkAppStart): No need to connect app");
                this.cs.setStatusKey("appStatus", true);
            }
        },
        wsMessage(message: any) {
            message = JSON.parse(message);
            console.log("AppSelector(wsMessage): Message:", message, message.action);
        },
        showConnectedApp(isConnected: boolean) {
            console.log("AppSelector(showConnectedApp): Connected app", isConnected);
            
        },
        actionHandler(event: any) {
            console.log("AppSelector(actionHandler): Action handler", event);
            if(event.value === 'spawn' || event.value === 'attach') {
                this.startApp(event.value);
            } else if(event.value === 'disconnect') {
                this.ws.send(JSON.stringify({
                    "action": "app.disconnect"
                }))
            }
        },
        startApp(action: string | null = null) {
            console.log("AppSelector(startApp): Starting app ", action, this.cs.getSelection.action);
            this.cs.setStatusKey("appConnectingStatus", true);
            const t_session_id = crypto.randomUUID();
            this.cs.setSelectionKey("sessionId", t_session_id);
            this.ws.send(JSON.stringify({
                "action": "app." + (action || this.cs.getSelection.action),
                "deviceId": this.cs.getSelection.device.id,
                "appId": this.cs.getSelection.app.id,
                "platform": this.cs.getSelection.platform,
                "appName": this.cs.getSelection.app.name,
                "user": this.cs.getSelection.user.id || -1,
                "library": this.cs.getSelection.library ? this.cs.getSelection.library.file : null,
                "sessionId": t_session_id
            }))
        },
        setLibrary($event: any) {
            this.cs.setSelectionKey("library", $event.value)
            this.ws.send(JSON.stringify({
                "action": "library.change",
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
            this.cs.setSelectionKey("library", library)
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
		// this.ws.removeOpenCallback(this.wsReady);
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
