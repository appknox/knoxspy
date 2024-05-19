<template>
	<div class="page">
        <Toast />

        <div class="section-group">
            <div class="section section-apps">
                <div class="section-header">
                    <div class="section-header-device">
                        <h4>Apps For</h4>
                        <Dropdown v-model="selectedDevice" :options="data" optionLabel="name" optionValue="value" @change="fetchApps" placeholder="Select a Device" class="w-full md:w-14rem" :placeholder="selectedDevice.value" />
                    
                        <div class="section-header-search">
                            <IconField iconPosition="left">
                                <InputIcon class="pi pi-search"> </InputIcon>
                                <InputText v-model="appSearch" placeholder="Search Apps" :onKeydown="searchApp" />
                            </IconField>
                        </div>
                    </div>
                    <div style="display: flex; gap: 5px; position: relative;">
                        <Dropdown style="display: flex; " v-model="selectedLibrary" :options="libraryList" optionLabel="name" placeholder="Select a Library" class="w-full md:w-14rem">
                            <template #value="slotProps">
                                <div v-if="slotProps.value" class="flex align-items-center">
                                    <div v-if="slotProps.value.platform === 'iOS'"><i class="pi pi-apple"></i> {{ slotProps.value.name }}</div>
                                    <div v-else><i class="pi pi-android"></i> {{ slotProps.value.name }}</div>
                                </div>
                                <span v-else>
                                    {{ slotProps.placeholder }}
                                </span>
                            </template>
                            <template #option="slotProps">
                                <div class="flex align-items-center">
                                    <div v-if="slotProps.option.platform === 'iOS'"><i class="pi pi-apple"></i> {{ slotProps.option.name }}</div>
                                    <div v-else><i class="pi pi-android"></i> {{ slotProps.option.name }}</div>
                                </div>
                            </template>
                        </Dropdown>
                    </div>
                </div>
                <ul class="app-list" v-if="data">
                    <li v-for="item in sortedApps" :key="item.id" @click="startApp(item.identifier, item.name)">
                        <img :src="item.icon">
                        <p>{{ item.name }}</p>
                    </li>
                </ul>
                <div class="appPopupWrapper" :style="{'display': isConnected ? 'block' : 'none'}">
                    <Card class="appPopup">
                        <template #content>
                            <i class="pi pi-info-circle" style="font-size: 35px; margin-bottom: 20px"></i>
                            <p class="m-0">
                                Connected to <t style="display: block;">'{{ connectionAppName }}'</t> App!
                                <!-- <AutoComplete style="display: block;" v-model="selectedLibrary" optionLabel="name" :suggestions="filteredLibraryList" @complete="search" /> -->
                                
                                <div style="display: flex; justify-content: center; align-items: center; gap: 10px" class="auto-detect-library-wrapper">
                                    <Dropdown @change="setLibrary" style="display: flex; " v-model="selectedLibrary" :options="libraryList" optionLabel="name" placeholder="Select a Library" class="w-full md:w-14rem">
                                        <template #value="slotProps">
                                            <div v-if="slotProps.value" class="flex align-items-center">
                                                <div v-if="slotProps.value.platform === 'iOS'"><i class="pi pi-apple"></i> {{ slotProps.value.name }}</div>
                                                <div v-else><i class="pi pi-android"></i> {{ slotProps.value.name }}</div>
                                            </div>
                                            <span v-else>
                                                {{ slotProps.placeholder }}
                                            </span>
                                        </template>
                                        <template #option="slotProps">
                                            <div class="flex align-items-center">
                                                <div v-if="slotProps.option.platform === 'iOS'"><i class="pi pi-apple"></i> {{ slotProps.option.name }}</div>
                                                <div v-else><i class="pi pi-android"></i> {{ slotProps.option.name }}</div>
                                            </div>
                                        </template>
                                    </Dropdown>
                                    <Button label="Auto-Detect" icon="pi pi-refresh" @click="toggleAutoDetectOverlay" />
                                    <div class="overlay-auto-detect" v-if="libraryDetectionPopup">
                                        <div class="flex flex-column gap-3 w-25rem">
                                            <div>
                                                <span class="font-medium text-900 block mb-2">Detected Libraries:</span>
                                                <ul class="list-none p-0 m-0 flex flex-row gap-3">
                                                        <div v-if="!librariesDetected">
                                                            <i class="pi pi-spin pi-spinner" style="color: var(--primary-color)"></i>
                                                        </div>
                                                    <li v-else v-for="member in librariesFound" :key="member.name" class="flex align-items-center gap-2">
                                                        <div v-if="member.status === true">
                                                            <div style="display: flex; align-items: center; gap: 5px" v-if="member.platform === 'iOS'"><i class="pi pi-apple"></i> <span class="font-medium">{{ member.name }}</span></div>
                                                            <div style="display: flex; align-items: center; gap: 5px" v-else><i class="pi pi-android"></i> <span class="font-medium">{{ member.name }}</span></div>
                                                        </div>
                                                    </li>
                                                </ul>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <span :v-if="selectedLibrary !== null && selectedLibrary !== ''" style="display: block; margin-top: 10px"><router-link to="/traffic">Switch to HTTP Traffic tab</router-link></span>
                            </p>
                        </template>
                    </Card>
                </div>
            </div>
        </div>
	</div>
</template>

<script lang="ts">
import { defineComponent } from "vue";
import Dropdown from 'primevue/dropdown';
import Dialog from 'primevue/dialog';
import InputText from "primevue/inputtext";
import IconField from 'primevue/iconfield';
import InputIcon from 'primevue/inputicon';
import Card from "primevue/card";
import AutoComplete from "primevue/autocomplete";
import Toast from 'primevue/toast';
import Button from "primevue/button";


export default defineComponent({
	name: 'DashboardPage',
    components: {
        Dropdown,
        Dialog,
        InputText,
        InputIcon,
        IconField,
        Card,
        AutoComplete,
        Toast,
        Button
    },
    data() {
        return {
            librariesDetected: false,
            librariesFound: [],
            libraryDetectionPopup: false,
            selectedDevice: null,
            selectedApp: "",
            data: [],
            apps: null,
            visibleDialog: true,
            visiblePopup: "none",
            ws: null,
            isConnected: false,
            connection_status: "test",
            appSearch: null,
            connectionAppName: "",
            connectionSessionId: -1,
            libraryList: [{name:'AFNetworking', file:'afnetworking.js', platform: 'iOS'}, {name:'TrustKit', file:'trustkit.js', platform: 'iOS'}, {name:'AlamoFire', file:'alamofire.js', platform: 'iOS'}, {name:'OkHTTP', file:'okhttp.js', platform: 'android'}],
            filteredLibraryList: [],
            selectedLibrary: null
        }
    },
    mounted() {
    },
    computed: {
        sortedApps() {
            var query = this.appSearch;
            // console.log(query);
            
            if(query && query.trim() !== "") {
                query = query.toLowerCase();
                return this.apps.filter(app => app.name.toLowerCase().includes(query))
                                .sort((a, b) => a.name.localeCompare(b.name));
            } else {
                return this.apps;
            }
        },
    },
    created() {
        const url = 'ws://192.168.29.203:8000';
        this.ws = new WebSocket(url);

        this.ws.onopen = () => {
            // this.isConnected = true;
            console.log('Connected to WebSocket server');
            const json = {"action":"devices"}
            this.ws.send(JSON.stringify(json))
            // this.fetchApps()
            // this.startApp("com.appknox.SSL-Pinning-Test", "SSL Pinning Test")
        };

        this.ws.onmessage = (event: { data: string; }) => {
            const message = JSON.parse(event.data);
            if(message['action'] === 'devices') {
                for(const a in message['devices']) {
                    const b = message['devices'][a];
                    this.data.push({"name": b.name, "value": b.id});
                }
                if(this.data.length == 1) {
                    this.selectedDevice = message['devices'][0].id
                    this.fetchApps()
                }
            } else if(message['action'] === 'apps') {
                this.apps = message['apps'];
            } else if(message['action'] === 'startApp') {
                this.visibleDialog = true;
            } else if(message['action'] === 'deviceUpdate') {
                this.connectionSessionId = parseInt(localStorage.getItem("sessionId"))
                const tmpSessionId = message['sessionId']
                if(tmpSessionId === this.connectionSessionId) {
                    this.connectionAppName = `(${message['appName']})`
                    if(message['message'] === "Connected") {
                        this.isConnected = true;
                        localStorage.setItem("appId", message["appId"])
                        localStorage.setItem("appName", message["appName"])
                        localStorage.setItem("library", message["library"])
                        this.ws.send(JSON.stringify({'action': 'detectLibraries', 'sessionId': this.connectionSessionId}))
                    } else {
                        this.connectionAppName = ``
                        this.isConnected = false;
                        localStorage.setItem("appId", "")
                        localStorage.setItem("appName", "")
                        localStorage.setItem("library", "")
                    }
                } else {
                    console.log("Old Session Got Disconnected: " + tmpSessionId + " | Current Session Id: " + this.connectionSessionId);  
                }
            } else if (message['action'] == "scriptError") {
                this.showSticky(message['message']['description'])
                console.log("got an error from script");
            } else if(message['action'] == 'scriptOutput') {
                const libraryStatus = message['message'];
                this.librariesFound = libraryStatus
                this.librariesDetected = true
            }
        };

        this.ws.onerror = (error: any) => {
            console.error('WebSocket error:', error);
        };

        this.ws.onclose = () => {
            this.isConnected = false;
            console.log('WebSocket connection closed');
        };
    },
    methods: {
        setLibrary() {
            if(this.isConnected) {
                this.ws.send(JSON.stringify({'action': 'changeLibrary', 'library': this.selectedLibrary, 'sessionId': this.connectionSessionId}))
            }
        },
        toggleAutoDetectOverlay() {
            this.libraryDetectionPopup = !this.libraryDetectionPopup
        },
        showSticky(message: String) {
            this.$toast.add({ severity: 'error', summary: 'Script Error', detail: message});
        },
        async fetchApps() {
            console.log(this.selectedDevice);
            const json = {"action":"apps", "deviceId": this.selectedDevice}
            this.ws.send(JSON.stringify(json))
        },
        async startApp(identifier: string, name: string) {
            this.selectedApp = identifier
            console.log(this.selectedDevice);
            const sessionId = Math.floor(Math.random() * 100000);
            this.connectionSessionId = sessionId
            localStorage.setItem("sessionId", ""+sessionId)
            const library = this.selectedLibrary !== null ? this.selectedLibrary.file : null
            const json = {"action":"startApp", "deviceId": this.selectedDevice, "appId": identifier, 'appName': name, 'sessionId': sessionId, 'library': library}
            this.ws.send(JSON.stringify(json))
        },
        searchApp() {
            console.log("Searching");
        },
        search(event: any) {
            setTimeout(() => {
                if (!event.query.trim().length) {
                    this.filteredLibraryList = [...this.libraryList];
                } else {
                    this.filteredLibraryList = this.libraryList.filter((library: any) => {
                        return library.name.toLowerCase().startsWith(event.query.toLowerCase());
                    });
                }
            }, 250);
        }
    },
});
</script>


<style>
.auto-detect-library-wrapper {
    position: relative;
    margin-top: 10px;
}
.auto-detect-library-wrapper button span {
    font-size: 13px !important;
}
.auto-detect-library-wrapper span {
    color: #fff !important;
    margin:  0;
    margin-top: 0 !important;
}
.auto-detect-library-wrapper .p-dropdown span {
    color: #333 !important;
    display: flex;
    align-items: center;
    margin-top: 10px;
    font-size: 13px !important;
}
.auto-detect-library-wrapper span:first-of-type {
    margin-right: 5px;
}
.overlay-auto-detect {
    position: absolute;
    right: 0;
    top: 0;
    top: 60px;
    padding: 20px;
    border-radius: 10px;
    background-color: #212631;
    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1);
}
.overlay-auto-detect  div span.font-medium.block {
    color: #aaa !important;
    font-variant: small-caps;
    border-bottom: 1px solid #aaaa;
    margin-bottom: 10px;
    display: block;
}
.overlay-auto-detect ul li {
    padding: 0 !important;
}
.overlay-auto-detect ul li span {
    color: #ddd;
    font-variant: normal;
    font-size: 18px;
    text-align: left;
    padding: 3px !important;
    display: block;
    background-color: #222831aa !important;
    transition: all ease-in-out .2s;
}

.overlay-auto-detect ul li span:hover {
    color: var(--primary-color);
}
.overlay-auto-detect ul li div i {
    color: #fff;
}
.overlay-auto-detect ul {
    height: unset !important;
    overflow: hidden !important;
    display: unset !important;
}
.p-dropdown > .p-dropdown-label {
    display: block;
    width: 100%;
    margin: 0;
}
.appPopupWrapper {
    background-color: #000a;
    position: absolute;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
}
.appPopupWrapper p {
    font-variant: small-caps;
    font-size: 25px;
    padding: 0px;
    margin: 0;
    font-weight: bold;
}
.appPopupWrapper p span {
    color: #10b981;
    font-weight: initial;
    font-variant: normal;
    font-size: 16px;
    margin-top: 30px;
    text-decoration: none;
}
.appPopupWrapper p span a {
    color: #10b981;
    transition: all linear .1s;
    text-decoration: none;
}
.appPopupWrapper p span a:hover {
    text-shadow: 1px 1px 1px #0005;
}
.appPopup {
    box-shadow: 0 0 20px -10px #000;
    position: absolute;
    width: 400px;
    top: 250px;
    left: 50%;
    margin-left: -200px;
    display: block;
}
.page {
    /* position: relative; */
	/* position: absolute;
	left: 200px; */
    overflow: hidden;
    flex-grow: 1;
	/* width: calc(100% - 200px); */
	height: 100%;
	background-color: #222831;
    background-color: #fff;
}
.dashboard {
	position: absolute;
	left: 200px;
	width: calc(100% - 200px);
	height: 100%;
	background-color: #fff;
}
.dashboard h1 {
	flex: 1;
}
.section ul {
    list-style: none;
    margin: 0;
    padding: 0;
}
.section ul li {
    margin: 0;
    padding: 10px;
    cursor: pointer;
    transition: all linear .2s;
}
.section h4 {
    font-variant: small-caps;
    font-size: 26px;
    color: #222c;
    margin: 0;
    /* margin: 10px 25px; */
    /* padding: 15px; */
}
.section-devices li:hover {
    background-color: #fffa;
}
.section-header {
    flex-wrap: wrap;
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid #ddd;
    padding: 0 25px;
    margin: 0 45px;
    height: 60px;
}
.section-header .section-header-device {
    display: flex;
    column-gap: 10px;
    margin: 0;
}
.section-header > div {
    margin-left: 20px;
}
.section-devices ul {
    overflow-y: hidden;
}
.section-apps {
    height: 100vh;
}
.section-apps ul.app-list {
    height: calc(100vh - 110px);
    overflow-y: scroll;
    overflow-x: hidden;
    display: grid;
    padding: 20px;
    row-gap: 20px;
    margin-top: 20px;
    column-gap: 0px;
    grid-template-columns: repeat(auto-fit, 20%);
}
@media only screen and (min-width: 1500px) {
    .section-apps ul.app-list {
        grid-template-columns: repeat(auto-fit, 16.6667%);
        grid-template-columns: repeat(auto-fit, 14.2857142857%);
    }
}
@media only screen and (max-width: 1000px) {
    .section-apps ul.app-list {
        grid-template-columns: repeat(auto-fit, 25%);
    }
}
@media only screen and (max-width: 700px) {
    .section-apps ul.app-list {
        grid-template-columns: repeat(auto-fit, 33.3333%);
    }
}
@media only screen and (max-width: 500px) {
    .section-apps ul.app-list {
        grid-template-columns: repeat(auto-fit, 50%);
    }
}
.section-apps .app-list li {
    align-content: center;
    border-radius: 10px;
    transition: all linear .4s;
}
.section-apps .app-list li:hover {
    box-shadow: 0px 0px 15px -5px #0005;
    background-color: #0001;
    background-color: #2222;
}
.section-apps li img {
    width: 70px;
    margin-top: 10px;
    transition: all linear .2s;
}
.section-apps li:hover img {
    margin-top: 5px;
    width: 80px;
}
.section-apps li p {
    transition: all linear .2s;
}
.section-apps li:hover p {
    margin-top: 11px;
}
.section-popup {
    position: absolute;
    top: 90px;
    left: 0;
    width: 100%;
    height: calc(100% - 90px);
    background-color: #fffa;
}
.section-popup p {
    background-color: #eee;
    position: absolute;
    top: 50%;
    left: 50%;
    margin-top: -30px;
    line-height: 100px;
    border-radius: 10px;
    box-shadow: 0px 0 15px -10px #000;
    height: 100px;
    min-width: 700px;
    margin-left: -350px;
    font-size: 30px;
}
break {
    flex-basis: 100%;
    height: 0;
}
</style>
