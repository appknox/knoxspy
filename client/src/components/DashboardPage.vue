<template>
	<div class="page">
        <div class="section-group">
            <div class="section section-apps">
                <div class="section-header">
                    <div class="section-header-device">
                        <h4>Apps For</h4>
                        <Dropdown v-model="selectedDevice" :options="data" optionLabel="name" optionValue="value" @change="fetchApps" placeholder="Select a Device" class="w-full md:w-14rem" :placeholder="selectedDevice.value" />
                    </div>
                    <AutoComplete v-model="selectedLibrary" optionLabel="name" :suggestions="filteredLibraryList" @complete="search" />

                    <div class="section-header-search">
                        <IconField iconPosition="left">
                            <InputIcon class="pi pi-search"> </InputIcon>
                            <InputText v-model="appSearch" placeholder="Search" :onKeydown="searchApp" />
                        </IconField>
                    </div>
                </div>
                <ul v-if="data">
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
                                <span style="display: block"><router-link to="/traffic">Switch to HTTP Traffic tab</router-link></span>
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

export default defineComponent({
	name: 'DashboardPage',
    components: {
        Dropdown,
        Dialog,
        InputText,
        InputIcon,
        IconField,
        Card,
        AutoComplete
    },
    data() {
        return {
            selectedDevice: "2d2dfbf",
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
            libraryList: [{name:'AFNetworking', file:'afnetworking.js'}, {name:'TrustKit', file:'trustkit.js'}, {name:'AlamoFile', file:'alamofire.js'}, {name:'OkHTTP', file:'okhttp.js'}],
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
                    this.fetchApps()
                }
            } else if(message['action'] === 'apps') {
                this.apps = message['apps'];
            } else if(message['action'] === 'startApp') {
                this.visibleDialog = true;
            } else if(message['action'] === 'deviceUpdate') {
                const tmpSessionId = message['sessionId']
                if(tmpSessionId === this.connectionSessionId) {
                    this.connectionAppName = `(${message['appName']})`
                    if(message['message'] === "Connected") {
                        this.isConnected = true;
                    } else {
                        this.isConnected = false;
                    }
                } else {
                    console.log("Got info for an old app i think" + tmpSessionId);
                    
                }
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
            const json = {"action":"startApp", "deviceId": this.selectedDevice, "appId": identifier, 'appName': name, 'sessionId': sessionId, 'library': this.selectedLibrary.file}
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
    background-color: #fffa
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
.section-apps ul {
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
    .section-apps ul {
        grid-template-columns: repeat(auto-fit, 16.6667%);
        grid-template-columns: repeat(auto-fit, 14.2857142857%);
    }
}
@media only screen and (max-width: 1000px) {
    .section-apps ul {
        grid-template-columns: repeat(auto-fit, 25%);
    }
}
@media only screen and (max-width: 700px) {
    .section-apps ul {
        grid-template-columns: repeat(auto-fit, 33.3333%);
    }
}
@media only screen and (max-width: 500px) {
    .section-apps ul {
        grid-template-columns: repeat(auto-fit, 50%);
    }
}
.section-apps li {
    align-content: center;
    border-radius: 10px;
    transition: all linear .4s;
}
.section-apps li:hover {
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
