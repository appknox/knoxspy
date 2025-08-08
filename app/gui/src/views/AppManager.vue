<template>
	<div class="page">
        <Toast />
        <ConfirmDialog></ConfirmDialog>
        <div class="section-group">
            <div class="section section-apps">
                <div class="section-header">
                    <div class="section-header-device">
                        <h4>Apps For</h4>
                        <Dropdown v-model="cs.getSelection.device" :options="cs.getData.devices" optionLabel="name" @change="switchDevice" class="w-full md:w-14rem" :placeholder="cs.getSelection.device.id ? cs.getSelection.device.id : 'Select a Device'">
                            <template #value="slotProps">
                                <div v-if="slotProps.value.id" class="flex align-items-center">
                                    <div v-if="slotProps.value.platform === 'iOS'"><i style="margin-right: 5px;" class="pi pi-apple"></i>{{ slotProps.value.name }}</div>
                                    <div v-if="slotProps.value.platform === 'iPhone OS'"><i style="margin-right: 5px;" class="pi pi-apple"></i>{{ slotProps.value.name }}</div>
                                    <div v-if="slotProps.value.platform === 'Android'"><i style="margin-right: 5px;" class="pi pi-android"></i>{{ slotProps.value.name }}</div>
                                    <div v-if="slotProps.value.platform === 'Unknown'"><i style="margin-right: 5px;" class="pi pi-times"></i>{{ slotProps.value.name }}</div>
                                </div>
                                <span v-else>
                                    {{ slotProps.placeholder }}
                                </span>
                            </template>
                            <template #option="slotProps">
                                <div class="flex align-items-center">
                                    <div v-if="slotProps.option.platform === 'iOS'"><i style="margin-right: 5px;" class="pi pi-apple"></i>{{ slotProps.option.name }}</div>
                                    <div v-if="slotProps.option.platform === 'iPhone OS'"><i style="margin-right: 5px;" class="pi pi-apple"></i>{{ slotProps.option.name }}</div>
                                    <div v-if="slotProps.option.platform === 'Android'"><i style="margin-right: 5px;" class="pi pi-android"></i>{{ slotProps.option.name }}</div>
                                    <div v-if="slotProps.option.platform === 'Unknown'"><i style="margin-right: 5px;" class="pi pi-times"></i>{{ slotProps.option.name }}</div>
                                </div>
                            </template>
                        </Dropdown>
                        <Button icon="pi pi-refresh" rounded aria-label="Filter" :loading="refreshingDevices" label="Refresh Devices" @click="refreshDevices" outlined />
                    </div>
                    <div v-if="cs.getData.users && cs.getData.users.length" style="display: flex; gap: 10px; align-items: center; justify-content: center; flex-wrap: wrap;" >
                        <b>Choose User:</b>
                        <SelectButton v-model="cs.getSelection.user" :options="cs.getData.users" optionLabel="name" aria-labelledby="basic" @change="switchUser" />
                    </div>
                    <div style="display: flex; gap: 10px; position: relative;">
                        <Button icon="pi pi-refresh" :loading="refreshingApps" rounded aria-label="Filter" label="Refresh Apps" @click="refreshApps" outlined />
                        <div class="section-header-search">
                            <IconField iconPosition="left">
                                <InputIcon class="pi pi-search"></InputIcon>
                                <InputText v-model="appSearch" placeholder="Search Apps" />
                            </IconField>
                        </div>
                    </div>
                </div>
                <div v-if="!cs.getSelection.device || !cs.getSelection.device.id" style="display: flex; width: 100%; height: calc(100vh - 65px); justify-content: center; align-items: center; flex-direction: column;">
                    <i style="font-size: 40px; color: var(--surface-500);" class="pi pi-info-circle"></i>
                    <p style="font: 25px 'Fira Code'; color: var(--surface-500)">No Device Selected!</p>
                </div>
                <div v-if="isLoading" style="display: flex; width: 100%; height: calc(100vh - 65px); justify-content: center; align-items: center; flex-direction: column;">
                    <i class="pi pi-sync pi-spin" style="font-size: 40px; color: var(--surface-500);"></i>
                    <p style="font: 25px 'Fira Code'; color: var(--surface-500)">Loading Apps</p>
                </div>
                <ul class="app-list" v-if="cs.getSelection.apps && cs.getSelection.apps.length > 0" style="padding-bottom: 100px;">
                    <ContextMenu ref="menu" :model="appMenu" />
                    <li v-for="item in sortedApps" :key="item.id" @click="startApp(item.id)" @contextmenu="onRightClick($event, item)">
                        <img :src="item.icon || defaultPng">
                        <p>{{ item.name }}</p>
                    </li>
                </ul>
            </div>
        </div>
	</div>
    <Footer @dashboardReady="dashboardReady"></Footer>
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
import ContextMenu from "primevue/contextmenu";
import {useAppStore, useWebSocketStore} from '../stores/session';
import defaultPng from '../../public/default.png';
import Footer from "../components/Footer.vue";
import SelectButton from 'primevue/selectbutton';
import ConfirmDialog from 'primevue/confirmdialog';

export default defineComponent({
	name: 'AppManager',
    components: {
        ContextMenu,
        Dropdown,
        Dialog,
        InputText,
        InputIcon,
        IconField,
        Card,
        AutoComplete,
        Toast,
        Button,
        Footer,
        SelectButton,
        ConfirmDialog,
    },
    data() {
        return {
            defaultPng,
            appMenu: [
                {
                    label: 'Spawn',
                    icon: 'pi pi-plus',
                    command: () => this.rightClickHandler('spawn')
                },
                {
                    label: 'Attach',
                    icon: 'pi pi-link',
                    command: () => this.rightClickHandler('attach')
                },
            ],
            appSearch: "",
            rightClickMenuIdentifier: "",
            rightClickMenuApp: "",
            cs: useAppStore(),
            ws: useWebSocketStore(),
            isLoading: true,
            refreshingApps: false,
            refreshingDevices: false,
        }
    },
    computed: {
        sortedApps(): any {
            var query = this.appSearch;
            if(query && query.trim() !== "") {
                query = query.toLowerCase();
                return this.cs.getSelection.apps.filter((app: any) => app.name.toLowerCase().includes(query))
                                .sort((a: any, b: any) => a.name.localeCompare(b.name));
            } else {
                return this.cs.getSelection.apps;
            }
        },
    },
    mounted() {
        console.log("AppManager(mounted): Page mounted");
        if(this.ws.isConnected) {
            console.log("AppManager(mounted): WebSocket connected");
            this.isLoading = false;
        }
        this.ws.addOnMessageHandler(this.wsMessage);
    },
    methods: {
        wsMessage(message: any) {
            message = JSON.parse(message);
            console.log("AppManager(wsMessage): Received message:", message.action);
            if(message.action === "apps.refresh.ack") {
                console.log("Footer(wsMessage): Apps ready", message.data);
				if(message.platform.toLowerCase() === "android") {
					this.cs.setDataKey("users", message.data);
					this.cs.setSelectionKey("user", message.data.filter((user: any) => user.id == "0")[0]);
					this.cs.setSelectionKey("apps", message.data.filter((user: any) => user.id == "0")[0].apps);
				} else {
					this.cs.setDataKey("apps", message.data[0]);
					this.cs.setDataKey("users", []);
				}
                this.refreshingApps = false;
            } else if(message.action === "devices.refresh.ack") {
				console.log("Footer(wsMessage): Devices ready", message.data);
				this.cs.setDataKey("devices", message.data);
                this.cs.setDefaultDevice();
                this.refreshingDevices = false;
            }
        },
        dashboardReady() {
            this.isLoading = false
        },
        refreshDevices() {
            this.refreshingDevices = true;
            this.ws.send(JSON.stringify({"action":"devices.refresh"}));
        },
        refreshApps() {
            this.refreshingApps = true;
            this.ws.send(JSON.stringify({"action":"apps.refresh", "device": this.cs.getSelection.device.id, "platform": this.cs.getSelection.device.platform}))
        },
        rightClickHandler(type: string) {
            this.$router.push({path: '/app', query: {
                ...this.$route.query,
                app: this.rightClickMenuIdentifier,
                device: this.cs.getSelection.device.id,
                platform: this.cs.getSelection.device.platform,
                user: this.cs.getSelection.user.id || -1,
                action: type
            }})
        },
        onRightClick(event: any, item: any) {
            this.rightClickMenuIdentifier = item.id
            this.rightClickMenuApp = item.name
            this.$refs.menu.show(event);
        },
        switchDevice() {
            const t_device = this.cs.getSelection.device;
            console.log("AppManager(switchDevice): Selected device:", t_device);
            if(t_device.platform.toLowerCase() === "android") {
                this.cs.setSelectionKey("apps", t_device.users.filter((user: any) => user.id == "0")[0].apps);
                this.cs.setSelectionKey("user", t_device.users.filter((user: any) => user.id == "0")[0]);
                this.cs.setDataKey("users", t_device.users);
                console.log("AppManager(switchDevice): Users:", this.cs.getData.users);
            } else {
                this.cs.setSelectionKey("apps", t_device.users[0]);
                this.cs.setDataKey("users", []);
                this.cs.setSelectionKey("user", {});
            }
        },
        switchUser(user: any) {
            console.log("AppManager(switchUser): Selected user:", user.value);
            const t_apps = this.cs.getData.users.find((u: any) => u.id == parseInt(user.value.id)).apps;
            console.log("AppManager(switchUser): Apps:", t_apps);
            this.cs.setSelectionKey("apps", t_apps);
        },
        async startApp(identifier: string) {
            const t_apps = this.cs.getSelection.apps;
            const t_app = t_apps.find((app: any) => app.id == identifier);
            this.cs.setSelectionKey("app", t_app)
            console.log("AppManager(startApp): Selected app:", this.cs.getSelection.app);
            console.log("AppManager(startApp): Selected device:", this.cs.getSelection.device);
            this.$router.push({path: '/app', query: {
                ...this.$route.query,
                app: t_app.id,
                platform: this.cs.getSelection.device.platform,
                user: this.cs.getSelection.user.id || -1,
                device: this.cs.getSelection.device.id,
                action: "spawn"
            }})
        },
    },
});
</script>


<style>
.appPopupCloseWrapper {
    position: absolute;
    right: -15px;
    top: -15px;
    background-color: var(--red-600);
    color: #fff;
    /* box-shadow: -5px 5px 15px -10px #000; */
    border-radius: 50%;
    width: 30px;
    height: 30px;
    display: flex;
    justify-content: center;
    align-items: center;
    cursor: pointer;
    transition: all ease-in-out .2s;
}
.appPopupCloseWrapper:hover {
    box-shadow: -5px 5px 15px -7px #000;
}
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
    height: calc(100vh - 180px);
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
    overflow-wrap: break-word;
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
.app-list {
    margin-bottom: 50px;
    align-items: start;
}
.app-list::after {
    content: '';
    position: absolute;
    bottom: 100px;
    left: 0;
    right: 0;
    height: 150px; /* Height of the fade area */
    /* Gradient from transparent to the container's background color */
    background: linear-gradient(to bottom, rgba(255, 255, 255, 0), rgba(255, 255, 255, .3) 30%, rgba(255, 255, 255, .6) 60%, rgba(255, 255, 255, 1) 100%);
    pointer-events: none; /* Allows clicking/scrolling through the overlay */
    border-bottom-left-radius: 0.75rem; /* Match container rounding */
    border-bottom-right-radius: 0.75rem; /* Match container rounding */
}
</style>
