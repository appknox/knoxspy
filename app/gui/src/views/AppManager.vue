<template>
	<div class="page">
        <Toast />
        <ConfirmDialog></ConfirmDialog>
        <div class="section-group">
            <div class="section section-apps">
                <div class="section-header">
                    <div class="section-header-device">
                        <h4>Apps For</h4>
                        <Dropdown v-model="currentSession.app.selectedDevice" :options="currentSession.app.devices" optionLabel="name" @change="fetchApps" class="w-full md:w-14rem" :placeholder="currentSession.app.selectedDevice?.value || 'Select a Device'">
                            <template #value="slotProps">
                                <div v-if="slotProps.value" class="flex align-items-center">
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
                        <Button icon="pi pi-refresh" rounded aria-label="Filter" label="Refresh" @click="refreshDevices" outlined />
                    </div>
                    <div style="display: flex; gap: 10px; align-items: center;" v-if="currentSession.app.selectedDevice? currentSession.app.selectedDevice.platform === 'Android' ? true : false : false">
                        <p><b>Choose Profile</b></p>
                        <SelectButton v-model="androidSelectedUser" :options="currentSession.app.users" option-label="name" aria-labelledby="basic" :allow-empty="false" @change="setSelectedUser($event)"/>
                    </div>
                    <div style="display: flex; gap: 10px; position: relative;">
                        <div class="section-header-search">
                            <IconField iconPosition="left">
                                <InputIcon class="pi pi-search"></InputIcon>
                                <InputText v-model="appSearch" placeholder="Search Apps" :onKeydown="searchApp" />
                            </IconField>
                        </div>
                    </div>
                </div>
                <div v-if="currentSession.app.selectedDevice == null" style="display: flex; width: 100%; height: calc(100vh - 65px); justify-content: center; align-items: center; flex-direction: column;">
                    <i style="font-size: 40px; color: var(--surface-500);" class="pi pi-info-circle"></i>
                    <p style="font: 25px 'Fira Code'; color: var(--surface-500)">No Device Selected!</p>
                </div>
                <div v-if="isLoading" style="display: flex; width: 100%; height: calc(100vh - 65px); justify-content: center; align-items: center; flex-direction: column;">
                    <i class="pi pi-sync pi-spin" style="font-size: 40px; color: var(--surface-500);"></i>
                    <p style="font: 25px 'Fira Code'; color: var(--surface-500)">Loading Apps</p>
                </div>
                <ul class="app-list" v-if="apps.length > 0" style="padding-bottom: 100px;">
                    <ContextMenu ref="menu" :model="appMenu" />
                    <li v-for="item in apps" :key="item.id" @click="startApp(item.id, item.name)" @contextmenu="onRightClick($event, item)">
                        <img :src="item.icon == '' ? defaultPng : item.icon">
                        <p>{{ item.name }}</p>
                    </li>
                </ul>
            </div>
        </div>
	</div>
    <Footer @deviceUpdated="updateDeviceInfo" @appListUpdated="updateAppList" @workAppListUpdated="updateWorkAppList"></Footer>
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
import {useAppStore, useWebSocketStore, usePageReadyEmitter} from '../stores/session';
import Footer from "../components/Footer.vue";
import SelectButton from 'primevue/selectbutton';
import {defaultPng} from "../constants";


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
        SelectButton
    },
    data() {
        return {
            defaultPng: defaultPng,
            androidSelectedUser: {name: "User", id: "0"},
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
            currentSession: useAppStore(),
            ws: useWebSocketStore(),
            isLoading: true,
            emitter: usePageReadyEmitter(),
            apps: [],
        }
    },
    computed: {
        sortedApps(): any {
            var query = this.appSearch;
            // console.log(query);
            
            if(query && query.trim() !== "") {
                query = query.toLowerCase();
                return this.apps.filter((app: any) => app.name.toLowerCase().includes(query))
                                .sort((a: any, b: any) => a.name.localeCompare(b.name));
            } else {
                return this.apps;
            }
        },
    },
    mounted() {
        if(!this.currentSession.app.selectedSession) {
            this.$router.push('/');
        }
        console.log("AppManager: Page mounted. Apps length:", this.currentSession.app.apps.length);
        if(this.currentSession.app.apps.length > 0) {
            this.isLoading = false
        }
    },
    methods: {
        setSelectedUser(user: any) {
            const t_user = user.value;
            console.log("AppManager(setSelectedUser): Selected user:", t_user);
            this.$router.replace({query: {
                ...this.$route.query,
                user: t_user.id
            }})
            if(parseInt(t_user.id) >= 10) {
                this.apps = t_user.apps;
                console.log("AppManager(setSelectedUser): Selected extra user apps:", t_user.apps);
            } else {
                console.log("AppManager(setSelectedUser): Selected default user apps:", this.currentSession.app.apps);
                this.apps = this.currentSession.app.apps
            }
        },
        updateWorkAppList(work_apps: any) {
            console.log("AppManager(updateWorkAppList): Work apps received:", work_apps.length);
        },
        refreshDevices() {
            this.ws.send(JSON.stringify({"action":"devices"}))
        },
        rightClickHandler(type: string) {
            this.currentSession.setSelectedApp(this.rightClickMenuIdentifier)
            this.currentSession.storeSelectedApp()
            this.$router.push({path: '/app', query: {
                ...this.$route.query,
                app: this.rightClickMenuIdentifier,
                device: this.currentSession.app.selectedDevice.id,
                action: type
            }})
        },
        onRightClick(event: any, item: any) {
            this.rightClickMenuIdentifier = item.id
            this.rightClickMenuApp = item.name
            this.$refs.menu.show(event);
        },
        async fetchApps() {
            this.isLoading = true
            this.ws.send(JSON.stringify({"action":"apps", "deviceId": this.currentSession.app.selectedDevice.id, "platform": this.currentSession.app.selectedDevice.platform}))
        },
        async startApp(identifier: string, name: string) {
            this.currentSession.setSelectedApp(identifier)
            console.log("AppManager(startApp): Selected app:", this.currentSession.app.selectedApp);
            console.log("AppManager(startApp): Selected device:", this.currentSession.app.selectedDevice);
            this.$router.push({path: '/app', query: {
                ...this.$route.query,
                app: identifier,
                device: this.currentSession.app.selectedDevice.id,
                user: this.androidSelectedUser.id,
                action: "spawn"
            }})
        },
        searchApp(event: any) {
            console.log("Search app", event.target.value);
        },
        updateDeviceInfo() {
            // this.fetchApps();
        },
        updateAppList(app_list: any) {
            console.log("app_list", app_list)
            this.apps = app_list
            this.isLoading = false
        }
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
    align-items: start;
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
    word-wrap: break-word;
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
