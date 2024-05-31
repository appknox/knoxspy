<template>
    <div class="sidebar" :class="{'active': isActive}">
        <div class="sidebar-header">
            <Button v-shortkey="['meta', 'l']" @shortkey="toggleSidebar" :icon="isActive ? 'pi pi-times' : 'pi pi-angle-right'" rounded aria-label="Submit" @click="toggleSidebar" />
            <h1 :class="{'active': isActive}">Appknox</h1>
        </div>
        <ul>
            <li><router-link to="/"><i class="pi pi-home" style="margin-right: 10px"></i><span :class="{'active': isActive}">Dashboard</span></router-link></li>
            <li><router-link to="/apps"><i class="pi pi-th-large" style="margin-right: 10px"></i><span :class="{'active': isActive}">Apps</span></router-link></li>
            <li><router-link to="/traffic"><i class="pi pi-history mr-2" style="margin-right: 10px"></i><span :class="{'active': isActive}">HTTP Traffic</span></router-link></li>
            <li><router-link to="/libraries"><i class="pi pi-folder mr-2" style="margin-right: 10px"></i><span :class="{'active': isActive}">Library Manager</span></router-link></li>
        </ul>
        <div class="app-info" :class="isActive ? '' : 'closed'">
            <p class="app-message" type="connected">{{status}}<span>{{ name }}</span></p>
            <div class="app-info-button-group-wrapper" style="display: none;">
                <div class="app-info-button-group">
                    <Button icon="pi pi-refresh" @click="restartApp" style="margin-right: 10px;" severity="success" rounded text />
                    <Button icon="pi pi-times" disabled severity="danger" rounded text/>
                </div>
            </div>
        </div>
        <!-- <SpeedDial @show="toggleSpeeddial" @hide="toggleSpeeddial" :model="speeddial_menu" direction="left" style="box-shadow: 0 10px 15px -10px #aaa;position: fixed; bottom: 30px; right: 30px;border-radius: 50px;" id="speeddial_menu" :style="{backgroundColor: speedMenuBackground}">
            <template #item="{ item }" style="background-color: red;">
                <Button :key="item.label" :icon="item.icon" class="speeddial-buttons" link style="text-decoration: none; width: auto;">
                    <span style="width: 120px;"><i :class="item.icon" style="margin-right: 5px;"></i>{{ item.label }}</span>
                </Button>
            </template>
        </SpeedDial> -->

    </div>
</template>

<script lang="ts">
import { defineComponent } from "vue";
import Message from "primevue/message";
import Button from "primevue/button";
import Toolbar from "primevue/toolbar";
import ToggleButton from "primevue/togglebutton";
import { useSessionStore } from "../stores/session";
import SpeedDial from "primevue/speeddial";

export default defineComponent({
	name: 'SideBar',
    data() {
        return {
            speedMenuBackground: "#fff0",
            ws: null,
            isConnected: false,
            status: "Not Connected",
            name: null,
            identifier: null,
            deviceId: null,
            library: null,
            isActive: false,
            sessionId: -1,
            sess: null,
            speeddial_menu: [
                {
                    label: 'Add',
                    icon: 'pi pi-pencil',
                    command: () => {
                    }
                },
                {
                    label: 'Update',
                    icon: 'pi pi-refresh',
                    command: () => {
                    }
                },
                {
                    label: 'Delete',
                    icon: 'pi pi-trash',
                    command: () => {
                    }
                },
            ]
        }
    },
    components: {
        SpeedDial,
        Message,
        Button,
        Toolbar,
        ToggleButton
    },
    methods: {
        toggleSpeeddial() {
            this.speedMenuBackground = this.speedMenuBackground == "#fff0" ? "#ffff" : "#fff0";
        },
        toggleSidebar() {            
            this.isActive = !this.isActive;
        },
        restartApp() {
            const sessionId = Math.floor(Math.random() * 100000);
            this.sess.restartApp(sessionId)
        }
    },
    created() {
        this.sess = useSessionStore();
        
        this.sess.$subscribe((mutation, state) => {
            if(mutation.type === 'patch object') {
                if('app' in mutation.payload) {
                    const appConnectionObj = mutation.payload.app;
                    for(var element in appConnectionObj) {
                        this[element] = appConnectionObj[element];
                        console.log(element, this[element], appConnectionObj[element]);
                        
                    }
                    
                    
                    console.log("Mutation", mutation.payload);
                    console.log(appConnectionObj);
                    // this.isConnected = appConnectionObj.isConnected;
                    // this.connectionAppName = appConnectionObj.name;
                    // this.connectionStatus = appConnectionObj.status;
                    // this.connectionSessionId = appConnectionObj.sessionId;
                    // this.connectionAppIdentifier = appConnectionObj.identifier;
                    // this.connectionDeviceId = appConnectionObj.deviceId;
                    // this.connectionLibrary = appConnectionObj.library;
                }
            }
        });
    }
});
</script>

<style scoped>
#speeddial_menu {
    
}
.p-speeddial {
    width: 0;
}
.p-speeddial-list {
    background-color: red;
}
.speeddial-buttons {
    transition: all linear .2s;
}
.speeddial-buttons:hover {
    background-color: #eeea;
    border-radius: 50px;
}
.sidebar {
    display: flex;
    flex-direction: column;
}
.sidebar .app-info {
    transition: all ease-in-out .3s;
    margin-top: 30px;
    border-top: 1px solid #212631ff;
    margin-left: 15px;
    margin-right: 15px;
    margin-bottom: 20px;
}
.app-info .app-message {
    display: flex;
    flex-direction: column;
    color: #aaa;
    height: 55px !important;
    margin-left: -55px !important;
    margin-bottom: 80px !important;
    justify-content: center;
}
.app-info .app-message span {
    color: red;
    display: block;
}
.app-info .app-message[type='connected'] span {
    color: lightgreen;
}
.app-info-button-group-wrapper {
    display: flex;
    justify-content: center;
}
.app-info-button-group {
    border-radius: 50px;
    padding: 5px;
    background-color: #2a303d66;
}
.app-info-button-group button {
    width: 2rem;
    height: 2rem;
    transition: all linear .2s;
}
.app-info-button-group button:hover {
    background-color: #212631;
}
.app-info.closed {

    margin: 2px;

    .app-message {
        transform: rotateZ(-90deg);
        margin: 0;
        padding: 0;
        width: 150px;
        height: 150px;
    }
    .app-message span {
        display: inline-block;
    }
    .app-info-button-group-wrapper {
        margin-bottom: 40px;
        transform: rotateZ(-90deg);
        width: 160px;
        margin-left: -58px;
        margin-top: 50px;
    }
}
.sidebar {
    h1.active {
        display: block;
    }
    li span.active {
        display: inline;
    }
}
.sidebar {
    transition: all ease-in-out .4s;
    /* position: fixed; */
    position: relative;
    z-index: 1000;
    left: 0;
    top: 0;
    background-color: #212631;
    height: 100vh;
    width: 50px;
}
.sidebar.active {
    width: 200px;
    /* background-color: #31363F; */
    display: flex;
    flex-direction: column;
}
.sidebar .sidebar-header {
    background-color: #212631;
    display: flex;
    justify-content: center;
    align-items: center;
    column-gap: 10px;
    padding: 0 10px;
    height: 60px;
}
.sidebar-header button {
    position: absolute;
    left: 100%;
    margin-left: -20px;
    top: 10px;
}
.sidebar.active .sidebar-header {
    background-color: #fffe;
}
.sidebar h1 {
    margin: 0;
    display: none;
    padding: 15px 0px;
    font-size: 20px;
    /* background-color: #76ABAE; */
    box-shadow: 0px 10px 15px -14px #000;
}

ul {
    list-style-type: none;
    padding: 0;
    margin: 30px 0 0;
    flex-grow: 1;
}
ul li {
    padding-left: 10px;
    padding-right: 10px;
    margin-bottom: 5px;
}
li a {
    border-radius: 7px;
    display: block;
    color: rgba(255, 255, 255, .87);
    cursor: pointer;
    padding: 7px;
    transition: all linear .2s;
    text-decoration: none;
}

li a span {
    display: none;
}
li a:hover {
    box-shadow: 0px 6px 15px -14px #000;
    background-color: #2a303d66;
    color: rgba(255, 255, 255, 1);
}
ul li a.router-link-exact-active {
    box-shadow: 0px 6px 15px -14px #000;
    background-color: #2a303d;
}
</style>