<template>
    <div class="sidebar">
        <h1>MDM Dashboard</h1>
        <ul>
            <li><router-link to="/"><i class="pi pi-home" style="margin-right: 10px"></i>Dashboard</router-link></li>
            <li><router-link to="/traffic"><i class="pi pi-history mr-2" style="margin-right: 10px"></i>HTTP Traffic</router-link></li>
        </ul>
        <div class="app-info">
            <p class="app-message" type="connected">{{connectionStatus}}<span>{{ connectionAppName }}</span></p>
            <div class="app-info-button-group-wrapper">
                <div class="app-info-button-group">
                    <Button icon="pi pi-refresh" style="margin-right: 10px;" severity="success" rounded text />
                    <Button icon="pi pi-times" severity="danger" rounded text />
                </div>
            </div>
        </div>
    </div>
</template>

<script lang="ts">
import { defineComponent } from "vue";
import Message from "primevue/message";
import Button from "primevue/button";
import Toolbar from "primevue/toolbar";

export default defineComponent({
	name: 'DashboardPage',
    data() {
        return {
            ws: null,
            isConnected: false,
            connectionStatus: "Not Connected",
            connectionAppName: ""
        }
    },
    components: {
        Message,
        Button,
        Toolbar
    },
    created() {
        const url = 'ws://192.168.29.203:8000';
        this.ws = new WebSocket(url);

        this.ws.onopen = () => {
            this.isConnected = true;
            console.log('Connected to WebSocket server');
            const json = {"action":"devices"}
            this.ws.send(JSON.stringify(json))
        };

        this.ws.onmessage = (event: { data: string; }) => {
            const message = JSON.parse(event.data);
            if(message['action'] === 'deviceUpdate') {
                this.connectionStatus = message['message']
                this.connectionAppName = `(${message['appName']})`
            }
        };

        this.ws.onerror = (error: any) => {
            console.error('WebSocket error:', error);
        };

        this.ws.onclose = () => {
            this.isConnected = false;
            console.log('WebSocket connection closed');
        };
    }
});
</script>

<style scoped>
.sidebar .app-info {
    margin-top: 30px;
    border-top: 1px solid #212631ff;
    margin-left: 15px;
    margin-right: 15px;
    margin-bottom: 20px;
}
.app-info .app-message {
    color: #aaa;
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

.sidebar {
    position: fixed;
    width: 200px;
    z-index: 1000;
    height: 100%;
    left: 0;
    top: 0;
    background-color: #212631;
    /* background-color: #31363F; */
    display: flex;
    flex-direction: column;
}
.sidebar h1 {
    margin: 0;
    padding: 15px 0px;
    font-size: 20px;
    background-color: #fffe;
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