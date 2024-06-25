
<template>
    <div class="page page-dashboard">
        <Toast />
        <Card style="width: 40rem; overflow: hidden">
            <template #header>
                <h2 style="border-bottom: 1px solid #eee; padding-bottom: 20px; margin-bottom: 0">Sessions</h2>
            </template>
            <template #content>
                <Message severity="info" v-if="isSessionActive" :closable="false">
                    <template #messageicon>
                        <i class="pi pi-info-circle" style="margin-right: 10px;"></i>
                    </template>
                    <span class="ml-2" style="line-height: 38px;"><b>'{{sess.session.name}}'</b> session is currently in use!</span>
                    <Button severity="danger" label="Disconnect" text style="margin-left: 20px;" @click="clearActiveSession"/>
                    <!-- <Button severity="danger" label="Disconnect"/> -->
                </Message>
                <div style="display: flex; align-items: start; border-radius: 10px" id="sessionSelection" :class="isSessionActive ? 'disabled' : ''">
                    <div style="display: flex; flex-direction: column; flex-grow: 1; flex-basis: 0; padding: 20px; ">
                        <p class="m-0">
                            Create A New Session
                        </p>
                        <div style="gap: 10px; display: flex; flex-direction: column;">
                            <InputText v-model="newSessionName" placeholder="Session Name" />
                            <Button label="Create New" size="small" @click="createNewSession"/>
                        </div>
                    </div>
                    <div style="flex-grow: 1; flex-basis: 0; padding: 20px;border-left: 1px solid #eee;">
                        <p class="m-0">
                            Choose An Existing One
                        </p>
                        <Listbox v-model="selectedSession" :options="sessionList" optionLabel="name" class="w-full md:w-14rem" style="" />
                        <div style="display: flex; gap: 10px; justify-content: center">
                            <Button icon="pi pi-times" size="small" severity="danger" label="Delete" style="margin-top: 10px;" @click="deleteSession"/>
                            <Button icon="pi pi-check" size="small" label="Choose" style="margin-top: 10px;" @click="chooseExistingSession"/>
                        </div>
                    </div>
                </div>
            </template>
        </Card>
    </div>
</template>
<script lang="ts">
import Button from 'primevue/button';
import Card from 'primevue/card';
import InputText from 'primevue/inputtext';
import { defineComponent } from 'vue';
import Listbox from 'primevue/listbox';
import { useSessionStore } from '../stores/session';
import Message from 'primevue/message';
import Toast from 'primevue/toast';


export default defineComponent({
    name: 'DashboardPage',
    components: {
        Listbox,
        Card,
        Button,
        InputText,
        Message,
        Toast
    },
    data() {
        return {
            isSessionActive: false,
            ws: null,
            sess: null,
            newSessionName: null,
            selectedSession: null,
            sessionList: [],
        }
    },
    mounted() {
        if(this.sess.error !== null) {
            console.log("Error:" + this.sess.error);            
            this.$toast.add({ severity: 'info', summary: 'Info', detail: this.sess.error });
            this.sess.$patch({'error': null})
        }
    },
    created() {
        this.sess = useSessionStore()
        

        const url = 'ws://' + import.meta.env.VITE_SERVER_IP + ':8000';
        this.ws = new WebSocket(url);

        this.ws.onopen = () => {
            console.log('Connected to WebSocket server');
            const json = {"action":"sessions"}
            this.ws.send(JSON.stringify(json))
        };

        this.ws.onmessage = (event: { data: string; }) => {
            const message = JSON.parse(event.data);
            // console.log("New Message");
            // console.log(message);
            
            
            if(message['action'] === 'sessionList') {
                const tmpSessions = message['sessions'];
                this.sessionList = []
                tmpSessions.map((item) => {
                    this.sessionList.push(item)
                })                
            } else if (message['action'] === 'activeSession') {
                const tmpActiveSession = message['session'];
                var tmpLastSessionConfig = {"session": {}, "app": {}};
                this.sess.$patch({'session': message['session']})

                if(tmpActiveSession.name) {
                    console.log("Found an active session! Trying to restore last session");
                    console.log(message['session'], 'config' in message['session']);
                    
                    if('session' in message && 'config' in message['session']) {
                        console.log("Valid config found!");
                        const tmpSessionConfig = JSON.parse(message['session']['config']);
                        console.log(tmpSessionConfig);
                        console.log(tmpSessionConfig['sessionStoreSession']);
                        
                        if('sessionStoreSession' in tmpSessionConfig) {
                            tmpLastSessionConfig["session"] = tmpSessionConfig['sessionStoreSession'];
                        } else {
                            tmpLastSessionConfig["session"] = {}
                        }

                        if('sessionStoreApp' in tmpSessionConfig) {
                            tmpLastSessionConfig["app"] = tmpSessionConfig['sessionStoreApp'];
                        } else {
                            tmpLastSessionConfig["app"] = {}
                        }
                    }
                    
                    console.log("Last Config:", tmpLastSessionConfig);
                    // this.sess.$patch({'startupAppConfig': JSON.parse(message['session']['config'])['sessionStoreSession']})
                    // console.log(tmpLastSessionConfig.name, tmpLastSessionConfig.id);
                    // if(this.sess.session.name !== tmpLastSessionConfig.name) {
                    //     console.log("Last session used was different: ", tmpLastSessionConfig);
                        
                    // }
                    // console.log(message['session']);
                    
                    // console.log(this.sess.startupAppConfig);
                }
                
                if(message['session'].name != null) {
                    // console.log(this.sess.session);
                    this.isSessionActive = true
                    this.newSessionName = ""
                    this.selectedSession = ""
                }
                // this.$router.push({path: '/settings'})
                
            } else if( message['action'] === "clearActiveSession") {
                this.isSessionActive = message['status']
            } else if( message['action'] === "deleteSession") {
                if(message['message']) {
                    console.log(this.sessionList);
                    
                    const newSessionList = this.sessionList.filter((item) => item.id != message['session']);
                    console.log("Index:", newSessionList);
                    this.sessionList = newSessionList;
                    if(this.selectedSession && this.selectedSession.id == message['session']) {
                        console.log("Resetting selected session");
                        
                        this.selectedSession = null;
                    }
                    // this.sessionList.splice(this.sessionList.indexOf(sessionIndex), 1);
                } else {

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
        deleteSession() {
            if(!this.selectedSession || this.selectedSession == "") {
                alert("No session selected!")
            } else {
                console.log(this.selectedSession)
                this.ws.send(JSON.stringify({'action': 'deleteSession', 'session': this.selectedSession}))
            }
        },
        clearActiveSession() {
            this.ws.send(JSON.stringify({'action': 'clearActiveSession'}))
        },
        createNewSession() {
            this.ws.send(JSON.stringify({'action': 'createNewSession', 'name': this.newSessionName}))
        },
        chooseExistingSession() {
            this.sess.$patch({'session': {'name': this.selectedSession.name, 'id': this.selectedSession.id}})
            this.ws.send(JSON.stringify({'action': 'chooseSession', 'session': this.selectedSession}))
            this.isSessionActive = true
        }
    }
});
</script>
<style>
#sessionSelection {
    position: relative;
}
#sessionSelection.disabled::before {
    border-radius: 10px;
    position: absolute;
    left: 0;
    top: 0;
    background-color: #aaa3;
    z-index: 800;
    display: block;
    content: '';
    height: 100%;
    width: 100%;
}
.page-dashboard {
    width: 100%;
    height: 100vh !important;
    display: flex;
    background-color: #eee !important;
    justify-content: center;
    align-items: center;
}
h2 {
    font-size: 30px;
    font-variant: small-caps;
    font-weight: 600;
    font-family: "Fira Code";
    color: #666;
}
</style>