<template>
    <Footer @sessionUpdated="refreshSessionInfo"></Footer>
    <div class="page page-dashboard">
        <Card style="width: 40rem; overflow: hidden">
            <template #header>
                <h2 style="border-bottom: 1px solid #eee; padding-bottom: 20px; margin-bottom: 0">Sessions</h2>
            </template>
            <template #content>
                <Message severity="info" v-if="currentSession.app.isSessionActive" :closable="false">
                    <template #messageicon>
                        <i class="pi pi-info-circle" style="margin-right: 10px;"></i>
                    </template>
                    <span class="ml-2" style="line-height: 38px;"><b>'{{currentSession.app.selectedSession ? currentSession.app.selectedSession.name : 'No session selected'}}'</b> session is currently in use!</span>
                    <Button severity="danger" label="Disconnect" text style="margin-left: 20px;" @click="clearActiveSession"/>
                    <Button severity="success" label="Open" text style="margin-left: 20px;" @click="openAppsPage"/>
                </Message>
                <div style="display: flex; align-items: start; border-radius: 10px" id="sessionSelection" :class="currentSession.app.isSessionActive ? 'disabled' : ''">
                    <div style="display: flex; flex-direction: column; flex-grow: 1; flex-basis: 0; padding: 20px; ">
                        <p class="m-0">
                            Create A New Session
                        </p>
                        <div style="gap: 10px; display: flex; flex-direction: column;">
                            <InputText v-model="newSessionName" placeholder="Session Name" autocomplete="off"/>
                            <Button label="Create New" size="small" @click="createNewSession"/>
                        </div>
                    </div>
                    <div style="flex-grow: 1; flex-basis: 0; padding: 20px;border-left: 1px solid #eee;">
                        <p class="m-0">
                            Choose An Existing One
                        </p>
                        <Listbox v-model="currentSession.app.selectedSession" :options="currentSession.app.sessionsList" optionLabel="name" class="w-full md:w-14rem" style="max-height: 200px; overflow-y: scroll;" />
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
import { useAppStore, useWebSocketStore, usePageReadyEmitter } from '../stores/session';
import Message from 'primevue/message';
import Toast from 'primevue/toast';
import Footer from '../components/Footer.vue';

export default defineComponent({
    name: 'DashboardPage',
    components: {
        Listbox,
        Card,
        Button,
        InputText,
        Message,
        Toast,
        Footer
    },
    data() {
        return {
            currentSession: useAppStore(),
            ws: useWebSocketStore(),
            newSessionName: '',
            emitter: usePageReadyEmitter()
        }
    },
    created() {
        this.ws.addOnOpenHandler(this.wsReady)
        this.ws.addOnMessageHandler(this.wsMessage)
    },
    mounted() {
    },
    methods: {
        wsReady() {
            console.log("DashboardPage: WebSocket ready");
            this.ws.send(JSON.stringify({'action': 'sessions'}))
            this.ws.send(JSON.stringify({'action': 'getActiveSession'}))
        },
        wsMessage(message: any) {
            message = JSON.parse(message)
            console.log("DashboardPage: WebSocket message", message);
            if(message.action == 'sessionList') {
                this.currentSession.app.sessionsList = message.sessions
                console.log("Sessions:", this.currentSession.app.sessionsList)
            } else if(message.action == 'clearActiveSession') {
                if(message.status) {
                    this.currentSession.clearSelectedSession()
                    this.currentSession.app.isSessionActive = false
                    this.currentSession.app.selectedSession = null
                }
            } else if(message.action == 'activeSession') {
                this.currentSession.app.isSessionActive = true
                this.currentSession.app.selectedSession = message.session
                console.log("Active session:", this.currentSession.app.selectedSession);
                this.currentSession.setSelectedSession(this.currentSession.app.selectedSession)
                if(message.created) {
                    this.newSessionName = ''
                    this.ws.send(JSON.stringify({'action': 'sessions'}))
                }
            } else if(message.action == 'deleteSession') {
                if(message.status) {
                    this.currentSession.app.selectedSession = null
                    this.currentSession.app.sessionsList = this.currentSession.app.sessionsList.filter((session: any) => session.id !== message.session)
                    if(this.currentSession.app.sessionsList.length == 0) {
                        localStorage.removeItem('selectedSession')
                    }
                }
            }
        },
        pageReady(session: any) {
            console.log("DashboardPage: Page ready", session);
            this.ws.send(JSON.stringify({'action': 'sessions'}))
            this.ws.send(JSON.stringify({'action': 'getActiveSession'}))
        },
        openAppsPage() {
            this.$router.push('/apps');
        },
        deleteSession() {
            if(!this.currentSession.app.selectedSession || this.currentSession.app.selectedSession == "") {
                alert("No session selected!")
            } else {
                console.log(this.currentSession.app.selectedSession)
                this.ws.send(JSON.stringify({'action': 'deleteSession', 'session': this.currentSession.app.selectedSession}))
            }
        },
        clearActiveSession() {
            this.ws.send(JSON.stringify({'action': 'clearActiveSession'}))
        },
        createNewSession() {
            this.ws.send(JSON.stringify({'action': 'createNewSession', 'name': this.newSessionName}))
        },
        chooseExistingSession() {
            this.currentSession.app.selectedSession = this.currentSession.app.sessionsList.find((session: any) => session.id === this.currentSession.app.selectedSession.id)
            this.ws.send(JSON.stringify({'action': 'chooseSession', 'session': this.currentSession.app.selectedSession}))
            this.currentSession.setSelectedSession(this.currentSession.app.selectedSession)
            this.currentSession.app.isSessionActive = true
        },
        refreshSessionInfo() {
            console.log("DashboardPage: Refresh session info");
            
        }
    },
    unmounted() {
        console.log("Unmounting DashboardPage");
        this.ws.removeMessageCallback(this.wsMessage);
        this.ws.removeOpenCallback(this.wsReady);
    },
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