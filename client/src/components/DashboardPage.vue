
<template>
    <div class="page page-dashboard">
        <Toast />
        <Card style="width: 40rem; overflow: hidden">
            <template #header>
                <h2 style="border-bottom: 1px solid #eee; padding-bottom: 20px; margin-bottom: 0">Sessions</h2>
            </template>
            <template #content>
                <Message severity="info" v-if="isSessionActive">
                    <template #messageicon>
                        <i class="pi pi-cog" style="margin-right: 10px;"></i>
                    </template>
                    <span class="ml-2"><b>'{{sess.session.name}}'</b> session is currently in use!</span>
                    <!-- <Button severity="danger" label="Disconnect"/> -->
                </Message>
                <div style="display: flex; align-items: start;">
                    <div style="display: flex; flex-direction: column; flex-grow: 1; flex-basis: 0; padding: 20px; ">
                        <p class="m-0">
                            Create A New Session
                        </p>
                        <div style="gap: 10px; display: flex; flex-direction: column;">
                            <InputText v-model="newSessionName" placeholder="Session Name" />
                            <Button label="Create New" @click="createNewSession"/>
                        </div>
                    </div>
                    <div style="flex-grow: 1; flex-basis: 0; padding: 20px;border-left: 1px solid #eee;">
                        <p class="m-0">
                            Choose An Existing One
                        </p>
                        <Listbox v-model="selectedSession" :options="sessionList" optionLabel="name" class="w-full md:w-14rem" style="" />
                        <Button label="Choose" style="margin-top: 10px;" @click="chooseExistingSession"/>
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
                // console.log(message['session']);
                this.sess.$patch({'session': message['session']})
                if(message['session'].name != null) {
                    // console.log(this.sess.session);
                    this.isSessionActive = true
                }
                //this.$router.push({path: '/traffic'})
                
            }
        };

        this.ws.onerror = (error: any) => {
            console.error('WebSocket error:', error);
        };

        this.ws.onclose = () => {
            console.log('WebSocket connection closed');
        };
    },
    methods: {
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