<template>
    <Footer @dashboardReady="dashboardReady"></Footer>
    <div class="page page-dashboard">
        <Card style="width: 40rem; overflow: hidden">
            <template #header>
                <h2 style="border-bottom: 1px solid #eee; padding-bottom: 20px; margin-bottom: 0">Sessions</h2>
            </template>
            <template #content>
                <Message severity="info" v-if="cs.getStatus.sessionStatus" :closable="false">
                    <template #messageicon>
                        <i class="pi pi-info-circle" style="margin-right: 10px;"></i>
                    </template>
                    <span class="ml-2" style="line-height: 38px;"><b>'{{cs.getSelection.session ? cs.getSelection.session.name : 'No session selected'}}'</b> session is currently in use!</span>
                    <Button severity="danger" label="Disconnect" text style="margin-left: 20px;" @click="sessionActions().clear"/>
                    <Button severity="success" label="Open" text style="margin-left: 20px;" @click="sessionActions().open"/>
                </Message>
                <div style="display: flex; align-items: start; border-radius: 10px" id="sessionSelection" :class="cs.getStatus.sessionStatus ? 'disabled' : ''">
                    <div style="display: flex; flex-direction: column; flex-grow: 1; flex-basis: 0; padding: 20px; ">
                        <p class="m-0">
                            Create A New Session
                        </p>
                        <div style="gap: 10px; display: flex; flex-direction: column;">
                            <InputText v-model="newSessionName" placeholder="Session Name" />
                            <Button label="Create New" size="small" @click="sessionActions().create"/>
                        </div>
                    </div>
                    <div style="flex-grow: 1; flex-basis: 0; padding: 20px;border-left: 1px solid #eee;">
                        <p class="m-0">
                            Choose An Existing One
                        </p>
                        <Listbox v-model="cs.getSelection.session" :options="cs.getData.sessions" optionLabel="name" class="w-full md:w-14rem" listStyle="max-height:250px; overflow-y: scroll; scrollbar-width: none; -ms-overflow-style: none;">
                            <template #option="slotProps" v-if="sessionsLoaded && cs.getData.sessions.length > 0">
                                <div class="flex align-items-center">
                                    <div>{{ slotProps.option.name }}</div>
                                </div>
                            </template>
                            <template #empty>
                                <div class="flex align-items-center" v-if="sessionsLoaded">
                                    <div>No sessions available</div>
                                </div>
                                <div class="flex align-items-center" v-else>
                                    <ProgressSpinner style="width: 40px; height: 40px" />
                                </div>
                            </template>
                        </Listbox>
                        <div style="display: flex; gap: 10px; justify-content: center">
                            <Button icon="pi pi-times" size="small" severity="danger" label="Delete" style="margin-top: 10px;" @click="sessionActions().delete"/>
                            <Button icon="pi pi-check" size="small" label="Choose" style="margin-top: 10px;" @click="sessionActions().choose"/>
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
import { useAppStore, useWebSocketStore } from '../stores/session';
import Message from 'primevue/message';
import Toast from 'primevue/toast';
import Footer from '../components/Footer.vue';
import ProgressSpinner from 'primevue/progressspinner';

export default defineComponent({
    name: 'Sessions',
    components: {
        Listbox,
        Card,
        Button,
        InputText,
        Message,
        Toast,
        Footer,
        ProgressSpinner
    },
    data() {
        return {
            cs: useAppStore(),
            ws: useWebSocketStore(),
            newSessionName: '',
            sessionsLoaded: false,
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
            console.log("Sessions: WebSocket ready");
        },
        wsMessage(message: any) {
            message = JSON.parse(message)
            console.log("Sessions: WebSocket message", message);
            if(message.action == "session.create.ack") {
                if(message.created) {
                    this.$toast.add({ severity: 'success', summary: 'Session Created', detail: 'Session created successfully', life: 3000 });
                    this.newSessionName = ''
                } else {
                    this.$toast.add({ severity: 'error', summary: 'Session Creation Failed', detail: 'Failed to create session', life: 3000 });
                }
                this.cs.getData.sessions.push(message.session)
            } else if(message.action == "session.choose.ack") {
                this.cs.setStatusKey("sessionStatus", true)
            } else if(message.action == "session.delete.ack") {
                this.cs.getData.sessions = this.cs.getData.sessions.filter((session: any) => session.id != message.session)
            } else if(message.action == "session.clear.ack") {
                this.cs.setStatusKey("sessionStatus", false)
                this.cs.setSelectionKey("session", {});
            }
        },
        dashboardReady(status: boolean) {
            console.log("Sessions: Dashboard ready", status);
            if(status) {
                this.sessionsLoaded = true
            }
            console.log("Sessions: Session ready", this.sessionsLoaded);
        },
        sessionActions() {
            return {
                open: () => {
                    console.log("Sessions(sessionActions.open): Opening apps page");
                    this.$router.push({ path: '/apps' });
                },
                create: () => {
                    console.log("Sessions(sessionActions.create): Creating session");
                    this.ws.send(JSON.stringify({
                        action: "session.create",
                        name: this.newSessionName
                    }));
                },
                delete: () => {
                    console.log("Sessions(sessionActions.delete): Deleting session");
                    this.ws.send(JSON.stringify({
                        action: "session.delete",
                        session: this.cs.getSelection.session
                    }));
                },
                choose: () => {
                    console.log("Sessions(sessionActions.choose): Choosing session");
                    this.ws.send(JSON.stringify({
                        action: "session.choose",
                        session: this.cs.getSelection.session
                    }));
                },
                clear: () => {
                    console.log("Sessions(sessionActions.clear): Clearing session");
                    this.ws.send(JSON.stringify({
                        action: "session.clear",
                        session: this.cs.getSelection.session
                    }));
                },
            }
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