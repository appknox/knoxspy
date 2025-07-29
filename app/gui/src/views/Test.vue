<template>
    <Header></Header>
    <div class="page" style="text-align: center;">
        <h1>Test</h1>
        <p>Current session: {{ currentSession.app.selectedSession ? currentSession.app.selectedSession.name : 'No session selected' }}</p>
    </div>
</template>

<script lang="ts">
import { defineComponent } from "vue";
import { useAppStore, useWebSocketStore, usePageReadyEmitter } from "../stores/session";
import Header from '../components/Footer.vue';

export default defineComponent({
    name: "Test",
    components: {
        Header
    },
    data() {
        return {
            currentSession: useAppStore(),
            ws: useWebSocketStore(),
            emitter: usePageReadyEmitter()
        };
    },
    created() {
        this.ws.addOnOpenHandler(this.wsReady)
    },
    mounted() {
    },
    methods: {
        wsReady() {
            console.log("Test: WebSocket ready");
        },
        pageReady() {
            console.log("Test: Page ready");
        }
    }
});
</script>

<style scoped>

</style>