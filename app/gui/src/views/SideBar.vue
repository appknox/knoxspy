<template>
    <Toast />
    <div class="sidebar" :class="{'active': isSidebarOpen}">
        <div class="sidebar-header">
            <Button v-shortkey="['meta', 'l']" @shortkey="toggleSidebar" :icon="isSidebarOpen ? 'pi pi-times' : 'pi pi-angle-right'" rounded aria-label="Submit" @click="toggleSidebar" />
            <h1 :class="{'active': isSidebarOpen}">KnoxSpy</h1>
        </div>
        <ul>
            <li><router-link to="/"><i class="pi pi-home" style="margin-right: 10px"></i><span :class="{'active': isSidebarOpen}">Sessions</span></router-link></li>
            <li><router-link to="/apps"><i class="pi pi-th-large" style="margin-right: 10px"></i><span :class="{'active': isSidebarOpen}">Apps</span></router-link></li>
            <li><router-link to="/traffic"><i class="pi pi-history mr-2" style="margin-right: 10px"></i><span :class="{'active': isSidebarOpen}">HTTP Traffic</span></router-link></li>
            <li><router-link to="/libraries"><i class="pi pi-folder mr-2" style="margin-right: 10px"></i><span :class="{'active': isSidebarOpen}">Libraries</span></router-link></li>
        </ul>
    </div>
    <div id="splash-screen">
        <div class="card">
            <div class="loader">
                <p style="margin: 0">loading</p>
                <div class="words">
                <span class="word">sessions</span>
                <span class="word">devices</span>
                <span class="word">users</span>
                <span class="word">apps</span>
                <span class="word">libraries</span>
                </div>
            </div>
        </div>
    </div>
</template>

<script lang="ts">
import { defineComponent, watch } from "vue";
import Button from "primevue/button";
import InlineMessage from 'primevue/inlineMessage';
import { useAppStore, useWebSocketStore } from "../stores/session";
import OverlayPanel from 'primevue/overlaypanel';
import Toast from 'primevue/toast';
import Dropdown from 'primevue/dropdown';
import Tag from 'primevue/tag';

export default defineComponent({
	name: 'SideBar',
    data() {
        return {
            cs: useAppStore(),
            ws: useWebSocketStore(),
            isSidebarOpen: false,
        }
    },
    components: {
        Toast,
        Button,
        InlineMessage,
        OverlayPanel,
        Dropdown,
        Tag
    },
    created() {
        this.ws.addOnOpenHandler(this.wsReady)
        this.ws.addOnMessageHandler(this.handleMessage)
        window.addEventListener('beforeunload', this.handleReload)

        watch(() => this.cs.getStatus.dashboardStatus, (newVal, oldVal) => {
            if (newVal) {
                document.getElementById('splash-screen')?.classList.add('hidden');
            }
        })
    },
    methods: {
        wsReady() {
            console.log("SideBar: WebSocket ready");
        },
        handleMessage(message: any) {
            message = JSON.parse(message);
        },
        toggleSidebar() {            
            this.cs.setStatusKey("sidebarStatus", !this.isSidebarOpen);
            this.isSidebarOpen = !this.isSidebarOpen;
        },
        handleReload(event: any) {
            // event.preventDefault();
            console.log("Reloading");
            // this.currentSession.dump();
        },
        showSticky(message: string, header: string, type: string) {
            console.log("showSticky", message, header, type);
            this.$toast.add({ severity: type as any, summary: header, detail: message, life: 3000});
        },
        showConnectedApp(event: any) {
            this.$router.push('/apps/connected');
        }
    }
});
</script>

<style scoped>
.bottom-bar {
    box-shadow: -10px 0 15px -10px #333;
    position: fixed;
    bottom: 0;
    z-index: 1000;
    left: 51px;
    width: calc(100% - 52px);
    height: 35px;
    background-color: #d3d9e4;
    display: flex;
    gap: 10px;
    padding: 0 10px;
}
.highlight {
    background-color: rgba(248, 113, 113, 0.3)  !important;
    border: 1px solid rgba(248, 113, 113, 0.7);
    border-radius: 4px;
    padding: 0.2rem;
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
    z-index: 1001;
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
    z-index: 10003;
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
    white-space: nowrap;
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



#splash-screen {
	position: fixed;
    left: 0px;
    top: 0;
    height: 100%;
    width: 100%;
    background-color: #fff;
    z-index: 11000;
	display: flex;
    justify-content: center;
    align-content: center;
    flex-wrap: wrap;
}
#splash-screen.hidden {
    display: none;
}

#splash-screen .card {
  /* color used to softly clip top and bottom of the .words container */
  /* --bg-color: #111; */
  /* background-color: var(--bg-color); */
  padding: 1rem 2rem;
  border-radius: 1.25rem;
  width: 300px;
  
}
#splash-screen .loader {
  color: rgb(124, 124, 124);
  font-family: "Poppins", sans-serif;
  font-weight: 500;
  font-size: 25px;
  -webkit-box-sizing: content-box;
  box-sizing: content-box;
  height: 40px;
  padding: 10px 10px;
  display: -webkit-box;
  display: -ms-flexbox;
  display: flex;
  border-radius: 8px;
}

#splash-screen .words {
  overflow: hidden;
  position: relative;
}
#splash-screen .words::after {
  content: "";
  position: absolute;
  inset: 0;
  background: linear-gradient(
    var(--bg-color) 10%,
    transparent 30%,
    transparent 70%,
    var(--bg-color) 90%
  );
  z-index: 20;
}

#splash-screen .word {
  display: block;
  height: 100%;
  padding-left: 6px;
  color: var(--primary-color);
  animation: spin_4991 4s infinite;
}

@keyframes spin_4991 {
  10% {
    -webkit-transform: translateY(-102%);
    transform: translateY(-102%);
  }

  25% {
    -webkit-transform: translateY(-100%);
    transform: translateY(-100%);
  }

  35% {
    -webkit-transform: translateY(-202%);
    transform: translateY(-202%);
  }

  50% {
    -webkit-transform: translateY(-200%);
    transform: translateY(-200%);
  }

  60% {
    -webkit-transform: translateY(-302%);
    transform: translateY(-302%);
  }

  75% {
    -webkit-transform: translateY(-300%);
    transform: translateY(-300%);
  }

  85% {
    -webkit-transform: translateY(-402%);
    transform: translateY(-402%);
  }

  100% {
    -webkit-transform: translateY(-400%);
    transform: translateY(-400%);
  }
}

</style>