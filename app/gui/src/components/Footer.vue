<template>
	<div class="status-indicator-wrapper">
		<div class="status-group status-group-left">
			<div class="status-item" data-tooltip="Websocket Server">
				<div class="status-badge" :class=" ws.isConnected ? 'status-badge-green' : 'status-badge-red'">
					<div class="status-icon">
						<svg v-if="ws.isConnected" xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-gray-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
							<path stroke-linecap="round" stroke-linejoin="round" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
						</svg>
						<svg v-else xmlns="http://www.w3.org/2000/svg" class="h-* w-* text-gray-500 flex-shrink-0 spin-svg" fill="none" viewBox="0 0 16 16" stroke="currentColor" stroke-width="1">
							<path fill-rule="evenodd" d="M8 3a5 5 0 1 0 4.546 2.914.5.5 0 0 1 .908-.417A6 6 0 1 1 8 2z"/>
							<path d="M8 4.466V.534a.25.25 0 0 1 .41-.192l2.36 1.966c.12.1.12.284 0 .384L8.41 4.658A.25.25 0 0 1 8 4.466"/>
						</svg>
					</div>
					<div class="status-text">	
						<span><b style="color: #ddd">Server</b></span>
						<!-- <span>{{ ws.isConnected ? 'Conn.' : 'Connecting..' }}</span> -->
						<span>
							<svg v-if="ws.isConnected" xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="#fff" class="bi bi-check2" viewBox="0 0 16 16">
								<path d="M13.854 3.646a.5.5 0 0 1 0 .708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0"/>
							</svg>
							<svg v-else xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="#fff" class="bi bi-x" viewBox="0 0 16 16">
								<path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708"/>
							</svg>
						</span>
					</div>
				</div>
			</div>
			<div class="status-item" data-tooltip="App Connection">
				<div class="status-badge" :class="cs.getStatus.appStatus ? 'status-badge-green' : 'status-badge-red'">
					<div class="status-icon">
						<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="size-6">
							<path stroke-linecap="round" stroke-linejoin="round" d="M10.5 1.5H8.25A2.25 2.25 0 0 0 6 3.75v16.5a2.25 2.25 0 0 0 2.25 2.25h7.5A2.25 2.25 0 0 0 18 20.25V3.75a2.25 2.25 0 0 0-2.25-2.25H13.5m-3 0V3h3V1.5m-3 0h3m-3 18.75h3" />
						</svg>
					</div>
					<div class="status-text" @click="showConnectedApp()">	
						<span><b style="color: #ddd">App</b></span>
						<!-- <span>{{ cs.getStatus.appStatus ? 'Conn.' : 'Not Conn.' }}</span> -->
						<span>
							<svg v-if="cs.getStatus.appStatus" xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="#fff" class="bi bi-check2" viewBox="0 0 16 16">
								<path d="M13.854 3.646a.5.5 0 0 1 0 .708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0"/>
							</svg>
							<svg v-else xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="#fff" class="bi bi-x" viewBox="0 0 16 16">
								<path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708"/>
							</svg>
						</span>
					</div>
				</div>
			</div>
		</div>

		<div class="separator"></div>

		<div class="status-group status-group-right" style="flex-grow: 1;">
			<div class="status-item" data-tooltip="Selected Session" @click="toggleDropdown('session')" :class="showDropdown.session ? 'status-item-highlighted' : ''">
				<div class="status-badge" :class="cs.getSelection.session ? 'status-badge-blue' : 'status-badge-light-blue'">
					<div class="status-icon">
						<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-gray-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" d="M15.75 6a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0ZM4.501 20.118a7.5 7.5 0 0 1 14.998 0A17.933 17.933 0 0 1 12 21.75c-2.676 0-5.216-.584-7.499-1.632Z" />
						</svg>
					</div>
					<div class="status-text">	
						<span><b style="color: #ccc">Session: </b></span>
						<span>{{ cs.getStatus.sessionStatus ? (cs.getSelection.session.name ? cs.getSelection.session.name : '-') : '-' }}</span>
					</div>
					<div class="status-arrow">
						<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="size-6">
							<path stroke-linecap="round" stroke-linejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
						</svg>
					</div>
				</div>
				<div class="bottom-bar-dropdown" v-if="showDropdown.session">
					<ul>
						<li v-for="session in cs.getData.sessions" :key="session.id" @click="toggleDropdownItem('session', session.id)">
							• {{ session.name }}
						</li>
					</ul>
				</div>
			</div>
			<div class="status-item" data-tooltip="Selected Device" @click="toggleDropdown('device')" :class="showDropdown.device ? 'status-item-highlighted' : ''">
				<div class="status-badge" :class="cs.getSelection.device ? 'status-badge-blue' : 'status-badge-light-blue'">
					<div class="status-icon">
						<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="size-6">
							<path stroke-linecap="round" stroke-linejoin="round" d="M10.5 1.5H8.25A2.25 2.25 0 0 0 6 3.75v16.5a2.25 2.25 0 0 0 2.25 2.25h7.5A2.25 2.25 0 0 0 18 20.25V3.75a2.25 2.25 0 0 0-2.25-2.25H13.5m-3 0V3h3V1.5m-3 0h3m-3 18.75h3" />
						</svg>
					</div>
					<div class="status-text">	
						<span><b style="color: #ccc">Device: </b></span>
						<span>{{ cs.getSelection.device.id ? cs.getSelection.device.name : '-' }}</span>
					</div>
					<div class="status-arrow">
						<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="size-6">
							<path stroke-linecap="round" stroke-linejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
						</svg>
					</div>
				</div>
				<div class="bottom-bar-dropdown" v-if="showDropdown.device">
					<ul>
						<li v-for="device in cs.getData.devices" :key="device.id" @click="toggleDropdownItem('device', device.id)">
							• {{ device.name }}
						</li>
					</ul>
				</div>
			</div>
			<div class="status-item app-status-item" data-tooltip="Selected App" @click="" :class="showDropdown.app ? 'status-item-highlighted' : ''">
				<div class="status-badge" :class="cs.getSelection.app ? 'status-badge-blue' : 'status-badge-light-blue'">
					<div class="status-icon">
						<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-gray-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" d="M3.75 6A2.25 2.25 0 0 1 6 3.75h2.25A2.25 2.25 0 0 1 10.5 6v2.25a2.25 2.25 0 0 1-2.25 2.25H6a2.25 2.25 0 0 1-2.25-2.25V6ZM3.75 15.75A2.25 2.25 0 0 1 6 13.5h2.25a2.25 2.25 0 0 1 2.25 2.25V18a2.25 2.25 0 0 1-2.25 2.25H6a2.25 2.25 0 0 1-2.25-2.25v-2.25ZM13.5 6a2.25 2.25 0 0 1 2.25-2.25H18A2.25 2.25 0 0 1 20.25 6v2.25A2.25 2.25 0 0 1 18 10.5h-2.25a2.25 2.25 0 0 1-2.25-2.25V6ZM13.5 15.75a2.25 2.25 0 0 1 2.25-2.25H18a2.25 2.25 0 0 1 2.25 2.25V18A2.25 2.25 0 0 1 18 20.25h-2.25A2.25 2.25 0 0 1 13.5 18v-2.25Z" />
						</svg>
					</div>
					<div class="status-text">
						<span><b style="color: #ccc">App: </b></span>
						<span style="">{{ cs.getSelection.app.name ? cs.getSelection.app.name : '-' }}</span>
					</div>
					<div class="status-arrow" style="display: none">
						<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="size-6">
							<path stroke-linecap="round" stroke-linejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
						</svg>
					</div>
				</div>
				<div class="bottom-bar-dropdown" v-if="showDropdown.app" style="max-height: 200px; overflow-y: scroll; overflow-x: hidden">
					<ul>
						<li v-for="app in cs.getSelection.apps" :key="app.id" @click="toggleDropdownItem('app', app.id)">
							• {{ app.name }}
						</li>
					</ul>
				</div>
			</div>
			<div class="status-item" data-tooltip="Selected Platform" :class="showDropdown.platform ? 'status-item-highlighted' : ''">
				<div class="status-badge" :class="cs.getSelection.platform ? 'status-badge-blue' : 'status-badge-light-blue'">
					<div class="status-icon">
						<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-gray-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" d="M8.25 3v1.5M4.5 8.25H3m18 0h-1.5M4.5 12H3m18 0h-1.5m-15 3.75H3m18 0h-1.5M8.25 19.5V21M12 3v1.5m0 15V21m3.75-18v1.5m0 15V21m-9-1.5h10.5a2.25 2.25 0 0 0 2.25-2.25V6.75a2.25 2.25 0 0 0-2.25-2.25H6.75A2.25 2.25 0 0 0 4.5 6.75v10.5a2.25 2.25 0 0 0 2.25 2.25Zm.75-12h9v9h-9v-9Z" />
						</svg>
					</div>
					<div class="status-text">
						<span ><b style="color: #ccc">Platform: </b></span>
						<span>{{ cs.getSelection.platform ? cs.getSelection.platform : '-' }}</span>
					</div>
				</div>
			</div>
			<div class="status-item" data-tooltip="Selected Library" @click="toggleDropdown('library')" :class="showDropdown.library ? 'status-item-highlighted' : ''">
				<div class="status-badge" :class="cs.getSelection.library ? 'status-badge-blue' : 'status-badge-light-blue'">
					<div class="status-icon">
						<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-gray-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" d="M17.25 6.75 22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3-4.5 16.5" />
						</svg>
					</div>
					<div class="status-text">
						<span ><b style="color: #ccc">Library: </b></span>
						<span>{{ cs.getSelection.library.file ? cs.getSelection.library.file : '-' }}</span>
					</div>
					<div class="status-arrow">
						<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="size-6">
							<path stroke-linecap="round" stroke-linejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
						</svg>
					</div>
				</div>
				<div class="bottom-bar-dropdown" v-if="showDropdown.library">
					<ul>
						<li v-for="library in cs.getData.libraries" :key="library.id" @click="toggleDropdownItem('library', library.file)">
							• {{ library.name }}
						</li>
					</ul>
				</div>
			</div>
		</div>
	</div>
</template>

<script>
import { defineComponent, watch } from "vue";
import { useAppStore, useWebSocketStore } from "../stores/session";
import InlineMessage from "primevue/inlineMessage";

/** ToDo
- On clicking App Connection, check if data is loaded or not for app to launch
- 
*/

export default defineComponent({
	emits: ["dashboardReady"],
	name: "Footer",
	data() {
        return {
            cs: useAppStore(),
			ws: useWebSocketStore(),
			didPageLoad: false,
			showDropdown: {
				session: false,
				device: false,
				app: false,
				platform: false,
				library: false
			},
			loadingDropdown: {
				session: false,
				device: false,
				app: false,
				platform: false,
				library: false
			},
		};
	},
	components: {
		InlineMessage
	},
	created() {
		this.ws.addOnOpenHandler(this.wsReady);
		this.ws.addOnMessageHandler(this.wsMessage);
	},
	mounted() {
		watch(() => this.cs.getStatus.sidebarStatus, (newVal, oldVal) => {
			if(newVal) {
				document.getElementsByClassName("status-indicator-wrapper")[0].classList.add("shrink");
			} else {
				document.getElementsByClassName("status-indicator-wrapper")[0].classList.remove("shrink");
			}
		});
	},
	methods: {
		toggleDropdown(key) {
			this.showDropdown[key] = !this.showDropdown[key];
			if (this.showDropdown[key]) {
				this.populateDropdown(key);
			}
		},
		toggleDropdownItem(key, id) {
			if(key === "session") {
				const t_sess = this.cs.getData.sessions.find(session => session.id === id);
				this.ws.send(JSON.stringify({ action: "session.choose", session: t_sess}));
			} else if(key === "device") {
				const t_device = this.cs.getData.devices.find(device => device.id === id);
				console.log("Footer(toggleDropdownItem): Device selected:", t_device);
				this.cs.setSelectionKey("device", t_device);
				const t_platform = t_device.platform;
				this.cs.setSelectionKey("platform", t_platform);
				let t_apps = [];
				if(t_platform.toLowerCase() === "android") {
					t_apps = t_device.users.filter(user => user.id == "0")[0].apps;
					this.cs.setDataKey("users", t_device.users);
					this.cs.setSelectionKey("user", t_device.users.filter(user => user.id == "0")[0]);
				} else {
					t_apps = t_device.users[0];
					this.cs.setDataKey("users", []);
					this.cs.setSelectionKey("user", {});
				}
				this.cs.setSelectionKey("apps", t_apps);
				console.log("Footer(toggleDropdownItem): Selected Data:", this.cs.getSelection, this.cs.getData);
				
			} else if(key === "app") {
				const t_app = this.cs.getSelection
				console.log("App selected:", t_app);
			} else if(key === "platform") {
				// this.currentSession.setSelectedPlatform(this.currentSession.app.platforms.find(platform => platform.id === id));
			} else if(key === "library") {
				const t_lib = this.cs.getData.libraries.find(lib => lib.file === id);
				this.ws.send(JSON.stringify({ action: "library.change", library: t_lib }));
			}
		},
		populateDropdown(key) {
			// if (key === "session") {
			// 	console.log("Footer(populateDropdown): Populating sessions");
			// 	this.ws.send(JSON.stringify({ action: "sessions" }));
			// } else if(key === "device") {
			// 	console.log("Footer(populateDropdown): Populating devices");
			// 	this.ws.send(JSON.stringify({ action: "devices" }));
			// } else if (key === "app") {
			// 	console.log("Footer(populateDropdown): Populating apps");
			// 	this.ws.send(JSON.stringify({ action: "apps" }));
			// } else if (key === "platform") {
			// 	console.log("Footer(populateDropdown): Populating platforms");
			// 	this.ws.send(JSON.stringify({ action: "platforms" }));
			// } else if (key === "library") {
			// 	console.log("Footer(populateDropdown): Populating libraries");
			// 	this.ws.send(JSON.stringify({ action: "libraries" }));
			// }
		},
		async showConnectedApp() {
			console.log("Footer(showConnectedApp): Data:", this.cs.getData);
			console.log("Footer(showConnectedApp): Selection:", this.cs.getSelection);
			
			await this.cs.syncConnectedApp();
			if(this.cs.getConnectedApp.status) {
				console.log("Footer(showConnectedApp): App is connected, but no app is selected");
				this.cs.setSelectionKey("app", this.cs.getConnectedApp.app);
				this.$router.push({ path: "/app", query: {...this.$route.query} });
			}
			if(this.cs.getSelection.app.id) {
				console.log("Footer(showConnectedApp): App is selected, navigating to app page");
				this.$router.push({ path: "/app", query: {...this.$route.query} });
			} else {
				this.$toast.add({ severity: 'warn', summary: 'Warning', detail: 'No app selected', life: 3000 });
			}
		},
		async wsReady() {
			console.log("Footer(wsReady): WebSocket ready");
			this.ws.send(JSON.stringify({ action: "dashboard.init" }));
			await this.cs.syncConnectedApp();
		},
		async wsMessage(message) {
			message = JSON.parse(message);
			console.log("Footer(wsMessage): Message:", message, message.action);
			if (message.action == "dashboard.init.ack") {
				this.cs.setData(message.data);
				this.cs.setSelectionKey("session", message.data.activeSession);
				this.cs.setStatus({ dashboardStatus: true });
				if(message.data.activeSession && message.data.activeSession.id !== -1) {
					this.cs.setStatusKey("sessionStatus", true);
				}
				if(this.cs.checkRequiredQueryParams(this.$route.query)) {
					console.log("Footer(wsMessage): Query params are present");
					const t_result = this.cs.updateSelectionUsingQueryParams(this.$route.query);
					if(!t_result) {
						this.$router.push({ path: "/apps" })
					}
				} else if (this.cs.getConnectedApp.status) {
					console.log("Footer(wsMessage): Query params are not present, syncing from server");
					await this.cs.syncBackSelection(() => {
						this.$router.replace({
							query: {
								...this.$route.query,
								platform: this.cs.getSelection.platform,
								user: this.cs.getSelection.user.id || -1,
								device: this.cs.getSelection.device.id,
								app: this.cs.getSelection.app.id,
								library: this.cs.getSelection.library.file,
								action: this.cs.getSelection.action || "spawn"
							}
						})
					});
				} else if(message.data.devices.length > 0) {
					console.log("Footer(wsMessage): No query params, setting default device");
					this.cs.setDefaultDevice();
				}
				await this.cs.syncConnectedApp();
				const t_connectedApp = this.cs.getConnectedApp;
				if(t_connectedApp.status) {
					console.log("Footer(wsMessage): Connected App is ready");
					this.cs.setStatusKey("appStatus", true);
				}
				console.log("Footer(wsMessage): Dashboard ready", this.cs.getStatus.dashboardStatus);
				this.$emit("dashboardReady", this.cs.getStatus.dashboardStatus);
			} else if (message.action == "devices.init.ack") {
				console.log("Footer(wsMessage): Devices ready", message.data);
				this.cs.setDataKey("devices", message.data);
			} else if (message.action === "error.general") {
				console.log("Footer(wsMessage): Error", message.message);
				this.$toast.add({ severity: 'error', summary: 'Error', detail: message.message, life: 3000 });
			} else if (message.action === "apps.init.ack") {
				console.log("Footer(wsMessage): Apps ready", message.data);
				if(message.platform.toLowerCase() === "android") {
					this.cs.setDataKey("users", message.data);
					this.cs.setSelectionKey("user", message.data.filter(user => user.id == "0")[0]);
					this.cs.setSelectionKey("apps", message.data.filter(user => user.id == "0")[0].apps);
				} else {
					this.cs.setDataKey("apps", message.data[0]);
					this.cs.setDataKey("users", []);
				}
			} else if (message.action === "error.general") {
				console.log("Footer(wsMessage): Error", message.message);
				this.$toast.add({ severity: 'error', summary: 'Error', detail: message.message, life: 3000 });
			} else if (message.action === "error.json") {
				console.log("Footer(wsMessage): Error", message.message);
				for(let i = 0; i < message.message.length; i++) {
					this.$toast.add({ severity: 'error', summary: 'Error', detail: message.message[i], life: 3000 });
				}
			} else if (message.action === "general.ack") {
				console.log("Footer(wsMessage): General ack", message.message);
				this.$toast.add({ severity: 'success', summary: 'Info', detail: message.message, life: 3000 });
			} else if (message.action === "device.update") {
				console.log("Footer(wsMessage): Device update", message.message);
				if(message.message === "Connected") {
					this.cs.setStatusKey("appStatus", true);
					this.cs.setStatusKey("appConnectingStatus", false);
					this.cs.stopAppConnectionTimer();
					this.cs.syncConnectedApp();
					this.$toast.add({ severity: 'success', summary: 'Device Update', detail: message.extra, life: 3000 });
					// this.ws.send(JSON.stringify({ action: "dashboard.update", selection: this.cs.getSelection }));
				} else if(message.message === "Disconnected") {
					if(message.sessionId === this.cs.getSelection.sessionId) {
						this.$toast.add({ severity: 'warn', summary: 'Device Update', detail: "'" + message.appName + "' app disconnected", life: 3000 });
						// this.cs.setStatusKey("appStatus", false);
						this.cs.resetSelectedApp();
						console.log("Footer(wsMessage): Device disconnected, resetting app selection");
					} else {
						console.log("Footer(wsMessage): Device update for different session, ignoring. Existing sessionId:", this.cs.getSelection.sessionId, "Message sessionId:", message.sessionId);
					}
				}
			} else if (message.action === "app.connection") {
				console.log("Footer(wsMessage): App connection", message.message);
				this.cs.setStatusKey("appStatus", message.message);
			} else if (message.action === "session.choose.ack") {
				this.cs.setSelectionKey("session", message.session);
				this.ws.send(JSON.stringify({ action: "traffic.init", sessionId: message.session.id }));
				this.ws.send(JSON.stringify({ action: "repeater.init", sessionId: message.session.id }));
			} else if (message.action === "library.change.ack") {
				const t_lib = this.cs.getData.libraries.filter(lib => lib.file === message.library)[0];
				this.cs.setSelectionKey("library", t_lib);
				console.log("Footer(wsMessage): Library changed to", message.library, this.cs.getSelection);
				this.$router.replace({
					query: {
						...this.$route.query,
						library: t_lib.file,
					}
				});
			}
		},
	},
	unmounted() {
		console.log("Unmounting Header");
		this.ws.removeMessageCallback(this.wsMessage);
		this.ws.removeOpenCallback(this.wsReady);
	},
});
</script>

<style scoped>
.bottom-bar > div {
    cursor: pointer;
    border-radius: 0.375rem;
    padding: 0.10rem 0.5rem;
    margin: 0.30rem;
    transition-duration: 0.3s;
    display: flex; /* Use flexbox for horizontal alignment */
    align-items: center; /* Vertically center the content */
    flex: 1 1 25%;
    background-color: #e2e8f0;
}

.bottom-bar div:hover {
	color: #fff;
    background-color: #4b5563;
}

.bottom-bar h4 {
    font-size: .9rem;
    font-weight: 600;
    margin-right: 0.25rem;
}

.bottom-bar p {
    font-size: .9rem;
}
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
	display: none;
}
.highlight {
    background-color: rgba(248, 113, 113, 0.3)  !important;
    border: 1px solid rgba(248, 113, 113, 0.7);
    border-radius: 4px;
    padding: 0.2rem;
}

.bottom-bar-info {
	position: relative;
}
.bottom-bar-dropdown {
	position: absolute;
	bottom: calc(100% + 10px);
	width: 100%;
	left: 0;
	background-color: #4b5563;
	border: 1px solid #4b5563;
	border: 0;
	border-radius: 5px;
	box-shadow: 0 4px 6px rgba(0, 0, 0, 0.2);
	z-index: 1000;
	display: block; /* Hide by default */
}
.bottom-bar > div.highlight-dropdown-item {
	background-color: #4b5563;
	color: #fff;
	border-color: #4b5563 !important;
}
.bottom-bar-dropdown ul {
	list-style: none;
	padding: 0;
	margin: 0;
	border-radius: 5px;
}
.bottom-bar-dropdown li {
	padding: 0.5rem 1rem;
	border-radius: 5px;
	text-align: left;
	font-size: 13px;
	color: #fffe;
	cursor: pointer;
	margin: 5px;
	padding: 5px;
}
.bottom-bar-dropdown li:hover {
	background-color: #0004;
}
.bottom-bar-info:hover {
	background-color: #e2e8f0;
	border-color: #4b5563 !important;

}
.bottom-bar-info:hover .bottom-bar-dropdown {
	display: block; /* Show on hover */
}
.ws-info-disconnected {
	background-color: #dc2626 !important;
	color: #fff;
}
.bottom-bar-info.not-selected {
	border: 1px solid #dc2626;
}
.app-info ul,
.app-status-item ul {
	max-height: 200px;
	overflow-y: scroll;
  	-ms-overflow-style: none; /* IE and Edge */
  	scrollbar-width: none; /* Firefox */
}
.app-info ul::-webkit-scrollbar,
.app-status-item ul::-webkit-scrollbar {
  display: none;
}
/* svg {
 width: 2.25em;
 transform-origin: center;
 animation: rotate4 2s linear infinite;
 margin: 10px auto;
 display: block;
} */

circle {
 fill: none;
 stroke: #fffa;
 stroke-width: 4;
 stroke-dasharray: 1, 200;
 stroke-dashoffset: 0;
 stroke-linecap: round;
 animation: dash4 1.5s ease-in-out infinite;
}

.ws-info {
	background-color: #313949 !important;
	color: #fff;
}
.connection-info {
	background-color: #3f4d65 !important;
	color: #fff;
}

@keyframes rotate4 {
 100% {
  transform: rotate(360deg);
 }
}

@keyframes dash4 {
 0% {
  stroke-dasharray: 1, 200;
  stroke-dashoffset: 0;
 }

 50% {
  stroke-dasharray: 90, 200;
  stroke-dashoffset: -35px;
 }

 100% {
  stroke-dashoffset: -125px;
 }
}


@keyframes pulse {
	0%, 100% { opacity: 1; }
	50% { opacity: .5; }
}
.animate-pulse-custom {
	animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
}

/* Tooltip Styling */
[data-tooltip] {
	position: relative; /* Needed for absolute positioning of tooltip */
	cursor: default;
}
[data-tooltip]:hover::after {
	content: attr(data-tooltip);
	position: absolute;
	bottom: 125%;
	left: 50%;
	transform: translateX(-50%);
	margin-bottom: 5px;
	padding: 4px 8px;
	color: white;
	background-color: #374151; /* Equivalent to bg-gray-700 */
	border-radius: 4px; /* Equivalent to rounded */
	font-size: 0.75rem; /* Equivalent to text-xs */
	white-space: nowrap;
	z-index: 10;
	opacity: 1; /* Show on hover */
	visibility: visible;
	transition: opacity 0.2s ease-in-out, visibility 0.2s ease-in-out;
}
/* Initially hide tooltip */
[data-tooltip]::after {
	opacity: 0;
	visibility: hidden;
}


/* Modern Header Container - Light Theme */
.header-container {
	background-color: #ffffff; /* Equivalent to bg-white */
	color: #374151; /* Equivalent to text-gray-700 */
	padding: 0.75rem 1.5rem; /* Equivalent to p-3 px-6 */
	border-radius: 0.5rem; /* Equivalent to rounded-lg */
	box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px -1px rgba(0, 0, 0, 0.1); /* Equivalent to shadow-md */
	display: flex;
	justify-content: space-between;
	align-items: center;
	flex-wrap: wrap; /* Allow wrapping */
	gap: 1rem; /* Equivalent to gap-4 */
	border: 1px solid #e5e7eb; /* Equivalent to border border-gray-200 */
}

/* App Title */
.app-title {
	font-size: 1.125rem; /* Equivalent to text-lg */
	font-weight: 600; /* Equivalent to font-semibold */
	color: #1f2937; /* Equivalent to text-gray-800 */
}

/* Group for all status indicators */
.status-indicator-wrapper {
    background-color: #d3d9e4;
	background-color: #eee;
	border-top: 1px solid #dfdfdf;
    box-shadow: -10px 0 15px -10px #333;
    position: fixed;
    bottom: 0;
    z-index: 1000;
    left: 51px;
    width: calc(100% - 52px);
	display: flex;
	align-items: center;
    transition: all ease-in-out .4s;
	flex-wrap: nowrap; /* Allow groups to wrap */
	gap: .3rem; /* Equivalent to gap-4 */
	padding: 5px;
}
.status-indicator-wrapper.shrink {
	width: calc(100% - 201px);
	left: 201px;
}

/* Group for specific status sections */
.status-group {
	display: flex;
	align-items: center;
	flex-wrap: nowrap; /* Prevent items within a group from wrapping */
	gap: .7rem; /* Equivalent to gap-3 */
	position: relative;
}

/* Individual status item */
.status-item {
	display: flex;
	align-items: center;
	gap: 0.375rem; /* Equivalent to gap-1.5 */
	position: relative; /* For tooltip */
	white-space: nowrap; /* Prevent text wrapping within item */
	flex: 1 1 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
}
.status-item:hover {
	cursor: pointer;
}
.status-item span {
	padding: 5px 10px;
	font-size: 14px;
}

.status-group-left .status-item {
	padding: 0 0px;
}
.status-group-right {
	gap: 15px;
}
.status-group-right .status-item span {
	flex-grow: 1;
}
.status-group-right .status-item {
	flex-grow: 1;	
}

/* SVG Icon Styling */
.status-item svg {
	height: 1.25rem; /* Equivalent to h-5 */
	width: 1.25rem; /* Equivalent to w-5 */
	color: #6b7280; /* Equivalent to text-gray-500 */
	flex-shrink: 0; /* Prevent shrinking */
}

/* Status text badge styling */
.status-badge {
	font-size: 0.75rem; /* Equivalent to text-xs */
	font-weight: 500; /* Equivalent to font-medium */
	padding: 0.125rem 0.625rem; /* Equivalent to py-0.5 px-2.5 */
	border-radius: 9999px; /* Equivalent to rounded-full */
	line-height: 1.25;
	display: inline-flex;
	align-items: center;
	padding: 3px;
	display: flex;
	flex-grow: 1;

	flex: 1 1 0;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.status-icon {
	display: flex;
}
.status-icon svg {
	color: #fff;
	margin-left: 5px;
	width: 1rem;
	height: 1rem;
}
.status-text {
	display: flex;
	flex-grow: 1;
	flex: 1 1 0;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}
.status-text span:nth-of-type(1) {
	flex-grow: unset;
	padding-left: 5px;
}
.status-text span:nth-of-type(2) {
	overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
	background-color: #0004;
	border-radius: 9999px;
	padding: 5px 13px 5px 5px;
}
.status-group-left .status-text span:nth-of-type(2) {
	padding: 5px;
	flex-grow: 1;
}
.status-text::after {
	display: block;
	content: "";
	position: absolute;
	top: 50%;
	right: 12px;
	transform: translateY(-50%);
	font-size: 12px;
	color: #555;
	pointer-events: none;
}

.status-arrow {
	position: absolute;
    right: 2px;
    top: 6px;
	/* transition: all .2s ease; */
    color: #fff;
    transform: rotateZ(-90deg);
}
.status-arrow svg {
	width: 1rem;
	height: 1rem;
	color: #ddd;
}

.status-item-highlighted .status-arrow {
	transform: rotateZ(-180deg);
	right: 5px;
	top: 4px;
}

/* Color variants for badges */
.status-badge-blue { background-color: #374255; color: #ffffff; } /* bg-emerald-500 text-white */
.status-badge-light-blue {background-color: #8194af; background-color: #374255; color: #fff; border: 1px solid #374255;}
/* .status-badge-light-blue b {color: #444 !important;} */
.status-badge-green { background-color: #059669; color: #ffffff; } /* bg-emerald-500 text-white */
.status-badge-red { background-color: #be1f17; color: #ffffff; } /* bg-red-500 text-white */
.status-badge-yellow { background-color: #f59e0b; color: #ffffff; } /* bg-amber-500 text-white */
.status-badge-gray { background-color: #6b7280; color: #ffffff; } /* bg-gray-500 text-white */

/* Vertical Separator - Light Theme */
.separator {
	width: 1px;
	height: 1.25rem; /* Equivalent to h-5 */
	background-color: #d1d5db; /* Equivalent to bg-gray-300 */
	margin: 0 0.5rem; /* Equivalent to mx-2 */
}
.status-group-left .status-item {
	flex: unset;
}

.status-group-left .status-text {
	justify-content: space-between;
    align-items: anchor-center;
    padding: 0px;
}

.status-group-left .status-text span:nth-of-type(1) {
	padding: 0 5px;
}
.status-group-left .status-text span:nth-of-type(2) {
	flex-grow: 0;
	padding: 3px;
	display: flex;
	margin: 0;
	margin-left: 5px;
}

.status-group-right .status-text span:nth-of-type(2) {
	text-align: center;
}


/* Responsive: Hide separator on smaller screens if groups wrap */
@media (max-width: 992px) {
	.status-indicator-wrapper {
		gap: 0.5rem;
	}
	.separator {
		display: none;
	}
	.status-group {
		gap: 0.75rem;
	}
}
@media (max-width: 1700px) {
	.status-group-left .status-text span:nth-of-type(2) {
		/* max-width: 70px; */
		overflow: hidden;
		text-overflow: ellipsis;
		/* padding: 5px 5px !important; */
	}
}
@media (max-width: 1600px) {
	.status-group-left .status-text span:nth-of-type(2) {
		max-width: unset;
		/* overflow: hidden;
		text-overflow: ellipsis; */
		/* padding: 5px 10px !important; */
		/* margin-left: 5px; */
	}
	.status-group-left .status-text span:nth-of-type(1) {
		/* display: none; */
	}
	.status-group-right {
		gap: 10px;
	}
		
}
@media (max-width: 1300px) {
	.status-group-right .status-text span:nth-of-type(1) {
		display: none;
	}
	.status-group-right .status-text span:nth-of-type(2) {
		margin-left: 5px;
	}
}
	

@keyframes spin {
  to { transform: rotate(360deg); }
}
.spin-svg {
  animation: spin 2s linear infinite;
}

</style>
