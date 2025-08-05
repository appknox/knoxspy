<template>
	<div class="status-indicator-wrapper">
		<div class="status-group status-group-left">
			<div class="status-item" data-tooltip="Websocket Server">
				<div class="status-badge" :class=" ws.isConnected ? 'status-badge-green' : 'status-badge-red'">
					<div class="status-icon">
						<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-gray-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
							<path stroke-linecap="round" stroke-linejoin="round" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
						</svg>
					</div>
					<div class="status-text">	
						<span><b style="color: #ddd">Server:</b></span>
						<span style="background-color: #0004; border-radius: 9999px; padding: 5px 20px;">{{ ws.isConnected ? 'Connected' : 'Not Connected' }}</span>
					</div>
				</div>
			</div>
			<div class="status-item" data-tooltip="App Connection">
				<div class="status-badge" :class="currentSession.app.connectedApp && currentSession.app.connectedApp.status ? 'status-badge-green' : 'status-badge-red'">
					<div class="status-icon">
						<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="size-6">
							<path stroke-linecap="round" stroke-linejoin="round" d="M10.5 1.5H8.25A2.25 2.25 0 0 0 6 3.75v16.5a2.25 2.25 0 0 0 2.25 2.25h7.5A2.25 2.25 0 0 0 18 20.25V3.75a2.25 2.25 0 0 0-2.25-2.25H13.5m-3 0V3h3V1.5m-3 0h3m-3 18.75h3" />
						</svg>
					</div>
					<div class="status-text" @click="showConnectedApp()">	
						<span><b style="color: #ddd">App:</b></span>
						<span style="background-color: #0004; border-radius: 9999px; padding: 5px 20px;">{{ currentSession.app.connectedApp && currentSession.app.connectedApp.status ? 'Connected' : 'Not Connected' }}</span>
					</div>
				</div>
			</div>
		</div>

		<div class="separator"></div>

		<div class="status-group status-group-right" style="flex-grow: 1;">
			<div class="status-item" data-tooltip="Selected Session" @click="toggleDropdown('session')" :class="showDropdown.session ? 'status-item-highlighted' : ''">
				<div class="status-badge" :class="currentSession.app.selectedSession ? 'status-badge-blue' : 'status-badge-light-blue'">
					<div class="status-icon">
						<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-gray-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" d="M15.75 6a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0ZM4.501 20.118a7.5 7.5 0 0 1 14.998 0A17.933 17.933 0 0 1 12 21.75c-2.676 0-5.216-.584-7.499-1.632Z" />
						</svg>
					</div>
					<div class="status-text">	
						<span><b style="color: #ccc">Session: </b></span>
						<span style="background-color: #0004; border-radius: 9999px; padding: 5px 20px;">{{ currentSession.app.selectedSession ? currentSession.app.selectedSession.name : 'No session selected' }}</span>
					</div>
					<div class="status-arrow">
						<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="size-6">
							<path stroke-linecap="round" stroke-linejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
						</svg>
					</div>
				</div>
				<div class="bottom-bar-dropdown" v-if="showDropdown.session">
					<ul>
						<li v-for="session in currentSession.app.sessions" :key="session.id" @click="toggleDropdownItem('session', session.id)">
							• {{ session.name }}
						</li>
					</ul>
				</div>
			</div>
			<div class="status-item" data-tooltip="Selected Device" @click="toggleDropdown('device')" :class="showDropdown.device ? 'status-item-highlighted' : ''">
				<div class="status-badge" :class="currentSession.app.selectedDevice ? 'status-badge-blue' : 'status-badge-light-blue'">
					<div class="status-icon">
						<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="size-6">
							<path stroke-linecap="round" stroke-linejoin="round" d="M10.5 1.5H8.25A2.25 2.25 0 0 0 6 3.75v16.5a2.25 2.25 0 0 0 2.25 2.25h7.5A2.25 2.25 0 0 0 18 20.25V3.75a2.25 2.25 0 0 0-2.25-2.25H13.5m-3 0V3h3V1.5m-3 0h3m-3 18.75h3" />
						</svg>
					</div>
					<div class="status-text">	
						<span><b style="color: #ccc">Device: </b></span>
						<span style="background-color: #0004; border-radius: 9999px; padding: 5px 20px;">{{ currentSession.app.selectedDevice ? currentSession.app.selectedDevice.name : 'No device selected' }}</span>
					</div>
					<div class="status-arrow">
						<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="size-6">
							<path stroke-linecap="round" stroke-linejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
						</svg>
					</div>
				</div>
				<div class="bottom-bar-dropdown" v-if="showDropdown.device">
					<ul>
						<li v-for="device in currentSession.app.devices" :key="device.id" @click="toggleDropdownItem('device', device.id)">
							• {{ device.name }}
						</li>
					</ul>
				</div>
			</div>
			<div class="status-item app-status-item" data-tooltip="Selected App" @click="toggleDropdown('app')" :class="showDropdown.app ? 'status-item-highlighted' : ''">
				<div class="status-badge" :class="currentSession.app.selectedApp ? 'status-badge-blue' : 'status-badge-light-blue'">
					<div class="status-icon">
						<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-gray-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" d="M3.75 6A2.25 2.25 0 0 1 6 3.75h2.25A2.25 2.25 0 0 1 10.5 6v2.25a2.25 2.25 0 0 1-2.25 2.25H6a2.25 2.25 0 0 1-2.25-2.25V6ZM3.75 15.75A2.25 2.25 0 0 1 6 13.5h2.25a2.25 2.25 0 0 1 2.25 2.25V18a2.25 2.25 0 0 1-2.25 2.25H6a2.25 2.25 0 0 1-2.25-2.25v-2.25ZM13.5 6a2.25 2.25 0 0 1 2.25-2.25H18A2.25 2.25 0 0 1 20.25 6v2.25A2.25 2.25 0 0 1 18 10.5h-2.25a2.25 2.25 0 0 1-2.25-2.25V6ZM13.5 15.75a2.25 2.25 0 0 1 2.25-2.25H18a2.25 2.25 0 0 1 2.25 2.25V18A2.25 2.25 0 0 1 18 20.25h-2.25A2.25 2.25 0 0 1 13.5 18v-2.25Z" />
						</svg>
					</div>
					<div class="status-text">
						<span><b style="color: #ccc">App: </b></span>
						<span style="background-color: #0004; border-radius: 9999px; padding: 5px 20px;">{{ currentSession.app.selectedApp ? currentSession.app.selectedApp.name : 'No app selected' }}</span>
					</div>
					<div class="status-arrow">
						<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="size-6">
							<path stroke-linecap="round" stroke-linejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
						</svg>
					</div>
				</div>
				<div class="bottom-bar-dropdown" v-if="showDropdown.app" style="max-height: 200px; overflow-y: scroll; overflow-x: hidden">
					<ul>
						<li v-for="app in currentSession.app.apps" :key="app.id" @click="toggleDropdownItem('app', app.id)">
							• {{ app.name }}
						</li>
					</ul>
				</div>
			</div>
			<div class="status-item" data-tooltip="Selected Platform" :class="showDropdown.platform ? 'status-item-highlighted' : ''">
				<div class="status-badge" :class="currentSession.app.selectedPlatform ? 'status-badge-blue' : 'status-badge-light-blue'">
					<div class="status-icon">
						<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-gray-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" d="M8.25 3v1.5M4.5 8.25H3m18 0h-1.5M4.5 12H3m18 0h-1.5m-15 3.75H3m18 0h-1.5M8.25 19.5V21M12 3v1.5m0 15V21m3.75-18v1.5m0 15V21m-9-1.5h10.5a2.25 2.25 0 0 0 2.25-2.25V6.75a2.25 2.25 0 0 0-2.25-2.25H6.75A2.25 2.25 0 0 0 4.5 6.75v10.5a2.25 2.25 0 0 0 2.25 2.25Zm.75-12h9v9h-9v-9Z" />
						</svg>
					</div>
					<div class="status-text">
						<span ><b style="color: #ccc">Platform: </b></span>
						<span style="background-color: #0004; border-radius: 9999px; padding: 5px 20px;">{{ currentSession.app.selectedDevice ? currentSession.app.selectedDevice.platform : 'No platform' }}</span>
					</div>
				</div>
			</div>
			<div class="status-item" data-tooltip="Selected Library" @click="toggleDropdown('library')" :class="showDropdown.library ? 'status-item-highlighted' : ''">
				<div class="status-badge" :class="currentSession.app.selectedLibrary ? 'status-badge-blue' : 'status-badge-light-blue'">
					<div class="status-icon">
						<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-gray-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" d="M17.25 6.75 22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3-4.5 16.5" />
						</svg>
					</div>
					<div class="status-text">
						<span ><b style="color: #ccc">Library: </b></span>
						<span style="background-color: #0004; border-radius: 9999px; padding: 5px 20px;">{{ currentSession.app.selectedLibrary ? currentSession.app.selectedLibrary.file : 'No library' }}</span>
					</div>
					<div class="status-arrow">
						<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="size-6">
							<path stroke-linecap="round" stroke-linejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
						</svg>
					</div>
				</div>
				<div class="bottom-bar-dropdown" v-if="showDropdown.library">
					<ul>
						<li v-for="library in currentSession.app.libraries" :key="library.id" @click="toggleDropdownItem('library', library.file)">
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

export default defineComponent({
	emits: ["sessionUpdated", "deviceUpdated", "appUpdated", "libraryUpdated", "appListUpdated", "appConnected", "appDisconnected", "dashboardUpdated", "workAppListUpdated"],
	name: "Footer",
	data() {
        return {
            currentSession: useAppStore(),
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
	methods: {
		handleSidebarToggle(isOpen) {
			console.log("[Footer] handleSidebarToggle", isOpen);
			$(".status-indicator-wrapper").css("left", isOpen ? "51px" : "0");
		},
		toggleDropdown(key) {
			this.showDropdown[key] = !this.showDropdown[key];
			if (this.showDropdown[key]) {
				this.populateDropdown(key);
			}
		},
		toggleDropdownItem(key, id) {
			if(key === "session") {
				const t_sess = this.currentSession.app.sessions.find(session => session.id === id);
				this.currentSession.setSelectedSession(t_sess);
				this.ws.send(JSON.stringify({ action: "chooseSession", session: t_sess}));
				this.$emit("sessionUpdated", this.currentSession.app.selectedSession);
			} else if(key === "device") {
				this.currentSession.setSelectedDevice(this.currentSession.app.devices.find(device => device.id === id));
				// this.$emit("deviceUpdated", this.currentSession.app.selectedDevice);
			} else if(key === "app") {
				const t_app = this.currentSession.app.apps.find(app => app.id === id);
				console.log("App selected:", t_app);
				this.currentSession.setSelectedApp(t_app, true);
				this.startApp(t_app.id, "spawn");
				// this.$emit("appUpdated", this.currentSession.app.selectedApp);
			} else if(key === "platform") {
				this.currentSession.setSelectedPlatform(this.currentSession.app.platforms.find(platform => platform.id === id));
			} else if(key === "library") {
				this.currentSession.setSelectedLibrary(id);
				const t_lib = this.currentSession.app.libraries.find(lib => lib.file === id);
				this.ws.send(JSON.stringify({ action: "changeLibrary", library: t_lib }));
				this.$emit("libraryUpdated", this.currentSession.app.selectedLibrary);
			}
		},
		populateDropdown(key) {
			if (key === "session") {
				this.ws.send(JSON.stringify({ action: "sessions" }));
			} else if(key === "device") {
				this.ws.send(JSON.stringify({ action: "devices" }));
			} else if (key === "app") {
				this.ws.send(JSON.stringify({ action: "apps" }));
			} else if (key === "platform") {
				this.ws.send(JSON.stringify({ action: "platforms" }));
			} else if (key === "library") {
				this.ws.send(JSON.stringify({ action: "libraries" }));
			}
		},
		async wsReady() {
			console.log("Footer(wsReady): WebSocket ready");
			this.didPageLoad = true;
			const connectedApp = await this.currentSession.getConnectedApp();
			console.log("Footer(wsReady): Connected app:", connectedApp);
			this.currentSession.setAppConnectionPhase("loading");
			this.ws.send(JSON.stringify({ action: "sessions" }));
			this.ws.send(JSON.stringify({ action: "devices" }));
			this.ws.send(JSON.stringify({ action: "libraries" }));
			watch(() => this.currentSession.app.isDashboardReady, () => {
				console.log("Footer(wsReady): Dashboard ready", this.currentSession.app.isDashboardReady);
				this.$emit("dashboardUpdated", this.currentSession.app.isDashboardReady);
			});
		},
		async wsMessage(message) {
			message = JSON.parse(message);
			const t_query = this.$route.query;
			console.log("Footer(wsMessage): Message:", message, message.action);
			if (message.action == "sessionList") {
				this.currentSession.app.sessions = message.sessions;
				const t_sess = this.currentSession.app.sessions.find(session => session.id === this.currentSession.app.selectedSession.id);
				this.currentSession.setSelectedSession(t_sess);
				console.log("Footer(wsMessage): Sessions:", this.currentSession.app.sessions, "selected:", t_sess);
				if(t_sess) {
					this.currentSession.setSessionActive(true);
				}
				this.$emit("sessionUpdated", t_sess);
				this.currentSession.setDashboardPhase("sessions", true);
				this.currentSession.checkDeviceReady();
			} else if (message.action == "devices") {
				this.currentSession.app.devices = message.devices;
				if(this.currentSession.app.devices.length > 0) {
					if(this.currentSession.app.connectedApp.status) {
						console.log("Footer(wsMessage): Device selected from connected app", this.currentSession.app.connectedApp);
						this.currentSession.setSelectedDevice(this.currentSession.app.devices.find(device => device.id === this.currentSession.app.connectedApp.app.deviceId));
					} else if (t_query.device) {
						console.log("Footer(wsMessage): Device selected from query", t_query.device);
						this.currentSession.setSelectedDevice(this.currentSession.app.devices.find(device => device.id === t_query.device));
					} else {
						console.log("Footer(wsMessage): Device selected from default - first", this.currentSession.app.devices[0]);
						this.currentSession.setSelectedDevice(this.currentSession.app.devices[0]);
					}
					this.$emit("deviceUpdated", this.currentSession.app.selectedDevice);
					this.currentSession.setDashboardPhase("devices", true);
					this.currentSession.checkDeviceReady();
					console.log("Footer(wsMessage): Devices:", this.currentSession.app.devices);
					this.loadingDropdown.app = true;
					this.ws.send(JSON.stringify({ action: "apps", deviceId: this.currentSession.app.selectedDevice.id, platform: this.currentSession.app.selectedDevice.platform }));
				}
			} else if (message.action == "apps") {
				this.loadingDropdown.app = false;
				this.currentSession.app.apps = message.apps;
				let t_users = message.usersInfo.filter(user => {
					if (user.id >= 10) {
						return user;
					}
				});
				const t_default_user = {
					id: '0',
					name: "User"
				}
				this.currentSession.app.selectedUser = t_default_user;
				console.log("Footer(wsMessage): Default user set:", t_default_user);
				t_users = [t_default_user, ...t_users];
				this.currentSession.app.users = [...t_users];
				this.currentSession.app.extraApps = message.usersInfo;
				console.log("Footer(wsMessage): Extra apps received:", message.usersInfo);
				
				this.$emit("appListUpdated", this.currentSession.app.apps);
				this.$emit("workAppListUpdated", this.currentSession.app.extraApps);
				console.log("Footer(wsMessage): Apps received:", message.apps.length);
				console.log("Footer(wsMessage): Work apps received:", this.currentSession.app.extraApps);
				console.log("Footer(wsMessage): Users received:", this.currentSession.app.users);
				if(this.currentSession.app.apps.length > 0) {
					if(this.currentSession.app.connectedApp.status) {
						console.log("Footer(wsMessage): App selected from connected app", this.currentSession.app.connectedApp);
						let t_selected_app = this.currentSession.app.apps.find(app => app.id === this.currentSession.app.connectedApp.app.identifier);
						if (!t_selected_app) {
							t_selected_app = this.currentSession.app.workApps.find(app => app.id === this.currentSession.app.connectedApp.app.identifier);
							this.currentSession.setSelectedApp(t_selected_app, true, true);
						} else {
							this.currentSession.setSelectedApp(t_selected_app, true, false);
						}
						this.$emit("appUpdated", t_selected_app);
					} else if (t_query.app) {
						let t_selected_app = this.currentSession.app.apps.find(app => app.id === t_query.app);
						if (!t_selected_app) {
							t_selected_app = this.currentSession.app.workApps.find(app => app.id === t_query.app);
							this.currentSession.setSelectedApp(t_selected_app, true, true);
						} else {
							this.currentSession.setSelectedApp(t_selected_app, true, false);
						}
						this.$emit("appUpdated", t_selected_app);
						if(this.didPageLoad) {
							this.startApp(t_query.app, "spawn");
						}
					}
					this.currentSession.setDashboardPhase("apps", true);
					this.currentSession.checkDeviceReady();
				} else {
					console.log("Footer(wsMessage): No apps found");
				}
				console.log("Footer(wsMessage): Apps:", this.currentSession.app.apps);
			} else if (message.action == "platforms") {
				this.currentSession.app.platforms = message.platforms;
				console.log("Footer(wsMessage): Platforms:", this.currentSession.app.platforms);
			} else if (message.action == "libraries") {
				this.currentSession.setDashboardPhase("libraries", true);
				if (message.libraries.length > 0) {
					this.currentSession.setLibraries(message.libraries);
					console.log("Footer(wsMessage): Libraries:", message.libraries);
				}
				if(this.currentSession.app.connectedApp.status) {
					console.log("Footer(wsMessage): Library selected from connected app", this.currentSession.app.connectedApp.app.library);
					this.currentSession.setSelectedLibrary(this.currentSession.app.connectedApp.app.library);
					this.$emit("libraryUpdated", this.currentSession.app.selectedLibrary);
				} else if(t_query.library) {
					this.currentSession.setSelectedLibrary(t_query.library);
					this.$emit("libraryUpdated", this.currentSession.app.selectedLibrary);
				}
			} else if (message.action == "deviceUpdate") {
				console.log("Footer(wsMessage): Device updated:", message);
				if(message.message === "Connected") {
					this.$emit("appConnected", this.currentSession.app.selectedApp);
					this.currentSession.setAppConnected(true);
				} else if (message.message === "Disconnected") {
					this.$emit("appDisconnected", this.currentSession.app.selectedApp);
					this.currentSession.setAppConnected(false);
					this.currentSession.setConnectedApp(null);
				}
				await this.currentSession.getConnectedApp()
			} else if (message.action == "error") {
				// if message.message is an object, loop through it and add each error message to the toast
				if(typeof message.message === "object") {
					for (const key in message.message) {
						this.$toast.add({
							snackbar: true,
							severity: "error",
							summary: "Error",
							detail: message.message[key],
							life: 3000
						});
					}
				} else {
					this.$toast.add({
						snackbar: true,
						severity: "error",
						summary: "Error",
						detail: message.message,
						life: 3000
					});
				}
			} else if (message.action == "jsonError") {
				this.$toast.add({
					snackbar: true,
					severity: "error",
					summary: "Error",
					detail: message.message.join("\n"),
					life: 3000
				});
			}
		},
		startApp(packageName, action) {
            this.isConnecting = true;
            const library = this.currentSession.app.selectedLibrary !== null ? this.currentSession.app.selectedLibrary.file : null
			this.$emit("appUpdated", this.currentSession.app.selectedApp);
			// console.log("Starting app:", packageName, action);
            // this.ws.send(JSON.stringify({
            //     "action": action + "App",
            //     "deviceId": this.currentSession.app.selectedDevice ? this.currentSession.app.selectedDevice.id : "",
            //     "appId": packageName,
            //     "appName": this.currentSession.app.selectedApp ? this.currentSession.app.selectedApp.name : "",
            //     "library": library
            // }))
        },
		showConnectedApp() {
			if(Object.keys(this.$route.query).length === 0) {
				// add app=com.appknox.mdm_test_app&device=192.168.0.105:5555&action=spawn&library=okhttp.js
				this.$router.push({
					path: "/app",
					query: {
						device: this.currentSession.app.selectedDevice ? this.currentSession.app.selectedDevice.id : null,
						app: this.currentSession.app.selectedApp ? this.currentSession.app.selectedApp.id : null,
						action: "spawn",
						library: this.currentSession.app.selectedLibrary ? this.currentSession.app.selectedLibrary.file : null
					}
				})
			} else {
				console.log("Query params present, redirecting to app");
				this.$router.push({ path: "/app", query: this.$route.query })
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
    transition: all ease-in-out .4s;
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
	flex-wrap: wrap; /* Allow groups to wrap */
	gap: .3rem; /* Equivalent to gap-4 */
	padding: 5px;
}

/* Group for specific status sections */
.status-group {
	display: flex;
	align-items: center;
	flex-wrap: nowrap; /* Prevent items within a group from wrapping */
	gap: .1rem; /* Equivalent to gap-3 */
	position: relative;
}

/* Individual status item */
.status-item {
	display: flex;
	align-items: center;
	gap: 0.375rem; /* Equivalent to gap-1.5 */
	position: relative; /* For tooltip */
	white-space: nowrap; /* Prevent text wrapping within item */
}
.status-item:hover {
	cursor: pointer;
}
.status-item span {
	padding: 5px 10px;
	font-size: 14px;
}

.status-group-left .status-item {
	padding: 0 10px;
}
.status-group-right {
	gap: 30px;
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
}
.status-text span:nth-of-type(1) {
	flex-grow: unset;
	padding-left: 5px;
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
		max-width: 70px;
		overflow: hidden;
		text-overflow: ellipsis;
		padding: 5px 5px !important;
	}
}
@media (max-width: 1600px) {
	.status-group-left .status-text span:nth-of-type(2) {
		max-width: unset;
		/* overflow: hidden;
		text-overflow: ellipsis; */
		padding: 5px 10px !important;
		margin-left: 5px;
	}
	.status-group-left .status-text span:nth-of-type(1) {
		display: none;
	}
	.status-group-right {
		gap: 10px;
	}
	.status-text span:first-child {
		display: none;
	}
	.status-text span:nth-of-type(2) {
		margin-left: 5px;
	}
}
</style>
