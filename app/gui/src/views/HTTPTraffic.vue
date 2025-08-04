<template>
    <div class="page">
        <Toast />
        <div class="page-loader" v-if="!isConnected">
            <div>
                <span><i class="pi pi-spinner pi-spin"></i></span>
                <p>Connecting to app...</p>
            </div>
        </div>
        <div style="display: flex; align-items: center; border-bottom: 1px solid #eee; position: relative;">
            <SelectButton v-model="value" :options="options" @change="tabChanged($event)" :allow-empty="false" aria-labelledby="basic" style="position: absolute; left: 30px; top: 8px; z-index: 1000; text-align: center"/>
        </div>

        <Splitter v-if="value == 'Proxy'" style="height: calc(100vh - 30px)" layout="vertical" v-on:resize="resizedSplitter">
            <SplitterPanel class="flex align-items-center justify-content-center" :size="60">
                <ContextMenu ref="cm" :model="menuModel" />
                <DataTable style="" contextMenu v-model:contextMenuSelection="selectedRow" @rowContextmenu="onRowContextMenu" selectionMode="single" @rowSelect="onRequestSelect" dataKey="id" class="traffic-history" :filters="filters" sortField="id" :sortOrder="-1" :value="rows" scrollable v-bind:scroll-height="dataTableHeight" tableStyle="min-width: 50rem" :globalFilterFields="['host', 'url']" size="small">
                    <template #header :style="{'margin':0, 'padding':0}" class="traffic-header" :class="{'hidden1': visibleTrafficHeader}">
                        <div class="traffic-header-inner flex justify-content-end" style="display: flex; justify-content: end; gap: 10px" :style="{'display': visibleTrafficHeader ? 'flex': 'flex'}" v-shortkey="['meta', 'f']" @shortkey.native="toggleTrafficHeader">
                            <IconField iconPosition="left">
                                <InputIcon class="pi pi-search"> </InputIcon>
                                <InputText v-model="filters['global'].value" placeholder="Host Search" />
                            </IconField>
                            <!-- <Button type="button" icon="pi pi-filter-slash" @click="" /> -->
                        </div>
                    </template>
                    <Column field="id" header="#" sortable style="width: 50px; font-size: 13px"></Column>
                    <Column field="method" header="Method" sortable style="width: 50px; font-size: 13px"></Column>
                    <Column field="protocol" header="Protocol" sortable style="width: 50px; font-size: 13px"></Column>
                    <Column field="host" header="Host" sortable style="width: 200px; font-size: 13px"></Column>
                    <Column field="endpoint" header="Endpoint" sortable style="width: 300px; font-size: 13px"></Column>
                    <Column field="content_type" header="Content Type" sortable style="width: 150px; font-size: 13px"></Column>
                    <Column field="status_code" header="Status" sortable style="width: 100px; font-size: 13px"></Column>
                    <Column field="length" header="Length" sortable style="width: 70px; font-size: 13px"></Column>
                </DataTable>
            </SplitterPanel>
            <SplitterPanel :size="40">
                <Splitter class="history-viewer-split">
                    <SplitterPanel class="flex align-items-center justify-content-center"  :size="50">
                        <ScrollPanel style="height: 100%; overflow-y: scroll; display: inline-block; width: 100%;">
                            <VCodeBlock
                                class="history-viewer-split-code"
                                :code="requestContent"
                                highlightjs
                                lang="http"
                                theme="vs"
                                style="text-align: left; word-wrap: break-word; text-wrap: wrap;"
                            />
                        </ScrollPanel>
                    </SplitterPanel>
                    <SplitterPanel class="flex align-items-center justify-content-center" :min-size="50":size="50">
                        <ScrollPanel style="height: 100%; overflow-y: scroll; display: inline-block; width: 100%;">
                            <VCodeBlock
                                class="history-viewer-split-code"
                                :code="responseContent"
                                highlightjs
                                lang="http"
                                theme="vs"
                                style="text-align: left; word-wrap: break-word; text-wrap: wrap"
                            />
                        </ScrollPanel>
                    </SplitterPanel>
                </Splitter>
            </SplitterPanel>
        </Splitter>
    
        <div v-if="value == 'Repeater'">
            <ContextMenu ref="repeaterTabMenu" :model="repeaterTabModel" />
            <ConfirmPopup group="templating">
                <template #message="slotProps">
                    <div class="flex flex-column align-items-center w-full gap-3 border-bottom-1 surface-border p-3 mb-3 pb-0">
                        <div class="" style="padding: 10px; display: flex; flex-direction: column">
                            <p style="margin: 0 0 5px; text-align: center">{{ slotProps.message.message }}</p>
                            <InputText placeholder="Tab Title" v-model="repeaterTabTitleConfirmInput"/>
                        </div>
                    </div>
                </template>
            </ConfirmPopup>

            <TabMenu v-if="value == 'Repeater'" v-model:activeIndex="activeRepeaterTab" :model="repeaterRows" :scrollable="true"  @tab-change="changeRepeater" style="margin-left: 230px; margin-right: 130px;">
                <template #item="{ item, props }">
                    <a v-ripple v-bind="props.action" class="repeater-tab-item flex align-items-center gap-2" @contextmenu="onRepeaterTabClick($event, item)">
                        <span class="font-bold" style="text-wrap: nowrap;" @click="editRepeaterTabTitle($event, item)">{{ item.label }}</span>
                        <i class="pi pi-times" style="font-size: 12px; display: none; margin-left: 5px" @click="removeTab($event, item)"></i>
                    </a>
                </template>
            </TabMenu>
            <Splitter class="repeater-viewer-split">
                <SplitterPanel class="flex align-items-center justify-content-center"  :size="50">
                    <codemirror
                        v-model="activeRepeaterData.requestContent"
                        placeholder="Code goes here..."
                        style="width: calc(100% - 10px);height: calc(100vh - 90px); border: 0; margin: 5px;  background-color: var(--surface-100)"
                        :autofocus="true"
                        :extensions="codeMirrorOptions.extensions"
                        :indent-with-tab="true"
                        :tab-size="2"
                    />
                </SplitterPanel>
                <SplitterPanel class="flex align-items-center justify-content-center" :min-size="50":size="50">
                    <codemirror
                        v-model="activeRepeaterData.responseContent"
                        style="width: calc(100% - 10px); height: calc(100vh - 90px); border: 0; margin: 5px; background-color: var(--surface-100)"
                        :autofocus="true"
                        :indent-with-tab="true"
                        :tab-size="2"
                        :extensions="codeMirrorOptions.extensions"
                        :disabled="true"
                    />
                    <!-- <Textarea v-model="activeRepeaterData.responseContent" rows="5" style="width: calc(100% - 10px);height: calc(100vh - 67px); border: 0; margin: 5px; background-color: var(--surface-100);" readonly /> -->
                    <!-- <textarea style="text-align: left;" v-model="activeRepeaterData" id="code-viewer" class="code-viewer"></textarea> -->
                </SplitterPanel>
            </Splitter>
            <Button :disabled='platformName == "1"' label="Replay" style="position: fixed; top: 7px; right: 10px;" icon="pi pi-send" @click="replayRequest"  v-shortkey="['meta', 'd']" @shortkey.native="replayRequest" />
        </div>
        <Footer @sessionUpdated="updateSessionInfo" @deviceUpdated="updateDeviceInfo" @appUpdated="updateAppInfo" @libraryUpdated="updateLibraryInfo"></Footer>
    </div>
</template>

<script lang="ts">
import { defineComponent } from 'vue';
import DataTable from 'primevue/datatable';
import Column from 'primevue/column';
import InputText from 'primevue/inputtext';
import VGrid from "@revolist/vue3-datagrid";
import { FilterMatchMode } from 'primevue/api';
import IconField from 'primevue/iconfield';
import InputIcon from 'primevue/inputicon';
import Button from 'primevue/button';
import Splitter from 'primevue/splitter';
import SplitterPanel from 'primevue/splitterpanel';
import { VCodeBlock } from '@wdns/vue-code-block';
import TabPanel from 'primevue/tabpanel';
import TabView from 'primevue/tabview';
import ContextMenu from 'primevue/contextmenu';
import SelectButton from 'primevue/selectbutton';
import { useAppStore, useWebSocketStore, usePageReadyEmitter } from '../stores/session';
import Listbox from 'primevue/listbox';
import { Codemirror } from 'vue-codemirror'
import TabMenu from 'primevue/tabmenu';
import Textarea from 'primevue/textarea';
import Toolbar from 'primevue/toolbar';
import { EditorView } from '@codemirror/view';
import { HTTPParser } from 'http-parser-js';
import {StreamLanguage} from '@codemirror/language';
import {http} from '@codemirror/legacy-modes/mode/http';
import ConfirmPopup from 'primevue/confirmpopup';
import { useConfirm } from "primevue/useconfirm";
import Toast from  'primevue/toast';
import hljs from 'highlight.js/lib/core';
import langHTTP from 'highlight.js/lib/languages/http';
import Footer from '../components/Footer.vue';
import { httpStatusCodes } from '../constants';

hljs.registerLanguage('http', langHTTP);

export default defineComponent({
    name: 'App',
    data() {
        return {
            platformName: '',
            repeaterTabTitleConfirmInput: "",
            confirm: useConfirm(),
            isPlatformDetectionVisible: false,
            dataTableHeight: "calc(60vh - 50px)",
            activeRepeaterTab: 0,
            activeRepeaterData: null,
            selectedRepeaterTab: null,
            sess: null,
            value: 'Proxy',
            options: ['Proxy', 'Repeater'],
            message: '',
            codeMirrorOptions: {
                extensions: [
                    EditorView.lineWrapping,
                    StreamLanguage.define(http)
                ]
            },
            messages: [],
            columns: [
                { prop: "id", name: "#", sortable: true, size: 50, columnType: 'numeric', cellCompare: this.naturalSort, order: 'asc'},
                { prop: "method", name: "Method", sortable: true, size: 100 },
                { prop: "protocol", name: "Protocol", sortable: true, size: 50},
                { prop: "host", name: "Host", sortable: true, size: 200 },
                { prop: "endpoint", name: "URL", sortable: true, size: window.innerWidth - 200 - 50 - 100 - 200 - 100 - 70 },
                { prop: "content_type", name: "Content Type", sortable: true, size: 100 },
                { prop: "status_code", name: "Status Code", sortable: true, size: 50 },
                { prop: "length", name: "Length", sortable: true, size: 70 }
            ],
            filters: {
                global: { value: null, matchMode: FilterMatchMode.CONTAINS },
                host: { value: null, matchMode: FilterMatchMode.CONTAINS },
                endpoint: { value: null, matchMode: FilterMatchMode.CONTAINS }
            },
            rows: [],
            repeaterRows: [],
            requestContent: "",
            responseContent: "",
            visibleTrafficHeader: false,
            selectedRow: null,
            menuModel: [
                {label: 'Send To Repeater', icon: 'pi pi-fw pi-reply', command: () => this.sendToRepeater(this.selectedRow)},
            ],
            repeaterTabModel: [
                // {label: 'Edit', icon: 'pi pi-fw pi-pencil', command: (event: any) => this.editRepeaterTabTitle(event.originalEvent, event.item)},
                // {label: 'Delete', icon: 'pi pi-fw pi-times', command: (event: any) => this.removeTab(event.originalEvent, event.item)},
                {label: 'Duplicate', icon: 'pi pi-fw pi-copy', command: (event: any) => this.sendToRepeater(event, true)},
            ],
            cmOptions: {
                mode: "text/javascript", // Language mode
                theme: "base16-light", // Theme
            },
            repeaterRequestViewer: null,
            repeaterResponseViewer: null,
            repeaterRightClickSelectedTab: null,
            currentSession: useAppStore(),
            ws: useWebSocketStore(),
            emitter: usePageReadyEmitter(),
            deviceId: this.$route.params.device_id as string,
            packageName: this.$route.params.package_name as string,
            library: this.$route.params.library as string,
            action: this.$route.params.action as string,
            isConnected: false,
            didPageLoad: false
        };
    },
    components: {
        Toast,
        Toolbar,
        ConfirmPopup,
        Textarea,
        TabMenu,
        SelectButton,
        TabView,
        TabPanel,
        VGrid,
        DataTable,
        Column,
        InputText,
        IconField,
        InputIcon,
        Button,
        Splitter,
        SplitterPanel,
        VCodeBlock,
        ContextMenu,
        Listbox,
        Codemirror,
        Footer
    },
    created() {
        this.ws.addOnOpenHandler(this.wsReady)
        this.ws.addOnMessageHandler(this.wsMessage)
    },
    methods: {
        wsReady() {
            console.log("Needs setup", this.didPageLoad);
            const connectedApp = this.currentSession.getConnectedApp;
            console.log("Connected app:", connectedApp);
            if(connectedApp) {
                this.isConnected = true;
            }
        },
        wsMessage(message: any) {
            message = JSON.parse(message);
            if (message.action === 'trafficUpdate') {
                let t_row = message.message;
                t_row["length"] = t_row["response_body"].length;
                const t_headers = JSON.parse(t_row["response_headers"]);
                console.log("Headers:", t_headers);
                let t_content_type = t_headers.find((header: any) => header.toLowerCase().startsWith("content-type"));
                t_row["content_type"] = "";
                if (t_content_type && t_content_type !== "") {
                    t_content_type = t_content_type.split(":")[1].trim();
                    t_row["content_type"] = t_content_type;
                }
                this.rows.push(t_row);
            } else if (message.action === 'repeaterUpdate') {
                let data = JSON.parse(message.traffic);
                this.addRowsToRepeater([data], false);
                console.log("New repeater tab added");
            } else if (message.action === 'trafficInit') {
                let data = JSON.parse(message.message);
                data.forEach((element: any) => {
                    element.length = element.response_body.length;
                    const t_headers = JSON.parse(element.response_headers);
                    let t_content_type = t_headers.find((header: any) => header.toLowerCase().startsWith("content-type"));
                    element.content_type = "";
                    if (t_content_type && t_content_type !== "") {
                        t_content_type = t_content_type.split(":")[1].trim();
                        element.content_type = t_content_type;
                    }
                });
                this.rows = data;
            } else if (message.action === 'repeaterInit') {
                let data = JSON.parse(message.message);
                this.addRowsToRepeater(data, true);
            } else if (message.action === 'replayUpdate') {
                let data = JSON.parse(message.replay);
                var tmpJSONFlag = false;
                let t_request_headers = JSON.parse(data.request_headers);
                t_request_headers.forEach((ele: any) => {
                    if(ele.toLowerCase().startsWith("content-type")) {
                        if(ele.indexOf("application/json")) {
                            tmpJSONFlag = true;
                        }
                    }
                })
                
                var tmpData = data.method + " " + data.endpoint + " HTTP/1.1\n"
                tmpData += t_request_headers.join("\n")
                // tmpData += "\nHost: " + element.host
                // console.log(element);
                // console.log(element.request_body);
                if(data.request_body) {
                    if(tmpJSONFlag) {
                        tmpData += "\n\n" + JSON.stringify(JSON.parse(data.request_body), null, 2);
                    } else {
                        tmpData += "\n\n" + data.request_body
                    }
                } else {
                    tmpData += "\n\n " 
                }
                
                var tmpRequestContent = tmpData
                let t_response_headers = JSON.parse(data.response_headers);
                tmpData = t_response_headers.join("\n")
                var newJSONFlag = false;
                var isHTTPResponseHeaderPresent = false;
                t_response_headers.forEach((ele: any) => {
                    console.log("For element:", ele);
                    if(ele.toLowerCase().startsWith("content-type")) {
                        console.log("Content-Type:", ele);
                        if(ele.indexOf("application/json") > 0) {
                            console.log("Element in final loop:", ele)
                            newJSONFlag = true;
                        }
                    }
                    if(ele.toLowerCase().startsWith("http/")) {
                        isHTTPResponseHeaderPresent = true;
                    }
                })
                console.log("New flag value: ", newJSONFlag)
                console.log("HTTP response header present: ", isHTTPResponseHeaderPresent, "Status:", data.status_code)
                if(!isHTTPResponseHeaderPresent) {
                    tmpData = "HTTP/1.1 " + data.status_code + " " + httpStatusCodes[data.status_code] + "\n" + tmpData;
                }
                if(newJSONFlag) {
                    tmpData += "\n\n" + JSON.stringify(JSON.parse(data.response_body), null, 2);
                } else {
                    tmpData += "\n\n" + data.response_body
                }
                
                var tmpResponseContent = tmpData
                var tmpUpdatedRequest = {id: data.id, name: data.host + data.endpoint, requestContent: tmpRequestContent, responseContent: tmpResponseContent, label: data.id, element: data}
                this.activeRepeaterData = tmpUpdatedRequest;
                var index = this.repeaterRows.findIndex(obj => obj.id === data.id)
                this.repeaterRows[index] = tmpUpdatedRequest 
            } else if (message.action === 'changeLibrary') {
                this.currentSession.app.selectedLibrary = message.library;
            } else if (message.action === "repeaterTabDeleted") {
                const t_repeater_id = message.id;
                this.repeaterRows = this.repeaterRows.filter((obj: any) => obj.id !== t_repeater_id);
                if(this.repeaterRows.length === 0) {
                    this.activeRepeaterTab = -1;
                    this.activeRepeaterData = null;
                    this.value = 'Proxy';
                } else {
                    this.activeRepeaterTab = this.repeaterRows.length - 1;
                    this.activeRepeaterData = this.repeaterRows[this.activeRepeaterTab];
                }
            }
        },
        setupPage(emitter: any = null) {
            console.log("HTTPTraffic: page setup", emitter);
            this.isConnected = true;
        
            console.log(this.deviceId, this.packageName, this.action, this.library);
            
            // if(this.deviceId && this.packageName && this.action && this.library) {
            //     console.log("All parameters present");
            //     const t_device_id = atob(this.deviceId);
            //     this.ws.send(JSON.stringify({"action": "findApp", "deviceId": t_device_id, "packageName": this.packageName}));
            // } else if(this.deviceId && this.packageName && this.action) {
            //     console.log("No library");
            //     const t_device_id = atob(this.deviceId);
            //     this.ws.send(JSON.stringify({"action": "findApp", "deviceId": t_device_id, "packageName": this.packageName}));
            // } else {
            //     console.log("No params");
            //     this.isConnected = true;
            //     this.$toast.add({
            //         severity: 'error',
            //         summary: 'Error',
            //         detail: 'No device selected',
            //         life: 3000
            //     });
            //     this.$toast.add({
            //         severity: 'error',
            //         summary: 'Error',
            //         detail: 'No app selected',
            //         life: 3000
            //     });
            // }
        },
        addRowsToRepeater(rows: any[], isInit: boolean = false) {
            rows.forEach((element: any) => {
                var tmpData = element.method + " " + element.endpoint + " HTTP/1.1\n"
                // console.log(element);
                var tmpJSONFlag = false;
                JSON.parse(element.request_headers).forEach((ele: any) => {
                    if(ele.toLowerCase().startsWith("content-type")) {
                        if(ele.indexOf("application/json")) {
                            tmpJSONFlag = true;
                        }
                    }
                })

                console.log(element.request_headers, typeof element.request_headers);
                
                tmpData += JSON.parse(element.request_headers).join("\n")

                console.log("[Repeater] Request headers:", tmpData);
                
                // tmpData += "\nHost: " + element.host
                // console.log(element);
                // console.log(element.request_body);
                if(element.request_body) {
                    if(tmpJSONFlag) {
                        tmpData += "\n\n" + JSON.stringify(JSON.parse(element.request_body), null, 2);
                    } else {
                        tmpData += "\n\n" + element.request_body
                    }
                } else {
                    tmpData += "\n\n " 
                }
                
                var tmpRequestContent = tmpData
                tmpData = JSON.parse(element.response_headers).join("\n")

                console.log("[Repeater] Response headers:", tmpData);
                
                var isHTTPResponseHeaderPresent = false;
                JSON.parse(element.response_headers).forEach((ele: any) => {
                    if(ele.toLowerCase().startsWith("content-type")) {
                        if(ele.indexOf("application/json") > 0) {
                            tmpJSONFlag = true;
                        }
                    }
                    if (ele.toLowerCase().startsWith("http/")) {
                        isHTTPResponseHeaderPresent = true;
                    }
                })
                if (!isHTTPResponseHeaderPresent) {
                    tmpData = "HTTP/1.1 200 OK\n" + tmpData;
                }

                if(tmpJSONFlag) {
                    tmpData += "\n\n" + JSON.stringify(JSON.parse(element.response_body), null, 2);
                } else {
                    tmpData += "\n\n" + element.response_body
                }
                // tmpData += "\n\n" + element.response_body
                
                var tmpResponseContent = tmpData
                // console.log("Label:", element.title == null ? element.id : element.title, element.id);
                const t_data = {id: element.id, name: element.host + element.endpoint, requestContent: tmpRequestContent, responseContent: tmpResponseContent, label: element.title == null || element.title.trim() === "" ? element.id : element.title, element: element}
                console.log("Added data:", t_data);
                this.repeaterRows.push(t_data)
            });
            this.activeRepeaterData = this.repeaterRows[this.repeaterRows.length - 1]
            this.activeRepeaterTab = this.repeaterRows.length - 1
            console.log("Repeater update:\n", this.activeRepeaterData, "\n", this.activeRepeaterTab)
            if(!isInit) {
                this.value = 'Repeater'
            }
        },
        startApp(packageName: string, action: string) {
            let t_library = this.library;
            if(this.library) {
                t_library = atob(this.library)
            }
            this.ws.send(JSON.stringify({
                "action": action + "App",
                "deviceId": this.currentSession.app.selectedDevice.id,
                "appId": packageName,
                "appName": this.currentSession.app.selectedApp.name,
                "library": t_library
            }))
        },
        tabChanged(event: any) {
            // console.log(event);
            if(event.value === "Repeater" && this.repeaterRows.length === 0) {
                this.$toast.add({ severity: 'error', summary: 'Error', detail: 'No tabs in repeater!', life: 3000 });
                // alert("No repeater tabs found")
                this.value = 'Proxy'
            }
            console.log("Tab changed", this.repeaterRows);
            
        },
        removeTab(event: any, item: any) {
            console.log("Removing", event, item);
            this.ws.send(JSON.stringify({'action': 'deleteRepeaterTab', 'id': this.activeRepeaterData.id}))
        },
        showTemplate(event: any) {
            this.$confirm.require({
                target: event.currentTarget,
                group: 'templating',
                message: 'Set new title for this tab',
                icon: 'pi pi-exclamation-circle',
                acceptIcon: 'pi pi-check',
                rejectIcon: 'pi pi-times',
                acceptLabel: 'Confirm',
                rejectLabel: 'Cancel',
                rejectClass: 'p-button-outlined p-button-sm',
                acceptClass: 'p-button-sm',
                accept: () => {
                    this.setRepeaterTabTitle(event)
                },
                reject: () => {
                    this.$toast.add({ severity: 'error', summary: 'Rejected', detail: 'You have rejected', life: 3000 });
                }
            });
        },
        resizedSplitter(event) {
            console.log("Resizing");
            console.log(event.sizes);
            this.dataTableHeight = `calc(${event.sizes[0]}vh - 80px)`;
        },
        parseRequest(requestData: string) {
            const lines = requestData.split('\n');
            const [method, path] = lines[0].split(' ');

            const headers = [];
            let body = '';
            let isBody = false;

            for (let i = 1; i < lines.length; i++) {
                if (isBody) {
                    body += lines[i];
                } else if (lines[i] === '') {
                    isBody = true;
                } else {
                    // const [key, value] = lines[i].split(': ');
                    headers.push(lines[i]);
                }
            }
            
            const parsedRequest = {
                method,
                "endpoint": path,
                "request_headers": JSON.stringify(headers),
                "request_body": body,
            };
            return parsedRequest;
        },
        replayRequest() {
            if(!this.currentSession.app.connectedApp.status) {
                console.log("No app connected");
            } else {
                let t_replayPayload = {
                    "id": "",
                    "protocol": "",
                    "host": "",
                    "status_code": "",
                    "response_body": "",
                    "response_headers": "",
                    "session_id": "",
                    "method": "",
                    "endpoint": "",
                    "request_headers": "",
                    "request_body": ""
                }
                var tmpRepeaterPayload = this.parseRequest(this.activeRepeaterData.requestContent);
                const tmpRepeaterData = this.activeRepeaterData.element;
                t_replayPayload['method'] = tmpRepeaterPayload.method;
                t_replayPayload['endpoint'] = tmpRepeaterPayload.endpoint;
                t_replayPayload['request_headers'] = tmpRepeaterPayload.request_headers;
                t_replayPayload['request_body'] = tmpRepeaterPayload.request_body;
                t_replayPayload['id'] = tmpRepeaterData.id;
                t_replayPayload['protocol'] = tmpRepeaterData.protocol;
                t_replayPayload['host'] = tmpRepeaterData.host;
                t_replayPayload['status_code'] = ""
                t_replayPayload['response_body'] = ""
                t_replayPayload['response_headers'] = ""
                t_replayPayload['session_id'] = tmpRepeaterData.session_id
                console.log("Replay payload", t_replayPayload);
                this.ws.send(JSON.stringify({'action': 'replayRequest', 'replay': t_replayPayload, 'platform': this.currentSession.app.selectedDevice.platform}))
            }
        },
        changeRepeater(event: any) {
            console.log("Changed to Repeater");
            // console.log(this.activeRepeaterData);
            this.activeRepeaterData = this.repeaterRows[event.index]
            // this.re
            // this.repeaterRequestViewer.setValue(this.activeRepeaterData.requestContent)
            // this.repeaterResponseViewer.setValue(this.activeRepeaterData.responseContent)
        },
        handleReady(payload: any) {
            this.view.value = payload.view
        },
        sendToRepeater(row: any, duplicate: any = false) {
            if(!duplicate) {
                console.log(row.id);
                // this.value = 'Repeater'
                this.ws.send(JSON.stringify({'action': 'sendToRepeater', 'id': row.id}))
            } else {

                console.log(this.repeaterRightClickSelectedTab.id);
                this.ws.send(JSON.stringify({'action': 'duplicateRepeater', 'id': this.repeaterRightClickSelectedTab.id}))
            }
            
        },
        editRepeaterTabTitle(event: any, item: any) {
            console.log("Event", event, item, this.activeRepeaterData);
            
            console.log("Editing", this.activeRepeaterData);
            if(this.activeRepeaterData.id === item.id) {
                this.repeaterTabTitleConfirmInput = this.activeRepeaterData.label
                this.showTemplate(event);
            }
        },
        setRepeaterTabTitle(event: any) {
            console.log("Event", this.repeaterTabTitleConfirmInput, this.activeRepeaterData);
            this.connection.send(JSON.stringify({'action': 'setRepeaterTabTitle', 'title': this.repeaterTabTitleConfirmInput, 'id': this.activeRepeaterData.id}))
            var index = this.repeaterRows.findIndex(obj => obj.id === this.activeRepeaterData.id)
            console.log("Updated Tab:", this.repeaterRows[index]);
            
            this.repeaterRows[index].label = this.repeaterTabTitleConfirmInput 
            console.log("Updated Tab:", this.repeaterRows[index]);
        },
        onRepeaterTabClick(event: any, item: any) {
            // console.log("Repeater tab right click");
            // console.log(event);
            // console.log(item);
            // console.log(this.activeRepeaterData);
            if(this.activeRepeaterData.id === item.id) {
                this.repeaterRightClickSelectedTab = item;
                this.$refs.repeaterTabMenu.show(event);
            } else {
                event.preventDefault()
            }
        },
        onRowContextMenu(event: any) {
            console.log(this.$refs.cm);
            
            this.$refs.cm.show(event.originalEvent);
        },
        toggleTrafficHeader() {
            this.visibleTrafficHeader = !this.visibleTrafficHeader
        },
        onRequestSelect(event: any) {
            var tmpData = event.data.method + " " + event.data.endpoint + " HTTP/1.1\n"
            tmpData += JSON.parse(event.data.request_headers).join("\n")
            console.log(event.data);
            console.log(event.data.request_body);
            if(event.data.request_body) {
                tmpData += "\n\n" + event.data.request_body
            } else {
                tmpData += "\n\n " 
            }
            
            console.log("Response headers:", event.data.response_headers);
            
            this.requestContent = tmpData
            tmpData = JSON.parse(event.data.response_headers).join("\n")
            tmpData += "\n\n" + event.data.response_body
            
            this.responseContent = tmpData
        },
        naturalSort(prop, a, b) {
            const av = a[prop].toString();
            const bv = b[prop].toString();
            window.console.log(typeof(av), typeof(bv));
            return av.localeCompare(bv, undefined, { numeric: true });
            // const av = parseFloat(a[prop])
            // const bv = parseFloat(b[prop])
            // console.log(typeof(av), typeof(bv));
            //  return av == bv ? 0 : av > bv ?  1 : -1;
        },
        updateSessionInfo(session: any) {
            console.log("Current path", this.$route.fullPath, "session");
        },
        updateDeviceInfo(device: any) {
            console.log("Current path", this.$route.fullPath, "device");
            this.updateURL(device.id, "device")
        },
        updateAppInfo(app: any) {
            console.log("Current path", this.$route.fullPath, "app");
            this.updateURL(app.id, "app")
        },
        updateLibraryInfo(library: any) {
            console.log("Current path", this.$route.fullPath, "library");
            this.updateURL(library.file, "library")
        },
        updateURL(value: any, key: string) {
            this.$router.push({path: "/traffic", query: {
                ...this.$route.query,
                [key]: value
            }})
        },
    },
    mounted() {
        console.log("HTTPTraffic: Page mounted");
        if(!this.currentSession.app.selectedSession) {
            this.$router.push('/');
        } else {
            this.isConnected = true;
            this.ws.send(JSON.stringify({action: "getTraffic", session: this.currentSession.app.selectedSession.id}))
            const grid = document.querySelector('revo-grid');
            if (grid) {
                grid.resize = true;
                grid.autoSizeColumn = true;
            }
        }
    },
	unmounted() {
		console.log("Unmounting HTTPTraffic");
		this.ws.removeMessageCallback(this.wsMessage);
		this.ws.removeOpenCallback(this.wsReady);
	},
});
</script>


<style scoped>
.history-viewer-split-code code {
    height: 100vh;
}
.repeater-tab-item span {
    padding:  0 5px;
}
.repeater-tab-item i {
    padding: 2px;
    border-radius: 50%;
    background-color: var(--bluegray-700);
    transition: all linear .2s;
    color: white;
    position: absolute;
    right: 0px;
    top: 50%;
    margin-top: -8px;
}
.repeater-tab-item:hover i {
}
.p-tabmenuitem.p-highlight:hover .repeater-tab-item i {

    display: block !important;
}
.page-loader {
    position: fixed;
    top: 0;
    left: 50px;
    /* margin-left: -50%; */
    z-index: 9999;
    width: calc(100% - 50px);
    height: 100vh;
    background-color: #fffa;
    display: flex;
    justify-content: end;
    align-items: end;
    flex-direction: row;
}
.page-loader div {
    /* background-color: #fff; */
    padding: 20px;
    border-radius: 10px;
    /* box-shadow: 0 5px 15px -13px #000a; */
    display: flex;
    flex-direction: row;
    justify-content: center;
    align-items: center;
}
.page-loader p {
    margin: 0;
    color: var(--green-700);
    font-size: 35px;
    font-family: "Fira Code";
    font-variant: small-caps;
}
.page-loader span {
    margin-right: 10px;
}
.page-loader span i {
    vertical-align: middle;
    color: var(--surface-500);
    font-size: 30px;
}
textarea:focus {
    outline: 0;
}
.page {
    text-align: left  !important;
}
.Codemirror pre.Codemirror-line {
    text-align: left;
}
.p-datatable .p-datatable-header{
    background-color: red;
    padding: 0;
}
.p-datatable div.p-datatable-header {
    padding: 0 !important;
    margin: 0;
}
.history-viewer-split .history-viewer-split-code {
    word-wrap: break-word;
    text-wrap: wrap;
    font-size: 13px !important;
    overflow: hidden;
}
.history-viewer-split > div {
    font-size: 13px;
}
.history-viewer-split {
    width: 100vh;
}
.history-viewer-split pre {
    text-align: left;
    font: 15px "Fira Code";
}
.traffic-history {
    height: 60vh;
}
.traffic-viewer {
    height: 30vh;
}
.p-datatable-header {
    position: absolute;
    z-index: 1001;
    top: 0;
}
.p-column-title	{
    font-size: 12px;
}
.page {
    overflow: hidden;
    flex-grow: 1;
    height: 100%;
    background-color: #fff;
}

.page {
    display: flex;
    flex-direction: column;
}
#revo-grid {
    width: 100%;
    max-width: 100%;
}
revo-grid {
    width: 100%;
    max-width: 100%;
}
revo-grid .inner-content-table {
    max-width: 100% !important;
    width: 100% !important;
}
</style>
