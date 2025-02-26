<template>
    <div class="page">
        <Toast />

        <div class="page-loader" v-if="isPlatformDetectionVisible">
            <div>
                <span><i class="pi pi-spinner pi-spin"></i></span>
                <p>Detecting device platform...</p>
            </div>
        </div>
        <!-- <v-grid :source="rows" :columns="columns" /> -->
        <div style="display: flex; align-items: center; border-bottom: 1px solid #eee; position: relative;">
            <SelectButton v-model="value" :options="options" @change="tabChanged($event)" :allow-empty="false" aria-labelledby="basic" style="position: absolute; left: 30px; top: 8px; z-index: 1000; text-align: center"/>

            <!-- <SelectButton v-model="value" :options="options" aria-labelledby="basic" style="margin-left: 30px; margin-right: 30px; padding: 5px"/> -->
        </div>

        <Splitter v-if="value == 'Proxy'" style="height: calc(100vh - 30px)" layout="vertical" v-on:resize="resizedSplitter">
            <SplitterPanel class="flex align-items-center justify-content-center" :size="60">
                <ContextMenu ref="cm" :model="menuModel" />
                <DataTable style="" contextMenu v-model:contextMenuSelection="selectedRow" @rowContextmenu="onRowContextMenu" selectionMode="single" @rowSelect="onRequestSelect" dataKey="id" class="traffic-history" :filters="filters" sortField="id" :sortOrder="-1" :value="rows" scrollable v-bind:scroll-height="dataTableHeight" tableStyle="min-width: 50rem" :globalFilterFields="['host', 'url']" size="small">
                    <template #header :style="{'margin':0, 'padding':0}" class="traffic-header" :class="{'hidden1': visibleTrafficHeader}">
                        <div class="traffic-header-inner flex justify-content-end" style="display: flex; justify-content: end; gap: 10px" :style="{'display': visibleTrafficHeader ? 'flex': 'flex'}" v-shortkey="['meta', 'f']" @shortkey.native="toggleTrafficHeader">
                            
                            <IconField iconPosition="left">
                                <InputIcon class="pi pi-search"> </InputIcon>
                                <InputText v-model="filters['global'].value" placeholder="Keyword Search" />
                            </IconField>
                            <Button type="button" icon="pi pi-filter-slash" @click="" />
                        </div>
                    </template>
                    <Column field="id" header="#" sortable style="width: 50px; font-size: 13px"></Column>
                    <Column field="method" header="Method" sortable style="width: 100px; font-size: 13px"></Column>
                    <Column field="host" header="Host" sortable style="width: 200px; font-size: 13px"></Column>
                    <Column field="endpoint" header="Endpoint" sortable style="width: 300px; font-size: 13px"></Column>
                    <Column field="status_code" header="Status" sortable style="width: 100px; font-size: 13px"></Column>
                    <Column field="length" header="Length" sortable style="width: 70px; font-size: 13px"></Column>
                </DataTable>
            </SplitterPanel>
            <SplitterPanel :size="40">
                <Splitter class="history-viewer-split">
                    <SplitterPanel class="flex align-items-center justify-content-center"  :size="50">
                        <VCodeBlock
                            class="history-viewer-split-code"
                            :code="requestContent"
                            highlightjs
                            lang="http"
                            theme="vs"
                            style="text-align: left; word-wrap: break-word; text-wrap: wrap;"
                        />
                    </SplitterPanel>
                    <SplitterPanel class="flex align-items-center justify-content-center" :min-size="50":size="50">
                        <VCodeBlock
                            class="history-viewer-split-code"
                            :code="responseContent"
                            highlightjs
                            lang="http"
                            theme="vs"
                            style="text-align: left; word-wrap: break-word; text-wrap: wrap"
                        />
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
            <!-- <TabMenu :scrollable="true" v-if="value == 'Repeater'" @contextmenu="onRepeaterTabClick" v-model:activeIndex="activeRepeaterTab" :model="repeaterRows" @tab-change="changeRepeater" style="margin-left: 230px; margin-right: 130px;"/> -->

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
                    <!-- <Textarea v-model="activeRepeaterData.requestContent" rows="5" style="width: calc(100% - 10px);height: calc(100vh - 67px); border: 0; margin: 5px;  background-color: var(--surface-100);"/> -->
                    <!-- <textarea style="text-align: left;" v-model="activeRepeaterData" id="code-editor" class="code-editor"></textarea> -->
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
import { useSessionStore } from '../stores/session';
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
            activeRepeaterData: "",
            selectedRepeaterTab: null,
            sess: null,
            value: 'Proxy',
            options: ['Proxy', 'Repeater'],
            connection: null,
            isConnected: false,
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
                { prop: "host", name: "Host", sortable: true, size: 200 },
                { prop: "endpoint", name: "URL", sortable: true, size: window.innerWidth - 200 - 50 - 100 - 200 - 100 - 70 },
                { prop: "status_code", name: "Status Code", sortable: true, size: 100 },
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
            repeaterRightClickSelectedTab: null
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
        Codemirror
    },
    setup() {
    },
    created() {
        this.sess = useSessionStore();
        if(this.sess.session.name === null) {
            this.sess.$patch({'error': 'Select A Session First!'})
            this.$router.push({name: 'Dashboard'})
        }

    
            
        // CodeMirror.fromTextArea(document.getElementById("repeaterRequestViewer"), {
        //     lineNumbers: true
        // });

        const url = 'ws://' + import.meta.env.VITE_SERVER_IP + ':8000';
        this.connection = new WebSocket(url);

        this.connection.onopen = () => {
            this.isConnected = true;
            this.connection.send(JSON.stringify({'action': 'repeaterUpdate'}))
            if(["ios", "android"].indexOf(this.sess.app.platform.toLowerCase()) === -1) {
                this.connection.send(JSON.stringify({'action': 'detectDevicePlatform', 'sessionId': this.sess.app.sessionId}))
            } else {
                this.isPlatformDetectionVisible = false
            }
            console.log('Connected to WebSocket server');
        };

        this.connection.onmessage = (event) => {
            const message = JSON.parse(event.data); // Assuming JSON data
            console.log(message.action);
            // console.log(message.message);
            
            if (message.action == "trafficInit") {                
                this.rows = message.message;
            } else if(message.action == "trafficUpdate") {
                this.rows.push(message.message);
            } else if(message.action == "repeaterAdd") {
                const element = message.message;
                var tmpData = element.method + " " + element.endpoint + "\n"
                tmpData += JSON.parse(element.request_headers).join("\n")
                console.log(element);
                console.log(element.request_body);

                var tmpJSONFlag = false;
                JSON.parse(element.request_headers).forEach((ele) => {
                    if(ele.toLowerCase().startsWith("content-type")) {
                        if(ele.indexOf("application/json")) {
                            tmpJSONFlag = true;
                        }
                    }
                })

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

                JSON.parse(element.response_headers).forEach((ele) => {
                    if(ele.toLowerCase().startsWith("content-type")) {
                        if(ele.indexOf("application/json") > 0) {
                            tmpJSONFlag = true;
                        }
                    }
                })
                if(tmpJSONFlag) {
                    tmpData += "\n\n" + JSON.stringify(JSON.parse(element.response_body), null, 2);
                } else {
                    tmpData += "\n\n" + element.response_body
                }
                
                var tmpResponseContent = tmpData
                this.repeaterRows.push({id: element.id, name: element.host + element.endpoint, requestContent: tmpRequestContent, responseContent: tmpResponseContent, label: element.id, element: element})
                // this.repeaterRows.push({label: element.host + element.endpoint})
                this.value = "Repeater"
                var index = this.repeaterRows.findIndex(obj => obj.id === element.id)
                this.activeRepeaterTab = index
                this.activeRepeaterData = this.repeaterRows[index]
            } else if(message.action == "repeaterUpdate") {
                // console.log(message.message)
                if(message.message.length) {
                    message.message.forEach((element: any) => {
                        var tmpData = element.method + " " + element.endpoint + "\n"
                        // console.log(element);
                        var tmpJSONFlag = false;
                        JSON.parse(element.request_headers).forEach((ele) => {
                            if(ele.toLowerCase().startsWith("content-type")) {
                                if(ele.indexOf("application/json")) {
                                    tmpJSONFlag = true;
                                }
                            }
                        })

                        tmpData += JSON.parse(element.request_headers).join("\n")
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


                        JSON.parse(element.response_headers).forEach((ele) => {
                            if(ele.toLowerCase().startsWith("content-type")) {
                                if(ele.indexOf("application/json") > 0) {
                                    tmpJSONFlag = true;
                                }
                            }
                        })
                        if(tmpJSONFlag) {
                            tmpData += "\n\n" + JSON.stringify(JSON.parse(element.response_body), null, 2);
                        } else {
                            tmpData += "\n\n" + element.response_body
                        }
                        // tmpData += "\n\n" + element.response_body
                        
                        var tmpResponseContent = tmpData
                        // console.log("Label:", element.title == null ? element.id : element.title, element.id);
                        
                        this.repeaterRows.push({id: element.id, name: element.host + element.endpoint, requestContent: tmpRequestContent, responseContent: tmpResponseContent, label: element.title == null || element.title.trim() === "" ? element.id : element.title, element: element})
                    });
                    this.activeRepeaterData = this.repeaterRows[0]
                    console.log("Repeater update:", this.activeRepeaterData)
                } else {
                    this.value = 'Proxy'
                }
                
            } else if(message.action === "replayUpdate") {
                const element = JSON.parse(message.replay);
                console.log(element);

                var tmpJSONFlag = false;
                element.request_headers.forEach((ele) => {
                    if(ele.toLowerCase().startsWith("content-type")) {
                        if(ele.indexOf("application/json")) {
                            tmpJSONFlag = true;
                        }
                    }
                })
                
                var tmpData = element.method + " " + element.endpoint + "\n"
                tmpData += element.request_headers.join("\n")
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
                tmpData = element.response_headers.join("\n")
                var newJSONFlag = false;
                element.response_headers.forEach((ele) => {
                    console.log("For element:", ele);
                    if(ele.toLowerCase().startsWith("content-type")) {
                        console.log("Content-Type:", ele);
                        if(ele.indexOf("application/json") > 0) {
                            console.log("Element in final loop:", ele)
                            newJSONFlag = true;
                        }
                    }
                })
                console.log("New flag value: ", newJSONFlag)
                if(newJSONFlag) {
                    tmpData += "\n\n" + JSON.stringify(JSON.parse(element.response_body), null, 2);
                } else {
                    tmpData += "\n\n" + element.response_body
                }
                
                var tmpResponseContent = tmpData
                var tmpUpdatedRequest = {id: element.id, name: element.host + element.endpoint, requestContent: tmpRequestContent, responseContent: tmpResponseContent, label: element.id, element: element}
                this.activeRepeaterData = tmpUpdatedRequest;
                var index = this.repeaterRows.findIndex(obj => obj.id === element.id)
                this.repeaterRows[index] = tmpUpdatedRequest 
            } else if(message.action === "detectPlatform") {
                const response = message.message;
                console.log("Platform received:", response);
                this.platformName = response;
                if(response.trim() !== "") {
                    this.sess.$patch({app: {platform: response}})
                }
                this.isPlatformDetectionVisible = false;
            } else if(message.action === "deleteRepeaterTabUpdate") {
                const tabID = message.id;
                const status = message.message;
                // console.log(status);
                
                if(status == true) {
                    // console.log("Tab deleted");
                    var index = this.repeaterRows.findIndex(obj => obj.id === tabID)
                    // console.log("Deletion index:", index);
                    // console.log("Deleting tab:", this.repeaterRows[index]);
                    
                    this.repeaterRows.splice(index, 1);

                    // console.log("Current Active tab:", this.activeRepeaterTab);
                    // console.log("Current Active tab data:", this.repeaterRows[this.activeRepeaterTab]);
                    
                    this.activeRepeaterData = this.repeaterRows[this.activeRepeaterTab]
                    // console.log("New Active tab data:", this.activeRepeaterData);
                    
                } else {
                    console.log("Couldn't delete tab");
                    
                }
            }
        };

        this.connection.onerror = (error) => {
            console.error('WebSocket error:', error);
        };

        this.connection.onclose = () => {
            this.isConnected = false;
            console.log('WebSocket connection closed');
            this.sess.$patch({app: {isConnected: false}})
        };
    },
    updated() {
    },
    methods: {
        tabChanged(event: any) {
            console.log(event);
            if(event.value === "Repeater" && this.repeaterRows.length === 0) {
                this.$toast.add({ severity: 'error', summary: 'Error', detail: 'No tabs in repeater!', life: 3000 });
                // alert("No repeater tabs found")
                this.value = 'Proxy'
            }
        },
        removeTab(event: any, item: any) {
            // event.preventDefault();
            console.log("Removing", event, item);
            
            this.connection.send(JSON.stringify({'action': 'deleteRepeaterTab', 'id': this.activeRepeaterData.id}))
            // alert("Tab removed")
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

            console.log(method);
            console.log(path);
            console.log(headers);
            console.log(body);
            
            const parsedRequest = {
                method,
                "endpoint": path,
                "request_headers": JSON.stringify(headers),
                "request_body": body,
            };
            return parsedRequest;
        },
        replayRequest() {
            if(this.sess.app.deviceId == null || this.sess.app.deviceId.trim() == "" || this.sess.app.name == null || this.sess.app.name.trim() == "") {
                this.$toast.add({ severity: 'info', summary: 'Info', detail: 'Connect to a device and app first!', life: 3000 });
            } else {
                var tmpRepeaterPayload = this.parseRequest(this.activeRepeaterData.requestContent);
                const tmpRepeaterData = this.activeRepeaterData.element;
                console.log(this.activeRepeaterData.element);
                // console.log(tmpRepeaterPayload);
                
                tmpRepeaterPayload['id'] = tmpRepeaterData.id;
                tmpRepeaterPayload['protocol'] = tmpRepeaterData.protocol;
                tmpRepeaterPayload['host'] = tmpRepeaterData.host;
                tmpRepeaterPayload['status_code'] = tmpRepeaterData.status_code
                tmpRepeaterPayload['response_body'] = tmpRepeaterData.response_body
                tmpRepeaterPayload['response_headers'] = tmpRepeaterData.response_headers
                tmpRepeaterPayload['session_id'] = tmpRepeaterData.session_id
                console.log(tmpRepeaterPayload);
                var obj = {
                    'deviceId': localStorage.getItem('deviceId'),
                    'appName': localStorage.getItem('appName'),
                    'sessionId': localStorage.getItem('sessionId'),
                    'appId': localStorage.getItem('appId')
                }
                this.connection.send(JSON.stringify({'action': 'replayRequest', 'replay': tmpRepeaterPayload, 'appData': obj, 'platform': this.sess.app.platform}))
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
                this.connection.send(JSON.stringify({'action': 'sendToRepeater', 'id': row.id}))
            } else {

                console.log(this.repeaterRightClickSelectedTab.id);
                this.connection.send(JSON.stringify({'action': 'duplicateRepeater', 'id': this.repeaterRightClickSelectedTab.id}))
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
            var tmpData = event.data.method + " " + event.data.endpoint + "\n"
            tmpData += JSON.parse(event.data.request_headers).join("\n")
            console.log(event.data);
            console.log(event.data.request_body);
            if(event.data.request_body) {
                tmpData += "\n\n" + event.data.request_body
            } else {
                tmpData += "\n\n " 
            }
            
            this.requestContent = tmpData
            tmpData = JSON.parse(event.data.response_headers).join("\n")
            tmpData += "\n\n" + event.data.response_body
            
            this.responseContent = tmpData
        },
        sendMessage() {
            if (this.isConnected) {
                this.connection.send(JSON.stringify(this.message)); // Send JSON data
                this.message = '';
            } else {
                console.warn('WebSocket connection not established');
            }
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
    },
    mounted() {
        const grid = document.querySelector('revo-grid');
        if (grid) {
            grid.resize = true;
            grid.autoSizeColumn = true;
        }
        // this.setupEditor()
    }
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
