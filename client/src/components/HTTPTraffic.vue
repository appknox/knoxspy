<template>
    <div class="page">
        <!-- <v-grid :source="rows" :columns="columns" /> -->
        <div style="display: flex; align-items: center; border-bottom: 1px solid #eee; position: relative;">
            <SelectButton v-model="value" :options="options" :allow-empty="false" aria-labelledby="basic" style="position: absolute; left: 30px; top: 8px; z-index: 1000; text-align: center"/>

            <!-- <SelectButton v-model="value" :options="options" aria-labelledby="basic" style="margin-left: 30px; margin-right: 30px; padding: 5px"/> -->
        </div>

        <Splitter v-if="value == 'Proxy'" style="height: calc(100vh - 0px)" layout="vertical" v-on:resize="resizedSplitter">
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
                            style="text-align: left; word-wrap: break-word; text-wrap: wrap"
                        />
                    </SplitterPanel>
                    <SplitterPanel class="flex align-items-center justify-content-center" :min-size="50":size="50">
                        <VCodeBlock
                            class="history-viewer-split-code"
                            :code="responseContent"
                            highlightjs
                            lang="http"
                            theme="atom-one-light"
                            style="text-align: left; word-wrap: break-word; text-wrap: wrap"
                        />
                    </SplitterPanel>
                </Splitter>
            </SplitterPanel>
        </Splitter>
    
        <div v-if="value == 'Repeater'">
            <TabMenu :scrollable="true" v-if="value == 'Repeater'" v-model:activeIndex="activeRepeaterTab" :model="repeaterRows" @tab-change="changeRepeater" style="padding-left: 230px; padding-right: 130px;"/>
            <Splitter class="repeater-viewer-split">
                <SplitterPanel class="flex align-items-center justify-content-center"  :size="50">
                    <codemirror
                        v-model="activeRepeaterData.requestContent"
                        placeholder="Code goes here..."
                        style="width: calc(100% - 10px);height: calc(100vh - 67px); border: 0; margin: 5px;  background-color: var(--surface-100)"
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
                        style="width: calc(100% - 10px); height: calc(100vh - 67px); border: 0; margin: 5px; background-color: var(--surface-100)"
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
            <Button label="Replay" style="position: fixed; top: 7px; right: 10px;" icon="pi pi-send" @click="replayRequest"  v-shortkey="['meta', 'd']" @shortkey.native="replayRequest" />
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


export default defineComponent({
    name: 'App',
    data() {
        return {
            dataTableHeight: "calc(60vh - 50px)",
            activeRepeaterTab: 0,
            activeRepeaterData: "",
            selectedRepeaterTab: null,
            sess: null,
            value: 'Repeater',
            options: ['Proxy', 'Repeater'],
            connection: null,
            isConnected: false,
            message: '',
            codeMirrorOptions: {
                extensions: [
                    EditorView.lineWrapping
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
            cmOptions: {
                mode: "text/javascript", // Language mode
                theme: "base16-light", // Theme
            },
            repeaterRequestViewer: null,
            repeaterResponseViewer: null
        };
    },
    components: {
        Toolbar,
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
            console.log('Connected to WebSocket server');
        };

        this.connection.onmessage = (event) => {
            const message = JSON.parse(event.data); // Assuming JSON data
            console.log(message.action);
            // console.log(message.message);
            
            if(message.action == "trafficInit") {
                this.rows = JSON.parse(message.message);
            } else if(message.action == "trafficUpdate") {
                this.rows.push(message.message);
            } else if(message.action == "repeaterAdd") {
                const element = message.message;
                var tmpData = element.method + " " + element.endpoint + "\n"
                tmpData += JSON.parse(element.request_headers).join("\n")
                console.log(element);
                console.log(element.request_body);
                if(element.request_body) {
                    tmpData += "\n\n" + element.request_body
                } else {
                    tmpData += "\n\n " 
                }
                
                var tmpRequestContent = tmpData
                tmpData = JSON.parse(element.response_headers).join("\n")
                tmpData += "\n\n" + element.response_body
                
                var tmpResponseContent = tmpData
                this.repeaterRows.push({id: element.id, name: element.host + element.endpoint, requestContent: tmpRequestContent, responseContent: tmpResponseContent, label: element.id, element: element})
                // this.repeaterRows.push({label: element.host + element.endpoint})
                this.value = "Repeater"
            } else if(message.action == "repeaterUpdate") {
                console.log(message.message)
                message.message.forEach((element: any) => {
                    var tmpData = element.method + " " + element.endpoint + "\n"
                    tmpData += JSON.parse(element.request_headers).join("\n")
                    // console.log(element);
                    // console.log(element.request_body);
                    if(element.request_body) {
                        tmpData += "\n\n" + element.request_body
                    } else {
                        tmpData += "\n\n " 
                    }
                    
                    var tmpRequestContent = tmpData
                    tmpData = JSON.parse(element.response_headers).join("\n")
                    tmpData += "\n\n" + element.response_body
                    
                    var tmpResponseContent = tmpData
                    this.repeaterRows.push({id: element.id, name: element.host + element.endpoint, requestContent: tmpRequestContent, responseContent: tmpResponseContent, label: element.id, element: element})
                });
                this.activeRepeaterData = this.repeaterRows[0]
                console.log("Repeater update:", this.activeRepeaterData)
                
            } else if(message.action === "replayUpdate") {
                const element = message.replay;
                var tmpData = element.method + " " + element.endpoint + "\n"
                tmpData += JSON.parse(element.request_headers).join("\n")
                // console.log(element);
                // console.log(element.request_body);
                if(element.request_body) {
                    tmpData += "\n\n" + element.request_body
                } else {
                    tmpData += "\n\n " 
                }
                
                var tmpRequestContent = tmpData
                tmpData = JSON.parse(element.response_headers).join("\n")
                tmpData += "\n\n" + element.response_body
                
                var tmpResponseContent = tmpData
                var tmpUpdatedRequest = {id: element.id, name: element.host + element.endpoint, requestContent: tmpRequestContent, responseContent: tmpResponseContent, label: element.id, element: element}
                this.activeRepeaterData = tmpUpdatedRequest;
                var index = this.repeaterRows.findIndex(obj => obj.id === element.id)
                this.repeaterRows[index] = tmpUpdatedRequest 
            }
        };

        this.connection.onerror = (error) => {
            console.error('WebSocket error:', error);
        };

        this.connection.onclose = () => {
            this.isConnected = false;
            console.log('WebSocket connection closed');
        };
    },
    updated() {
    },
    methods: {
        resizedSplitter(event) {
            console.log("Resizing");
            console.log(event.sizes);
            this.dataTableHeight = `calc(${event.sizes[0]}vh - 55px)`;
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
            var tmpRepeaterPayload = this.parseRequest(this.activeRepeaterData.requestContent);
            const tmpRepeaterData = this.activeRepeaterData.element;
            console.log(this.activeRepeaterData.element);
            // console.log(tmpRepeaterPayload);
            
            tmpRepeaterPayload['id'] = tmpRepeaterData.id;
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
            this.connection.send(JSON.stringify({'action': 'replayRequest', 'replay': tmpRepeaterPayload, 'appData': obj}))
        },
        changeRepeater(event: any) {
            console.log("Changed to Repeater");
            console.log(this.activeRepeaterData);
            this.activeRepeaterData = this.repeaterRows[event.index]
            // this.re
            // this.repeaterRequestViewer.setValue(this.activeRepeaterData.requestContent)
            // this.repeaterResponseViewer.setValue(this.activeRepeaterData.responseContent)
        },
        setupEditor() {
            // console.log(document.getElementsByClassName("code-editor"))
            // this.repeaterRequestViewer = CodeMirror.fromTextArea(document.getElementById("code-editor"), {
            //     lineNumbers: true,
            //     mode: "http",
            //     theme: "idea",
            //     lineWrapping: true
            // });
            // this.repeaterResponseViewer = CodeMirror.fromTextArea(document.getElementById("code-viewer"), {
            //     lineNumbers: true,
            //     mode: "http",
            //     theme: "idea",
            //     lineWrapping: true,
            //     readOnly: true,
                
            // });
        },
        handleReady(payload: any) {
            this.view.value = payload.view
        },
        sendToRepeater(row: any) {
            console.log(row.id);
            this.connection.send(JSON.stringify({'action': 'sendToRepeater', 'id': row.id}))
            
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
        this.setupEditor()
    }
});
</script>


<style scoped>
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
