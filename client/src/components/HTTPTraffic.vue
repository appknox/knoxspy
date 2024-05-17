<template>
    <div class="page">
        <!-- <v-grid :source="rows" :columns="columns" /> -->
        
        <Splitter style="height: 100vh" layout="vertical">
            <SplitterPanel class="flex align-items-center justify-content-center" :size="60">
                <DataTable selectionMode="single" @rowSelect="onRequestSelect" dataKey="id" class="traffic-history" :filters="filters" sortField="id" :sortOrder="-1" :value="rows" scrollable scroll-height="100vh" tableStyle="min-width: 50rem" :globalFilterFields="['host', 'url']">
                    <template #header :style="{'margin':0, 'padding':0}" class="traffic-header" :class="{'hidden': visibleTrafficHeader}">
                        <div class="traffic-header-inner flex justify-content-end" style="display: flex; justify-content: space-between;" :style="{'display': visibleTrafficHeader ? 'flex': 'none'}" v-shortkey="['meta', 'f']" @shortkey.native="toggleTrafficHeader">
                            <Button type="button" icon="pi pi-filter-slash" label="Clear" outlined @click="" />
                            <IconField iconPosition="left">
                                <InputIcon class="pi pi-search"> </InputIcon>
                                <InputText v-model="filters['global'].value" placeholder="Keyword Search" />
                            </IconField>
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
                    <SplitterPanel class="flex align-items-center justify-content-center" :size="50">
                        <VCodeBlock
                            :code="requestContent"
                            highlightjs
                            lang="http"
                            theme="vs"
                            style="text-align: left;"
                        />
                    </SplitterPanel>
                    <SplitterPanel class="flex align-items-center justify-content-center" :size="50">
                        <VCodeBlock
                            :code="responseContent"
                            highlightjs
                            lang="http"
                            theme="atom-one-light"
                            style="text-align: left;"
                        />
                    </SplitterPanel>
                </Splitter>
            </SplitterPanel>
        </Splitter>

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
// import Prism from "prismjs";
// import "prismjs/themes/prism-dark.css";
// import 'prismjs/components/prism-http';
import HighlightJS from 'highlightjs';
import "highlightjs/styles/vs.css";



export default defineComponent({
    name: 'App',
    data() {
        return {
            connection: null,
            isConnected: false,
            message: '',
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
            requestContent: "",
            responseContent: "",
            visibleTrafficHeader: false,
        };
    },
    components: {
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
        HighlightJS
    },
    created() {
        // Replace with your server URL
        const url = 'ws://192.168.29.203:8000';
        this.connection = new WebSocket(url);

        this.connection.onopen = () => {
            this.isConnected = true;
            console.log('Connected to WebSocket server');
        };

        this.connection.onmessage = (event) => {
            const message = JSON.parse(event.data); // Assuming JSON data
            console.log(message.action);
            console.log(message.message);
            
            if(message.action == "trafficInit") {
                this.rows = JSON.parse(message.message);
            } else if(message.action == "trafficUpdate") {
                this.rows.push(message.message);
            }

            console.log(this.rows);
            
            
        };

        this.connection.onerror = (error) => {
            console.error('WebSocket error:', error);
        };

        this.connection.onclose = () => {
            this.isConnected = false;
            console.log('WebSocket connection closed');
        };
    },
    methods: {
        toggleTrafficHeader() {
            this.visibleTrafficHeader = !this.visibleTrafficHeader
        },
        onRequestSelect(event: any) {
            var tmpData = event.data.method + " " + event.data.endpoint + "\n"
            tmpData += JSON.parse(event.data.request_headers).join("\n")
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
    }
});
</script>


<style scoped>
.p-datatable .p-datatable-header {
    padding: 0 !important;
    margin: 0;
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
