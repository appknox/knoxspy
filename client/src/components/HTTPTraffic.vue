<template>
    <div class="page">
        <!-- <v-grid :source="rows" :columns="columns" /> -->
        <DataTable :filters="filters" sortField="id" :sortOrder="-1" :value="rows" scrollable scroll-height="100vh" tableStyle="min-width: 50rem" :globalFilterFields="['host', 'url']">
            <template #header>
                <div class="flex justify-content-end" style="display: flex; justify-content: space-between;">
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
            <Column field="url" header="Endpoint" sortable style="width: 300px; font-size: 13px"></Column>
            <Column field="status" header="Status" sortable style="width: 100px; font-size: 13px"></Column>
            <Column field="length" header="Length" sortable style="width: 70px; font-size: 13px"></Column>
        </DataTable>
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
                { prop: "url", name: "URL", sortable: true, size: window.innerWidth - 200 - 50 - 100 - 200 - 100 - 70 },
                { prop: "status", name: "Status Code", sortable: true, size: 100 },
                { prop: "length", name: "Length", sortable: true, size: 70 }
            ],
            filters: {
                global: { value: null, matchMode: FilterMatchMode.CONTAINS },
                host: { value: null, matchMode: FilterMatchMode.CONTAINS },
                endpoint: { value: null, matchMode: FilterMatchMode.CONTAINS }
            },
            rows: [],
        };
    },
    components: {
        VGrid,
        DataTable,
        Column,
        InputText,
        IconField,
        InputIcon,
        Button
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
.p-datatable-header {
    position: absolute;
    z-index: 1001;
    top: 0;
}
.p-column-title	{
    font-size: 12px;
}
.page {
    position: absolute;
    left: 200px;
    width: calc(100% - 200px);
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
