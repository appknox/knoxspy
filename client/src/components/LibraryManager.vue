<template>
	<div class="page page-library-manager">
        <h1>Library Manager</h1>
        <TabView style="width: 1000px; margin: 0 auto;">
            <TabPanel>
                <template #header>
                    <div class="flex align-items-center gap-2">
                        <i class="pi pi-bars" style="font-size: 1rem; margin-right: 5px;"></i>
                        <span class="font-bold white-space-nowrap">All Libraries</span>
                    </div>
                </template>
                <p class="m-0"> 
          
                    <div class="card flex justify-content-center" style="width: 700px; margin: 0 auto">
                        <Listbox v-model="selectedLibrary" :options="libraries" optionLabel="name" class="w-full md:w-14rem" listStyle="max-height:250px" :focusOnHover="false">
                            <template #option="slotProps">
                                <div class="flex align-items-start flex-column" style="display: flex; gap: 10px; align-items: center">
                                    <div>
                                        <i style="font-size: 30px; color: #222831;" class="pi" :class="{ 'pi-apple' : slotProps.option.platform == 'iOS', 'pi-android': slotProps.option.platform === 'Android'}"></i>
                                    </div>
                                    <div style="flex-grow: 1;">
                                        <div style="text-align: left;">{{ slotProps.option.name }}</div>
                                        <div style="font-size: 15px;margin-top: 3px; color: var(--primary-color); text-align: left;">File: {{ slotProps.option.file }}</div>
                                    </div>
                                    <div style="gap: 0px; display: flex;">
                                            <Button severity="info" label="View" icon="pi pi-eye" size="small" rounded text/>
                                            <Button label="Edit" icon="pi pi-pencil" size="small" rounded text/>
                                            <Button severity="danger" label="Delete" size="small" icon="pi pi-trash" rounded text/>
                                    </div>
                                </div>
                            </template>
                        </Listbox>
                    </div>

                </p>
            </TabPanel>
            <TabPanel>
                <template #header>
                    <div class="flex align-items-center gap-2">
                        <i class="pi pi-plus" style="font-size: 1rem; margin-right: 5px;"></i>
                        <span class="font-bold white-space-nowrap">Add New</span>
                    </div>
                </template>
                <p class="m-0">
                    <Stepper linear>
                        <StepperPanel header="Upload File" style="height: 400px;">
                            <template #content="{ nextCallback }">
                                <div class="flex flex-column h-12rem">
                                    <div class="border-2 border-dashed surface-border border-round surface-ground flex-auto flex justify-content-center align-items-center font-medium">
                                        <div class="card">
                                            <Toast />
                                            <FileUpload name="demo[]" url="/api/upload" @upload="onTemplatedUpload($event)" :multiple="true" accept="application/javascript,text/javascript,text/plain" :maxFileSize="1000000" @select="onSelectedFiles" style="width: 100%;">
                                                <template #header="{ chooseCallback, uploadCallback, clearCallback, files }">
                                                    <div class="flex flex-wrap justify-content-between align-items-center flex-1 gap-2" style="display: flex; justify-content: space-between;width: 100%;align-items: center">
                                                        <div class="flex gap-2">
                                                            <Button @click="chooseCallback()" icon="pi pi-images" rounded outlined></Button>
                                                            <Button @click="uploadEvent(uploadCallback)" icon="pi pi-cloud-upload" rounded outlined severity="success" :disabled="!files || files.length === 0"></Button>
                                                            <Button @click="clearCallback()" icon="pi pi-times" rounded outlined severity="danger" :disabled="!files || files.length === 0"></Button>
                                                        </div>
                                                        <ProgressBar style="width: 200px;" :value="totalSizePercent" :showValue="false" :class="['md:w-20rem h-1rem w-full md:ml-auto', { 'exceeded-progress-bar': totalSizePercent > 100 }]"
                                                            ><span class="white-space-nowrap">{{ totalSize }}B / 1Mb</span></ProgressBar
                                                        >
                                                    </div>
                                                </template>
                                                <template #content="{ files, uploadedFiles, removeUploadedFileCallback, removeFileCallback }">
                                                    <div v-if="files.length > 0">
                                                        <h5>Pending</h5>
                                                        <div class="flex flex-wrap p-0 sm:p-5 gap-5">
                                                            <div v-for="(file, index) of files" :key="file.name + file.type + file.size" class="card m-0 px-6 flex flex-column border-1 surface-border align-items-center gap-3">
                                                                <div>
                                                                    <img role="presentation" :alt="file.name" :src="file.objectURL" width="100" height="50" />
                                                                </div>
                                                                <span class="font-semibold">{{ file.name }}</span>
                                                                <div>{{ formatSize(file.size) }}</div>
                                                                <Badge value="Pending" severity="warning" />
                                                                <Button icon="pi pi-times" @click="onRemoveTemplatingFile(file, removeFileCallback, index)" outlined rounded  severity="danger" />
                                                            </div>
                                                        </div>
                                                    </div>

                                                    <div v-if="uploadedFiles.length > 0">
                                                        <h5>Completed</h5>
                                                        <div class="flex flex-wrap p-0 sm:p-5 gap-5">
                                                            <div v-for="(file, index) of uploadedFiles" :key="file.name + file.type + file.size" class="card m-0 px-6 flex flex-column border-1 surface-border align-items-center gap-3">
                                                                <div>
                                                                    <img role="presentation" :alt="file.name" :src="file.objectURL" width="100" height="50" />
                                                                </div>
                                                                <span class="font-semibold">{{ file.name }}</span>
                                                                <div>{{ formatSize(file.size) }}</div>
                                                                <Badge value="Completed" class="mt-3" severity="success" />
                                                                <Button icon="pi pi-times" @click="removeUploadedFileCallback(index)" outlined rounded  severity="danger" />
                                                            </div>
                                                        </div>
                                                    </div>
                                                </template>
                                                <template #empty>
                                                    <div class="flex align-items-center justify-content-center flex-column">
                                                        <i class="pi pi-cloud-upload border-2 border-circle p-5 text-8xl text-400 border-400"  style="font-size: 100px; color: #222831dd"/>
                                                        <p class="mt-4 mb-0">Drag and drop files to here to upload.</p>
                                                    </div>
                                                </template>
                                            </FileUpload>
                                        </div>
                                    </div>
                                </div>
                                <div class="flex pt-4 justify-content-end" style="margin-top: 20px;">
                                    <Button label="Next" icon="pi pi-arrow-right" iconPos="right" @click="nextCallback" />
                                </div>
                            </template>
                        </StepperPanel>
                        <StepperPanel header="Platform Selection" style="height: 400px;">
                            <template #content="{ prevCallback, nextCallback }">
                                <div class="flex flex-column h-12rem">
                                    <div class="border-2 border-dashed surface-border border-round surface-ground flex-auto flex justify-content-center align-items-center font-medium">Content II</div>
                                </div>
                                <div class="flex pt-4 justify-content-between">
                                    <Button label="Back" severity="secondary" icon="pi pi-arrow-left" @click="prevCallback" />
                                    <Button label="Next" icon="pi pi-arrow-right" iconPos="right" @click="nextCallback" />
                                </div>
                            </template>
                        </StepperPanel>
                        <StepperPanel header="Final" style="height: 400px;">
                            <template #content="{ prevCallback }">
                                <div class="flex flex-column h-12rem">
                                    <div class="border-2 border-dashed surface-border border-round surface-ground flex-auto flex justify-content-center align-items-center font-medium">Content III</div>
                                </div>
                                <div class="flex pt-4 justify-content-start">
                                    <Button label="Back" severity="secondary" icon="pi pi-arrow-left" @click="prevCallback" />
                                </div>
                            </template>
                        </StepperPanel>
                    </Stepper>
                </p>
            </TabPanel>
        </TabView>
	</div>
</template>

<script lang="ts">
import { defineComponent } from "vue";
import Card from "primevue/card";
import Toast from "primevue/toast";
import FileUpload from "primevue/fileupload";
import Button from "primevue/button";
import Badge from "primevue/badge";
import ProgressBar from "primevue/progressbar";
import Splitter from "primevue/splitter";
import SplitterPanel from "primevue/splitterpanel";
import Stepper from 'primevue/stepper';
import StepperPanel from "primevue/stepperpanel";
import Listbox from "primevue/listbox";
import TabView from 'primevue/tabview';
import TabPanel from 'primevue/tabpanel';
import ListBox from "primevue/listbox";
import ButtonGroup from 'primevue/buttongroup';


export default defineComponent({
	name: 'LibraryManager',
    components: {
        Card,
        Toast,
        FileUpload,
        Button,
        Badge,
        ProgressBar,
        Splitter,
        SplitterPanel,
        Stepper,
        StepperPanel,
        Listbox,
        TabView,
        TabPanel,
        ListBox,
        ButtonGroup,
    },
    data() {
        return { 
            files: [],
            totalSize: 0,
            totalSizePercent: 0,
            libraries: null,
            selectedLibrary: "",
            products: null
        }
    },
    created() {
        const url = 'ws://' + import.meta.env.VITE_SERVER_IP + ':8000';
        this.ws = new WebSocket(url);

        this.ws.onopen = () => {
            // this.isConnected = true;
            console.log('Connected to WebSocket server');
            const json = {"action":"library"}
            this.ws.send(JSON.stringify(json))
            // this.fetchApps()
            // this.startApp("com.appknox.SSL-Pinning-Test", "SSL Pinning Test")
        };

        this.ws.onmessage = (event: { data: string; }) => {
            const message = JSON.parse(event.data);
            this.libraries = [];
            if(message['action'] === 'library') {
                const tmpJsonData = JSON.parse(message['message'])
                for(const a in tmpJsonData) {
                    console.log(tmpJsonData[a]);
                    
                    const b = tmpJsonData[a];
                    this.libraries.push({"name": b.name, "id": b.id, "file": b.file, "platform": b.platform});
                }
                console.log(this.libraries);
                
                // if(this.data.length == 1) {
                //     this.fetchApps()
                // }
            }
        };

        this.ws.onerror = (error: any) => {
            console.error('WebSocket error:', error);
        };

        this.ws.onclose = () => {
            this.isConnected = false;
            console.log('WebSocket connection closed');
        };
    },
    methods: {
        onRemoveTemplatingFile(file, removeFileCallback, index) {
            removeFileCallback(index);
            this.totalSize -= parseInt(this.formatSize(file.size));
            this.totalSizePercent = this.totalSize / 10;
        },
        onClearTemplatingUpload(clear) {
            clear();
            this.totalSize = 0;
            this.totalSizePercent = 0;
        },
        onSelectedFiles(event) {
            this.files = event.files;
            this.files.forEach((file) => {
                this.totalSize += parseInt(this.formatSize(file.size));
            });
        },
        uploadEvent(callback) {
            this.totalSizePercent = this.totalSize / 10;
            callback();
        },
        onTemplatedUpload() {
            this.$toast.add({ severity: 'info', summary: 'Success', detail: 'File Uploaded', life: 3000 });
        },
        formatSize(bytes) {
            const k = 1024;
            const dm = 3;
            const sizes = this.$primevue.config.locale.fileSizeTypes;

            if (bytes === 0) {
                return `0 ${sizes[0]}`;
            }

            const i = Math.floor(Math.log(bytes) / Math.log(k));
            const formattedSize = parseFloat((bytes / Math.pow(k, i)).toFixed(dm));

            return `${formattedSize} ${sizes[i]}`;
        }
    },
});
</script>

<style>
.page {
    overflow: hidden;
    /* flex-grow: 1; */
	height: 100%;
	background-color: #222831;
    background-color: #fff;
}
.page-library-manager {
    padding: 30px;
}
.page h1 {
    margin: 0;
    padding: 0;
    height: 100px;
    font: 35px "Fira Code";
    font-variant: small-caps;
}
.page h5 {
    margin: 0 0 10px;
    padding: 10px 0;
    font-size: 20px;
    font-weight: 400;
    border-radius: 10px;
    background-color: #eee;
}
.p-stepper {
    flex-basis: 50rem;
}
</style>
