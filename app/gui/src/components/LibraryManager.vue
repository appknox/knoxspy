<template>
	<div class="page page-library-manager">
        <h1>Library Manager</h1>
        <TabView style="width: 1000px; margin: 0 auto;" :activeIndex="tabViewActiveIndex" @update:activeIndex="onTabViewChange">
            <TabPanel>
                <template #header>
                    <div class="flex align-items-center gap-2">
                        <i class="pi pi-bars" style="font-size: 1rem; margin-right: 5px;"></i>
                        <span class="font-bold white-space-nowrap">All Libraries</span>
                    </div>
                </template>
                <p class="m-0"> 
          
                    <div class="card flex justify-content-center" style="width: 700px; margin: 0 auto">
                        <Listbox v-model="selectedLibrary" :options="libraries" optionLabel="name" class="w-full md:w-14rem" listStyle="minx-height:250px" :focusOnHover="false">
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
                    <Stepper linear @step-change="onStepperChanged" v-model:activeStep="stepperActiveIndex">
                        <StepperPanel header="Configuration" style="height: 400px;">
                            <template #content="{ nextCallback }">
                                <div class="flex flex-column h-12rem">
                                    <div class="border-2 border-dashed surface-border border-round surface-ground flex-auto flex justify-content-center align-items-center font-medium">
                                        <div class="card">
                                            <FloatLabel style="width: 400px; margin: 30px auto 30px;">
                                                <InputText id="username" v-model="libraryNameValue" style="width: 350px;" @input="changeSelectedPlatform"/>
                                                <label for="username" style="width: 350px;">Library Name</label>
                                            </FloatLabel>
                                            <Dropdown style="width: 350px;" v-model="selectedPlatform" @change="changeSelectedPlatform" :options="platforms" optionLabel="name" placeholder="Select a Platform" class="w-full md:w-14rem">
                                                <template #value="slotProps">
                                                    <div v-if="slotProps.value" class="flex align-items-center">
                                                        <div><i :class="slotProps.value.icon" style="margin-right: 5px;"></i>{{ slotProps.value.name }}</div>
                                                    </div>
                                                    <span v-else>
                                                        {{ slotProps.placeholder }}
                                                    </span>
                                                </template>
                                                <template #option="slotProps">
                                                    <div class="flex align-items-center">
                                                        
                                                        <div><i :class="slotProps.option.icon" style="margin-right: 5px;"></i>{{ slotProps.option.name }}</div>
                                                    </div>
                                                </template>
                                            </Dropdown>
                                            
                                        </div>
                                    </div>
                                </div>
                                <div class="flex pt-4 justify-content-end" style="margin-top: 20px;">
                                    <Button :disabled="isNextButtonDisabled" label="Next" icon="pi pi-arrow-right" iconPos="right" @click="nextCallback" />
                                </div>
                            </template>
                        </StepperPanel>
                        <StepperPanel header="Upload ZIP File" style="height: 400px;">
                            <template #content="{ prevCallback, nextCallback }">
                                <div class="flex flex-column h-12rem">
                                    <div class="border-2 border-dashed surface-border border-round surface-ground flex-auto flex justify-content-center align-items-center font-medium">
                                        <div class="card">
                                            <Toast />
                                            <FileUpload name="demo[]" :url="fileUploadURL" @upload="onTemplatedUpload($event)" :multiple="true" accept="application/zip" :maxFileSize="100000000" @select="onSelectedFiles" style="width: 100%;">
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
                                                                    <i class="pi pi-file-import" style="font-size: 45px; padding: 20px; color: #f97316"></i>
                                                                </div> 
                                                                <span class="font-semibold">{{ file.name }}</span>
                                                                <div>{{ formatSize(file.size) }}</div>
                                                                <Button style="margin-top: 20px;" icon="pi pi-times" @click="onRemoveTemplatingFile(file, removeFileCallback, index)" outlined rounded  severity="danger" />
                                                            </div>
                                                        </div>
                                                    </div>

                                                    <div v-if="uploadedFiles.length > 0">
                                                        <h5>Completed</h5>
                                                        <div class="flex flex-wrap p-0 sm:p-5 gap-5">
                                                            <div v-for="(file, index) of uploadedFiles" :key="file.name + file.type + file.size" class="card m-0 px-6 flex flex-column border-1 surface-border align-items-center gap-3">
                                                                <div>
                                                                    <i class="pi pi-file-plus" style="font-size: 45px; padding: 20px; color: var(--green-700)"></i>
                                                                </div>
                                                                <span class="font-semibold">{{ file.name }}</span>
                                                                <div>{{ formatSize(file.size) }}</div>
                                                                <Button style="margin-top: 20px;" icon="pi pi-times" @click="removeUploadedFileCallback(index)" outlined rounded  severity="danger" />
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
                                <div class="flex pt-4 justify-content-between" style="margin-top: 20px;">
                                    <Button label="Back" severity="secondary" icon="pi pi-arrow-left" @click="prevCallback" style="margin-right: 10px;"/>
                                    <Button :disabled="isNextButtonDisabled" label="Next" icon="pi pi-arrow-right" iconPos="right" @click="nextCallback" />
                                </div>
                            </template>
                        </StepperPanel>
                        <StepperPanel header="Finalising Setup" style="height: 400px;">
                            <template #content="{ prevCallback }">
                                <div class="flex flex-column h-12rem">
                                    <div class="border-2 border-dashed surface-border border-round surface-ground flex-auto flex justify-content-center align-items-center font-medium">
                                        <div v-if="librarySetupDone == false" class="card">
                                            <p style=" font-size: 23px; color: var(--surface-600);margin-top: 20px;">Setting up library...</p>
                                            <i class="pi pi-spinner pi-spin" style="margin-bottom: 40px; font-size: 45px; color: var(--green-600)"></i>
                                        </div>
                                        <div v-if="librarySetupDone == true" class="card">
                                            <p style=" font-size: 23px; color: var(--surface-600);margin-top: 20px;">Library setup done!</p>
                                        </div>
                                    </div>
                                </div>
                                <div class="flex pt-4 justify-content-start">
                                    <Button label="Finish" severity="success" icon="pi pi-check" @click="setupDone" />
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
import Dropdown from 'primevue/dropdown';
import axios from 'axios';
import FloatLabel from 'primevue/floatlabel';
import InputText from 'primevue/inputtext';
import {useSessionStore} from '../stores/session';

export default defineComponent({
	name: 'LibraryManager',
    components: {
        InputText,
        FloatLabel,
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
        Dropdown
    },
    data() {
        return {
            libraryNameValue: "",
            tabViewActiveIndex: 0,
            librarySetupDone: false,
            isNextButtonDisabled: true,
            stepperActiveIndex: 0,
            files: [],
            totalSize: 0,
            totalSizePercent: 0,
            libraries: null,
            selectedLibrary: "",
            products: null,
            platforms: [
                {'name': 'iOS', 'icon': 'pi pi-apple'},
                {'name': 'Android', 'icon': 'pi pi-android'},
            ],
            selectedPlatform: "",
            selectedFileName: "",
            ws: null,
            host: "",
            fileUploadURL: ""
        }
    },
    created() {
        this.sess = useSessionStore()
        this.host = import.meta.env.VITE_SERVER_IP
        this.fileUploadURL = "http://" + import.meta.env.VITE_SERVER_IP + ":8000/api/upload"
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
                console.log(tmpJsonData);
                
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
            this.sess.$patch({app: {isConnected: false}})
        };
    },
    methods: {
        onStepperIndexChanged(event) {
            console.log("Stepper event", event);
            
        },
        onTabViewChange(event) {
            this.tabViewActiveIndex = event
        },
        setupDone() {
            this.selectedPlatform = ""
            this.selectedFileName = ""
            this.libraryNameValue = ""
            this.stepperActiveIndex = 0
            this.tabViewActiveIndex = 0


            const json = {"action":"library"}
            this.ws.send(JSON.stringify(json))
        },
        changeSelectedPlatform(event) {
            // console.log("-->" + this.selectedPlatform + "<--");
            
            // console.log("Detect:", this.selectedPlatform != "", this.libraryNameValue.trim() != "", this.selectedPlatform != "" && this.libraryNameValue.trim() != "");            
            this.isNextButtonDisabled = (this.selectedPlatform == "") || (this.libraryNameValue.trim() == "");
        },
        onStepperChanged(event) {
            // console.log("Stepper", this.stepperActiveIndex);
            this.stepperActiveIndex = event.index;
            // this.stepperActiveIndex = 2
            // console.log("Stepper", this.stepperActiveIndex);
            
            this.isNextButtonDisabled = true;
            const tmpIndex = event.index;
            if(tmpIndex === 1) {
                if(!this.selectedPlatform || this.selectedPlatform == "") {
                    this.$toast.add({ severity: 'error', summary: 'Error', detail: "No platform selected!", life: 3000 });
                }
                if(!this.libraryNameValue || this.libraryNameValue == "") {
                    this.$toast.add({ severity: 'error', summary: 'Error', detail: "No library name entered!", life: 3000 });
                }
            } else if(tmpIndex === 2) {
                if(!this.selectedFileName || this.selectedFileName == "") {
                    this.$toast.add({ severity: 'error', summary: 'Error', detail: "No ZIP file uploaded!", life: 3000 });
                } else {
                    this.setupLibrary();
                }
            } else if(tmpIndex === 3) {
                if(!this.selectedFileName || this.selectedFileName == "" || !this.selectedPlatform || this.selectedPlatform == "") {
                    this.$toast.add({ severity: 'error', summary: 'Error', detail: "Some steps were skipped!", life: 3000 });
                }
            }
        },
        async setupLibrary() {
            try {
                const formData = new FormData();
                formData.append('filename', this.selectedFileName);
                formData.append('platform', this.selectedPlatform.name);
                formData.append("library", this.libraryNameValue);
                const response = await axios.post('http://'+this.host+':8000/api/setup_library', formData, {
                    headers: {
                        'Content-Type': 'multipart/form-data'
                    }
                });
                if(response.data.status) {
                    this.librarySetupDone = true
                }
                
            } catch (error) {
                console.error('Error uploading file:', error);
            }
        },
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
        onTemplatedUpload(event) {
            const response = JSON.parse(event.xhr.response);
            // console.log(response);
            
            if(response.status) {
                this.$toast.add({ severity: 'info', summary: 'Success', detail: 'File Uploaded', life: 3000 });
                this.selectedFileName = response.filename;
                this.isNextButtonDisabled = false;
            } else {
                this.$toast.add({ severity: 'error', summary: 'Error', detail: response.message, life: 3000 });
            }
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
