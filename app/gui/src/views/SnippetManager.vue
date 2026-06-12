<template>
	<div class="page page-snippet-manager">
        <h1>Snippet Library</h1>
        <div class="flex justify-content-end mb-4" style="margin-bottom: 20px; display: flex; justify-content: flex-end; gap: 10px;">
            <Button label="New Snippet" icon="pi pi-plus" @click="openNew" />
            <Button label="Fetch from Codeshare" icon="pi pi-cloud-download" severity="secondary" @click="openCodeshareDialog" />
        </div>

        <DataTable :value="snippets" tableStyle="min-width: 50rem" size="small" class="snippet-table">
            <Column field="name" header="Name" sortable></Column>
            <Column field="platform" header="Platform" sortable>
                <template #body="slotProps">
                    <i class="pi" :class="{ 'pi-apple' : slotProps.data.platform == 'iOS', 'pi-android': slotProps.data.platform === 'Android'}"></i>
                    <span style="margin-left: 10px">{{ slotProps.data.platform }}</span>
                </template>
            </Column>
            <Column field="source_type" header="Source" sortable>
                <template #body="slotProps">
                    <Tag :value="slotProps.data.source_type" :severity="slotProps.data.source_type === 'codeshare' ? 'info' : 'success'" />
                </template>
            </Column>
            <Column field="created_at" header="Created" sortable>
                <template #body="slotProps">
                    {{ new Date(slotProps.data.created_at).toLocaleString() }}
                </template>
            </Column>
            <Column :exportable="false" style="min-width:8rem">
                <template #body="slotProps">
                    <Button icon="pi pi-pencil" outlined rounded class="mr-2" style="margin-right: 5px" @click="editSnippet(slotProps.data)" />
                    <Button icon="pi pi-trash" outlined rounded severity="danger" @click="confirmDeleteSnippet(slotProps.data)" />
                </template>
            </Column>
        </DataTable>

        <!-- Edit/New Dialog -->
        <Dialog v-model:visible="snippetDialog" :style="{width: '80vw'}" header="Snippet Details" :modal="true" class="p-fluid">
            <div class="field" style="margin-bottom: 15px">
                <label for="name">Name</label>
                <InputText id="name" v-model.trim="snippet.name" required="true" autofocus :class="{'p-invalid': submitted && !snippet.name}" />
                <small class="p-error" v-if="submitted && !snippet.name">Name is required.</small>
            </div>
            <div class="field" style="margin-bottom: 15px">
                <label for="platform">Platform</label>
                <Dropdown id="platform" v-model="snippet.platform" :options="platforms" optionLabel="label" optionValue="value" placeholder="Select a Platform" />
            </div>
            <div class="field">
                <label for="content">Script Content</label>
                <div style="border: 1px solid #ccc; border-radius: 4px; overflow: hidden;">
                    <codemirror
                        v-model="snippet.content"
                        placeholder="Paste Frida script here..."
                        :style="{ height: '400px' }"
                        :autofocus="true"
                        :indent-with-tab="true"
                        :tab-size="2"
                        :extensions="codeMirrorExtensions"
                    />
                </div>
            </div>
            <template #footer>
                <Button label="Cancel" icon="pi pi-times" text @click="hideDialog"/>
                <Button label="Save" icon="pi pi-check" text @click="saveSnippet" />
            </template>
        </Dialog>

        <!-- Codeshare Dialog -->
        <Dialog v-model:visible="codeshareDialog" :style="{width: '450px'}" header="Fetch from Codeshare" :modal="true" class="p-fluid">
            <div class="field">
                <label for="codeshareUrl">Codeshare URL</label>
                <div style="display: flex; gap: 10px; align-items: center">
                    <InputText id="codeshareUrl" v-model="codeshareUrl" placeholder="e.g. https://codeshare.frida.re/@dzonerzy/unpinning" />
                    <Button icon="pi pi-search" :loading="fetchingCodeshare" @click="fetchCodeshare" />
                </div>
                <small>Or project handle: @user/project</small>
            </div>
        </Dialog>

        <!-- Delete Confirmation -->
        <Dialog v-model:visible="deleteSnippetDialog" :style="{width: '450px'}" header="Confirm" :modal="true">
            <div class="confirmation-content">
                <i class="pi pi-exclamation-triangle mr-3" style="font-size: 2rem; margin-right: 15px" />
                <span v-if="snippet">Are you sure you want to delete <b>{{snippet.name}}</b>?</span>
            </div>
            <template #footer>
                <Button label="No" icon="pi pi-times" text @click="deleteSnippetDialog = false"/>
                <Button label="Yes" icon="pi pi-check" text @click="deleteSnippet" />
            </template>
        </Dialog>
    </div>
</template>

<script lang="ts">
import { defineComponent } from "vue";
import DataTable from 'primevue/datatable';
import Column from 'primevue/column';
import Button from 'primevue/button';
import Dialog from 'primevue/dialog';
import InputText from 'primevue/inputtext';
import Dropdown from 'primevue/dropdown';
import Tag from 'primevue/tag';
import { Codemirror } from 'vue-codemirror';
import { javascript } from '@codemirror/lang-javascript';
import { useWebSocketStore } from "../stores/session";

export default defineComponent({
    name: 'SnippetManager',
    components: {
        DataTable,
        Column,
        Button,
        Dialog,
        InputText,
        Dropdown,
        Tag,
        Codemirror
    },
    data() {
        return {
            ws: useWebSocketStore(),
            snippets: [],
            snippet: {
                id: null,
                name: '',
                content: '',
                platform: 'Android',
                source_type: 'manual',
                source_url: ''
            },
            platforms: [
                {label: 'Android', value: 'Android'},
                {label: 'iOS', value: 'iOS'}
            ],
            snippetDialog: false,
            deleteSnippetDialog: false,
            codeshareDialog: false,
            submitted: false,
            codeshareUrl: '',
            fetchingCodeshare: false,
            codeMirrorExtensions: [javascript()]
        }
    },
    created() {
        this.ws.addOnMessageHandler(this.wsMessage);
        if (this.ws.isConnected) {
            this.ws.send(JSON.stringify({ action: "snippets.init" }));
        }
    },
    methods: {
        wsMessage(event: any) {
            const data = JSON.parse(event);
            if (data.action === "snippets.init.ack") {
                this.snippets = JSON.parse(data.snippets);
            } else if (data.action === "snippet.add.ack" || data.action === "snippet.update.ack") {
                this.snippets = JSON.parse(data.snippets);
                this.hideDialog();
                this.$toast.add({severity:'success', summary: 'Successful', detail: 'Snippet Saved', life: 3000});
            } else if (data.action === "snippet.delete.ack") {
                this.snippets = this.snippets.filter((s: any) => s.id !== data.id);
                this.deleteSnippetDialog = false;
                this.$toast.add({severity:'success', summary: 'Successful', detail: 'Snippet Deleted', life: 3000});
            } else if (data.action === "snippet.fetch_codeshare.ack") {
                this.fetchingCodeshare = false;
                if (data.status) {
                    this.snippet = {
                        id: null,
                        name: data.name,
                        content: data.content,
                        platform: 'Android', // Default, user can change
                        source_type: 'codeshare',
                        source_url: data.url
                    };
                    this.codeshareDialog = false;
                    this.snippetDialog = true;
                }
            }
        },
        openNew() {
            this.snippet = {
                id: null,
                name: '',
                content: '',
                platform: 'Android',
                source_type: 'manual',
                source_url: ''
            };
            this.submitted = false;
            this.snippetDialog = true;
        },
        openCodeshareDialog() {
            this.codeshareUrl = '';
            this.codeshareDialog = true;
        },
        hideDialog() {
            this.snippetDialog = false;
            this.submitted = false;
        },
        editSnippet(snippet: any) {
            this.snippet = {...snippet};
            this.snippetDialog = true;
        },
        confirmDeleteSnippet(snippet: any) {
            this.snippet = snippet;
            this.deleteSnippetDialog = true;
        },
        deleteSnippet() {
            this.ws.send(JSON.stringify({ action: "snippet.delete", id: this.snippet.id }));
        },
        saveSnippet() {
            this.submitted = true;
            if (this.snippet.name.trim() && this.snippet.content.trim()) {
                if (this.snippet.id) {
                    this.ws.send(JSON.stringify({ action: "snippet.update", id: this.snippet.id, snippet: this.snippet }));
                } else {
                    this.ws.send(JSON.stringify({ action: "snippet.add", snippet: this.snippet }));
                }
            }
        },
        fetchCodeshare() {
            if (!this.codeshareUrl) return;
            this.fetchingCodeshare = true;
            this.ws.send(JSON.stringify({ action: "snippet.fetch_codeshare", url: this.codeshareUrl }));
        }
    }
});
</script>

<style scoped>
.page-snippet-manager {
    padding: 30px;
}
.snippet-table {
    margin-top: 20px;
}
.field label {
    display: block;
    margin-bottom: 5px;
    font-weight: bold;
}
</style>
