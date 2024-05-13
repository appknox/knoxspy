import { createApp } from 'vue'
import App from './App.vue'
import router from './router.ts'
import '@progress/kendo-theme-default/dist/all.css';
import { Grid } from '@progress/kendo-vue-grid'
import PrimeVue from 'primevue/config';
import 'primevue/resources/themes/aura-light-green/theme.css'
// import 'primevue/resources/themes/lara-dark-green/theme.css'
import 'primeicons/primeicons.css'



createApp(App).component('Grid', Grid).use(PrimeVue).use(router).mount('#app')
