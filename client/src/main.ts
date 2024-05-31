import { createApp } from 'vue'
import App from './App.vue'
import router from './router.ts'
import PrimeVue from 'primevue/config';
import 'primevue/resources/themes/aura-light-green/theme.css'
// import 'primevue/resources/themes/lara-dark-green/theme.css';
import 'primeicons/primeicons.css'
import Shortkey from "vue3-shortkey"
import ToastService from 'primevue/toastservice';
import { createPinia } from 'pinia';

const pinia = createPinia()



createApp(App).use(pinia).use(PrimeVue).use(ToastService).use(Shortkey).use(router).mount('#app')
