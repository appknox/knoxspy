import { createApp } from "vue";
import App from "./App.vue";
import router from "./router";
import PrimeVue from "primevue/config";
import "primevue/resources/themes/aura-light-green/theme.css";
// import 'primevue/resources/themes/lara-dark-green/theme.css';
import "primeicons/primeicons.css";
import Shortkey from "vue3-shortkey";
import ToastService from "primevue/toastservice";
import { createPinia } from "pinia";
import ConfirmationService from "primevue/confirmationservice";
import Tooltip from "primevue/tooltip";

const pinia = createPinia();

const app = createApp(App);
app.directive("tooltip", Tooltip);
app
  .use(pinia)
  .use(PrimeVue)
  .use(ToastService)
  .use(Shortkey)
  .use(router)
  .use(ConfirmationService)
  .mount("#app");
