import { createApp } from "vue";
import App from "./App.vue";
import router from "./router";
import PrimeVue from "primevue/config";
import "primevue/resources/themes/aura-light-green/theme.css";
import "primeicons/primeicons.css";
import Shortkey from "vue3-shortkey";
import ToastService from "primevue/toastservice";
import { createPinia } from "pinia";
import ConfirmationService from "primevue/confirmationservice";
import Tooltip from "primevue/tooltip";
import { useWebSocketStore } from "./stores/session";
import "./assets/style.css";

const pinia = createPinia();

const app = createApp(App);
app.directive("tooltip", Tooltip);
app
  .use(pinia)
  .use(PrimeVue)
  .use(ToastService)
  .use(Shortkey)
  .use(router)
  .use(ConfirmationService);

let ws = useWebSocketStore();
ws.connect('ws://' + import.meta.env.VITE_SERVER_IP + ':8000');
app.mount("#app");


/* TODO:
  1. Check replay functionality for iOS                     - done
  2. Fix UI for macbook screen                              - in progress
  3. Fix HTTP version for iOS libraries                     - done
  4. Add library support for AFNetworking and NSURLSession      - 
  5. For iOS alamofire, fix missing port issue              - done 
  6. Delete all library files on deletion                   - 
  7. Footer handle dropdown change                          - 
*/