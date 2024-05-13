import { createMemoryHistory, createRouter } from 'vue-router'

import DashboardPage from './components/DashboardPage.vue'
import HTTPTraffic from './components/HTTPTraffic.vue'
import { PrimeIcons } from 'primevue/api';


const routes = [
  { path: '/', component: DashboardPage, icon: PrimeIcons.HOME },
  { path: '/traffic', component: HTTPTraffic },
]

const router = createRouter({
  history: createMemoryHistory(),
  routes,
})

export default router