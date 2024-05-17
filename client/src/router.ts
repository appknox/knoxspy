import { createMemoryHistory, createRouter } from 'vue-router'

import DashboardPage from './components/DashboardPage.vue'
import HTTPTraffic from './components/HTTPTraffic.vue'
import LibraryManager from './components/LibraryManager.vue'
import { PrimeIcons } from 'primevue/api';


const routes = [
  { path: '/', component: DashboardPage, icon: PrimeIcons.HOME},//, redirect: '/libraries' },
  { path: '/traffic', component: HTTPTraffic },
  { path: '/libraries', component: LibraryManager },
]

const router = createRouter({
  history: createMemoryHistory(),
  routes,
})

export default router