import { createMemoryHistory, createRouter } from 'vue-router'

import DashboardPage from './components/DashboardPage.vue'
import HTTPTraffic from './components/HTTPTraffic.vue'
import LibraryManager from './components/LibraryManager.vue'
import AppManager from './components/AppManager.vue'
import Settings from './components/Settings.vue'
import { PrimeIcons } from 'primevue/api';


const routes = [
  { path: '/', component: DashboardPage, name: 'Dashboard', icon: PrimeIcons.HOME},//, redirect: '/libraries' },
  { path: '/traffic', component: HTTPTraffic },
  { path: '/libraries', component: LibraryManager },
  { path: '/apps', component: AppManager},
  { path: '/settings', component: Settings}
]

const router = createRouter({
  history: createMemoryHistory(),
  routes,
})

export default router