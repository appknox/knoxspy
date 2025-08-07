import { createRouter, createWebHistory } from 'vue-router'

import Sessions from './views/Sessions.vue'
import HTTPTraffic from './views/HTTPTraffic.vue'
import LibraryManager from './views/LibraryManager.vue'
import AppManager from './views/AppManager.vue'
import AppSelector from './views/AppSelector.vue'

const routes = [
  { path: '/', beforeEnter: (to, from, next) => {
    if (Object.keys(from.query).length && Object.keys(to.query).length === 0) {
      next({ path: to.path, query: from.query });
    } else {
      next();
    }
  }, component: Sessions, name: 'Sessions'},
  { path: '/traffic', beforeEnter: (to, from, next) => {
    if (Object.keys(from.query).length && Object.keys(to.query).length === 0) {
      next({ path: to.path, query: from.query });
    } else {
      next();
    }
  }, component: HTTPTraffic },
  { path: '/libraries', beforeEnter: (to, from, next) => {
    if (Object.keys(from.query).length && Object.keys(to.query).length === 0) {
      next({ path: to.path, query: from.query });
    } else {
      next();
    }
  }, component: LibraryManager },
  { path: '/apps', component: AppManager, beforeEnter: (to, from, next) => {
    if (Object.keys(from.query).length && Object.keys(to.query).length === 0) {
      next({ path: to.path, query: from.query });
    } else {
      next();
    }
  }},
  { path: '/app', beforeEnter: (to, from, next) => {
    if (Object.keys(from.query).length && Object.keys(to.query).length === 0) {
      next({ path: to.path, query: from.query });
    } else {
      next();
    }
  }, component: AppSelector },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

export default router