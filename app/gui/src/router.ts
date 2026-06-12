import { createRouter, createWebHistory } from 'vue-router'

import Sessions from './views/Sessions.vue'
import HTTPTraffic from './views/HTTPTraffic.vue'
import LibraryManager from './views/LibraryManager.vue'
import SnippetManager from './views/SnippetManager.vue'
import AppManager from './views/AppManager.vue'
import AppSelector from './views/AppSelector.vue'

const routes = [
  { path: '/', beforeEnter: (to: any, from: any, next: any) => {
    if (Object.keys(from.query).length && Object.keys(to.query).length === 0) {
      next({ path: to.path, query: from.query });
    } else {
      next();
    }
  }, component: Sessions, name: 'Sessions'},
  { path: '/traffic', beforeEnter: (to: any, from: any, next: any) => {
    if (Object.keys(from.query).length && Object.keys(to.query).length === 0) {
      next({ path: to.path, query: from.query });
    } else {
      next();
    }
  }, component: HTTPTraffic },
  { path: '/libraries', beforeEnter: (to: any, from: any, next: any) => {
    if (Object.keys(from.query).length && Object.keys(to.query).length === 0) {
      next({ path: to.path, query: from.query });
    } else {
      next();
    }
  }, component: LibraryManager },
  { path: '/snippets', beforeEnter: (to: any, from: any, next: any) => {
    if (Object.keys(from.query).length && Object.keys(to.query).length === 0) {
      next({ path: to.path, query: from.query });
    } else {
      next();
    }
  }, component: SnippetManager },
  { path: '/apps', component: AppManager, beforeEnter: (to: any, from: any, next: any) => {
    if (Object.keys(from.query).length && Object.keys(to.query).length === 0) {
      next({ path: to.path, query: from.query });
    } else {
      next();
    }
  }},
  { path: '/app', beforeEnter: (to: any, from: any, next: any) => {
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