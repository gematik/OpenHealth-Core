import { createRouter, createWebHistory } from 'vue-router'

import Main from '@/pages/Main.vue'
import Authentication from '@/pages/Authentication.vue'

const routes = [
  { path: '/', component: Main },
  { path: '/usecase/authentication', component: Authentication },
]

export const router = createRouter({
  history: createWebHistory(),
  routes,
})
