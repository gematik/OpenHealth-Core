import './assets/main.css'
import '@fontsource/roboto/300.css'
import '@fontsource/roboto/400.css'
import '@fontsource/roboto/700.css'
import '@fontsource/ibm-plex-sans/300.css'
import '@fontsource/ibm-plex-sans/400.css'
import '@fontsource/ibm-plex-sans/700.css'
import '@/assets/verdana/stylesheet.css'
import 'material-icons/iconfont/material-icons.css';


import { createApp } from 'vue'
import { router } from '@/routes.ts'
import App from '@/App.vue'

createApp(App).use(router).mount('#app')
