<script setup lang="ts">
import Credentials from '@/pages/Credentials.vue'
import { onMounted, onUnmounted, ref } from 'vue'
import Pairing from '@/pages/Pairing.vue'
import { UseCase, useExchange } from '@/Exchange.ts'
import Transmission from '@/pages/Transmission.vue'

type PageState =
  | {
      page: 'credentials'
    }
  | {
      page: 'pairing'
      can: string
      pin: string
    }
  | {
      page: 'transmission'
      can: string
      pin: string
    }

const pageState = ref<PageState>({ page: 'credentials' })

const updatePageStateToPairing = ({ can, pin }: { can: string; pin: string }) => {
  pageState.value = { page: 'pairing', can, pin }
}

const updatePageStateToTransmission = () => {
  if (pageState.value.page === 'pairing') {
    pageState.value = { ...pageState.value, page: 'transmission' }
    console.log(pageState.value)
  }
}

const exchange = useExchange(UseCase.AUTHENTICATION)
const { finish } = exchange;

onUnmounted(async () => {
  await finish()
})
</script>

<template>
  <Credentials v-if="pageState.page === 'credentials'" :on-next="updatePageStateToPairing" />
  <Pairing v-if="pageState.page === 'pairing'" :on-next="updatePageStateToTransmission" :exchange="exchange" />
  <Transmission v-if="pageState.page === 'transmission'" :can="pageState.can" :pin="pageState.pin" :exchange="exchange" />
</template>

<style scoped></style>
