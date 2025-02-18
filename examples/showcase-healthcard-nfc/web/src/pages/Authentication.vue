<!--
  - Copyright 2025 gematik GmbH
  -
  - Licensed under the Apache License, Version 2.0 (the "License");
  - you may not use this file except in compliance with the License.
  - You may obtain a copy of the License at
  -
  -     http://www.apache.org/licenses/LICENSE-2.0
  -
  - Unless required by applicable law or agreed to in writing, software
  - distributed under the License is distributed on an "AS IS" BASIS,
  - WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  - See the License for the specific language governing permissions and
  - limitations under the License.
  -->

<script setup lang="ts">
import Credentials from '@/pages/Credentials.vue'
import { onUnmounted, ref } from 'vue'
import Pairing from '@/pages/Pairing.vue'
import { UseCase, useExchange } from '@/Exchange.ts'
import Transmission from '@/pages/Transmission.vue'
import { useReadHealthCard } from '@/ReadHealthCard.ts'

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
const exchange = useExchange(UseCase.AUTHENTICATION)
const { finish } = exchange
const readHealthCard = useReadHealthCard(exchange)

const onNextToPairing = ({ can, pin }: { can: string; pin: string }) => {
  pageState.value = { page: 'pairing', can, pin }
}

const onConnected = () => {
  if (pageState.value.page === 'pairing') {
    const currentPageState = pageState.value
    readHealthCard
      .process(currentPageState.can, currentPageState.pin, () => {
        pageState.value = { ...currentPageState, page: 'transmission' }
      })
      .catch((error) => {
        console.error(error)
      })
  }
}

onUnmounted(async () => {
  await finish()
})
</script>

<template>
  <Credentials v-if="pageState.page === 'credentials'" :on-next="onNextToPairing" />
  <Pairing v-else-if="pageState.page === 'pairing'" :on-connected="onConnected" :exchange="exchange" />
  <Transmission v-else-if="pageState.page === 'transmission'" :readHealthCard="readHealthCard" />
</template>

<style scoped></style>
