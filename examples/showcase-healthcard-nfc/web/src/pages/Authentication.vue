<script setup lang="ts">
import Credentials from '@/pages/Credentials.vue'
import { onMounted, ref } from 'vue'
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
  }
}

const exchange = useExchange(UseCase.AUTHENTICATION)
// const { token, ttlUntil, responseAsync, requestAsync, connect, finish } = exchange;

onMounted(async () => {
  // await connect();
  // await connect()
  //
  // console.log('Connected')
  //
  // try {
  //   const verifyCommand = await responseAsync()
  //   if (verifyCommand.type === 'verif') {
  //     while (true) {
  //       try {
  //         await readHealthCardAsync(
  //           () => {},
  //           () => {},
  //           async (apdu: Int8Array): Promise<Int8Array> => {
  //             console.log('Command:', int8ArrayToHex(apdu))
  //             const response = await requestAsync({ type: 'cmd', apdu: int8ArrayToHex(apdu) })
  //             if (response.type === 'cmd') {
  //               console.log('Data received:', response.apdu)
  //               return hexToInt8Array(response.apdu)
  //             } else if (response.type === 'verif') {
  //               throw new Error('Retry - Tag Lost')
  //             } else {
  //               throw new Error('Unknown Command')
  //             }
  //           },
  //         )
  //       } catch (err) {
  //         console.error(err)
  //         continue
  //       }
  //       break
  //     }
  //   }
  //   await requestAsync({ type: 'finish' })
  // } catch (e) {
  //   console.error(e)
  // }
})
</script>

<template>
  <Credentials v-if="pageState.page === 'credentials'" :on-next="updatePageStateToPairing" />
<!--  <Pairing v-if="pageState.page === 'pairing'" :on-next="updatePageStateToTransmission" :exchange="exchange" />-->
  <Transmission v-if="pageState.page === 'pairing'" :can="pageState.can" :pin="pageState.pin" :exchange="exchange" />
</template>

<style scoped></style>
