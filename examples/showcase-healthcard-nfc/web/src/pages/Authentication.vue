<script setup lang="ts">
import { useExchange } from '@/Exchange.ts'
import { computed, onMounted, onUnmounted } from 'vue'
import { readHealthCardAsync } from 'gematik-oh'
import { hexToInt8Array, int8ArrayToHex } from '@/HexUtils.ts'
import HeaderContent from '@/components/HeaderContent.vue'
import { useQRCode } from '@vueuse/integrations/useQRCode'

const { token, responseAsync, requestAsync, connect, finish } = useExchange()

const qrCode = useQRCode(computed(() => token.value ?? ''))

onMounted(async () => {
  await connect()

  const verifyCommand = await responseAsync()
  if (verifyCommand.type === 'verif') {
    while (true) {
      try {
        await readHealthCardAsync(
          () => {},
          () => {},
          async (apdu: Int8Array): Promise<Int8Array> => {
            console.log('Command:', int8ArrayToHex(apdu))
            const response = await requestAsync({ type: 'cmd', apdu: int8ArrayToHex(apdu) })
            if (response.type === 'cmd') {
              console.log('Data received:', response.apdu)
              return hexToInt8Array(response.apdu)
            } else if (response.type === 'verif') {
              throw new Error('Retry - Tag Lost')
            } else {
              throw new Error('Unknown Command')
            }
          },
        )
      } catch (err) {
        console.error(err)
        continue
      }
      break
    }
  }
  await requestAsync({ type: 'finish' })
})

onUnmounted(async () => {
  await finish()
})
</script>

<template>
  <div class="flex flex-col w-screen h-screen">
    <HeaderContent />
    <main class="font-['IBM Plex Sans'] flex flex-1 place-items-center p-18 text-white bg-white">
      <img :src="qrCode" alt="QR Connection Code" />
    </main>
  </div>
</template>

<style scoped></style>
