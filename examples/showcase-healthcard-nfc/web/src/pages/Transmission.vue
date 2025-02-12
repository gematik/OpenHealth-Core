<script setup lang="ts">
import Header from '@/components/Header.vue'
import { onMounted, ref } from 'vue'
import type { UseExchangeReturn } from '@/Exchange.ts'
import { readHealthCardAsync } from 'gematik-oh'
import LoadingSpinner from '@/components/LoadingSpinner.vue'
import { hexToInt8Array, int8ArrayToHex } from '@/HexUtils.ts'

const props = defineProps<{
  can: string
  pin: string
  exchange: UseExchangeReturn
}>()
const { responseAsync, requestAsync, finish } = props.exchange

const certificateSubject = ref<string | null>(null)

onMounted(async () => {
  try {
    const verifyCommand = await responseAsync()
    if (verifyCommand.type === 'verif') {
      while (true) {
        try {
          certificateSubject.value = await readHealthCardAsync(
            props.can,
            props.pin,
            async (apdu: Int8Array): Promise<Int8Array> => {
              console.log('Command:', int8ArrayToHex(apdu))
              const response = await requestAsync({ type: 'cmd', apdu: int8ArrayToHex(apdu) }, true)
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
    await requestAsync({ type: 'finish' }, false)
  } catch (e) {
    console.error(e)
  }
  await finish()
})
</script>

<template>
  <div class="flex h-screen w-screen flex-col">
    <Header class="bg-gem-primary" />
    <main class="font-['IBM Plex Sans'] flex flex-1 bg-white p-18 max-lg:p-6 max-lg:text-center justify-center">
      <div class="flex flex-col flex-1 items-center gap-14 max-lg:items-center lg:max-w-[1200px]">
        <div class="max-lg:text-4xl font-['Verdana'] text-6xl font-bold tracking-tight text-[#000e52] text-center">
          Befolge die Anweisungen in der OpenHealth App
        </div>
        <LoadingSpinner class="size-[120px]" />
      </div>
    </main>
  </div>
</template>

<style scoped></style>
