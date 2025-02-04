<script setup lang="ts">
import { useAbly } from '@/Ably.ts'
import { onMounted, ref, watch } from 'vue'
import { readHealthCardAsync } from '../../../../build/js/packages/kmp-gematik-common-examples-showcase-healthcard-nfc'
import { hexToInt8Array, int8ArrayToHex } from '@/HexUtils.ts'
import HeaderContent from '@/components/HeaderContent.vue'
import Main from '@/pages/Main.vue'
import Button from '@/components/Button.vue'
import { useQRCode } from '@vueuse/integrations/useQRCode'



// const { responseAsync, requestAsync } = useAbly('test')

onMounted(async () => {
  // const result = await fetch("/api/exchange");
  // console.log((await result.json()));
})

const qrCodeData = ref("");
const qrCode = useQRCode(qrCodeData);

// onMounted(async () => {
//   const verifyCommand = await responseAsync()
//   if (verifyCommand.type === 'verif') {
//     while (true) {
//       try {
//         await readHealthCardAsync(
//           () => {},
//           () => {},
//           async (apdu: Int8Array): Promise<Int8Array> => {
//             console.log('Command:', int8ArrayToHex(apdu))
//             const reponse = await requestAsync({ type: 'cmd', apdu: int8ArrayToHex(apdu) })
//             if (reponse.type === 'cmd') {
//               console.log('Data received:', reponse.apdu)
//               return hexToInt8Array(reponse.apdu)
//             } else if (reponse.type === 'verif') {
//               throw new Error('Retry - Tag Lost')
//             } else {
//               throw new Error('Unknown Command')
//             }
//           },
//         )
//       } catch (err) {
//         console.error(err);
//         continue;
//       }
//       break;
//     }
//   }
//   await requestAsync({ type: 'finish' })
// })
</script>

<template>
  <div class="flex flex-col w-screen h-screen">
    <HeaderContent />
    <main class="font-['IBM Plex Sans'] flex flex-1 place-items-center p-18 text-white  bg-white">

    </main>
  </div>
</template>

<style scoped></style>
