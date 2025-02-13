<script setup lang="ts">
import { UseCase, useExchange, type UseExchangeReturn } from '@/Exchange.ts'
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { readHealthCardAsync } from 'gematik-oh'
import { hexToInt8Array, int8ArrayToHex } from '@/HexUtils.ts'
import Header from '@/components/Header.vue'
import { useQRCode } from '@vueuse/integrations/useQRCode'
import { useTimeAgo, useTimeoutPoll } from '@vueuse/core'
import Button from '@/components/Button.vue'
import StepsScaffold from '@/pages/StepsScaffold.vue'
import LoadingSpinner from '@/components/LoadingSpinner.vue'
import LoadingIndicator from '@/components/LoadingIndicator.vue'

const props = defineProps<{ onNext: () => void; exchange: UseExchangeReturn }>()
const { token, ttlUntil, responseAsync, requestAsync, connect, finish } = props.exchange

const tokenValidUntil = ref({ minutesLeft: 0 })
const setTokenValidUntil = () => {
  const millisLeft = ttlUntil.value - Date.now()
  const minutesLeft = Math.floor(millisLeft / 60000)
  tokenValidUntil.value = { minutesLeft }
}
useTimeoutPoll(() => setTokenValidUntil(), 1000)
watch(ttlUntil, () => {
  if (ttlUntil) setTokenValidUntil()
})

const qrCode = useQRCode(
  computed(() => token.value ?? ''),
  { margin: 0 },
)

const isLoading = ref(true)

onMounted(async () => {
  try {
    isLoading.value = true
    await connect()
  } finally {
    isLoading.value = false
  }

  const verifyCommand = await responseAsync()
  if (verifyCommand.type === 'verif') {
    props.onNext()
  }
})

</script>

<template>
  <StepsScaffold>
    <template #header>
      <span>Gerätekopplung</span>
    </template>
    <template #description>
      <span>Bitte scannen Sie den QR Code mit der OpenHealth App der gematik.</span>
    </template>
    <template #body>
      <div class="flex flex-col items-center gap-2">
        <div class="bg-gem-neutral-200 text-gem-neutral-800 flex gap-2 rounded-lg px-2 py-1">
          <span class="material-icons-outlined">timer</span>
          {{
            tokenValidUntil.minutesLeft <= 0
              ? 'Code abgelaufen'
              : `Code noch ${tokenValidUntil.minutesLeft} Minuten gültig`
          }}
        </div>
        <div class="relative flex items-center justify-center size-[308px]">
          <div
            v-if="tokenValidUntil.minutesLeft <= 0 || isLoading"
            class="bg-gem-neutral-100 rounded-2xl size-full flex items-center justify-center"
          >
            <Button v-if="tokenValidUntil.minutesLeft <= 0 && !isLoading"
              ><span class="material-icons-outlined">refresh</span> Neuen Code erzeugen
            </Button>
            <LoadingIndicator v-if="isLoading" class="absolute">Code wird geladen... </LoadingIndicator>
          </div>
          <img v-else :src="qrCode" alt="QR Connection Code" />
        </div>
      </div>
    </template>
    <template #image>
      <img
        src="@/assets/phone_connect/phone_connect_1x.webp"
        srcset="@/assets/phone_connect/phone_connect_1x.webp 1x, @/assets/phone_connect/phone_connect_2x.webp 2x, @/assets/phone_connect/phone_connect_3x.webp 3x @/assets/phone_connect/phone_connect_4x.webp 4x"
        alt="Abbildung eines Smartphones mit der OpenHealth App der gematik"
        class="mx-auto h-full max-h-[900px] w-auto object-contain py-14"
      />
    </template>
  </StepsScaffold>
</template>

<style scoped></style>
