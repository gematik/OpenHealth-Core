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
import StepsScaffold from '@/pages/StepsScaffold.vue'
import Button from '@/components/Button.vue'
import Input from '@/components/Input.vue'
import { ref } from 'vue'

defineProps<{ onNext: ({ can, pin }: { can: string; pin: string }) => void }>()

const canInput = ref('')
const pinInput = ref('')
</script>

<template>
  <StepsScaffold>
    <template #header>
      <span>Anmeldung erforderlich</span>
    </template>
    <template #description>
      <span>Bitte Kartenkennung (CAN) und persönlichen Code (PIN) eingeben, um fortzufahren.</span>
    </template>
    <template #body>
      <div class="flex flex-col items-start gap-4 w-full">
        <Input
          label="Zugangsnummer (CAN)"
          class="w-full"
          v-model="canInput"
          inputmode="numeric"
          pattern="^[0-9]{0,6}$"
          error-message="Die CAN muss genau 6 Ziffern lang sein."
        />
        <Input
          label="Persönlicher Code (PIN)"
          class="w-full"
          v-model="pinInput"
          inputmode="numeric"
          pattern="^[0-9]{0,6}$"
          error-message="Die PIN muss zwischen 6 und 8 Ziffern lang sein."
        />
        <Button class="place-self-end" @click="onNext({ can: canInput, pin: pinInput })">Weiter</Button>
      </div>
    </template>
    <template #image>
      <img
        src="@/assets/ehealthcard/ehealthcard_1x.webp"
        srcset="@/assets/ehealthcard/ehealthcard_1x.webp 1x, @/assets/ehealthcard/ehealthcard_2x.webp 2x, @/assets/ehealthcard/ehealthcard_3x.webp 3x @/assets/ehealthcard/ehealthcard_4x.webp 4x"
        alt="Abbildung einer eGK mit Hinweis, wo die CAN steht"
        class="mx-auto h-full max-h-[350px] w-auto object-contain object-top lg:py-14"
      />
    </template>
  </StepsScaffold>
</template>

<style scoped></style>
