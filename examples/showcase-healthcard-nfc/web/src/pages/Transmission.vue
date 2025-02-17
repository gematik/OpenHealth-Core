<script setup lang="ts">
import Header from '@/components/Header.vue'
import LoadingSpinner from '@/components/LoadingSpinner.vue'
import Button from '@/components/Button.vue'
import { useRouter } from 'vue-router'
import type { UseReadHealthCardReturn } from '@/ReadHealthCard.ts'

defineProps<{
  readHealthCard: UseReadHealthCardReturn
}>()

const router = useRouter()
</script>

<template>
  <div class="flex h-screen w-screen flex-col">
    <Header class="bg-gem-primary" />
    <main class="font-[Verdana] flex flex-1 bg-white p-18 max-lg:p-6 max-lg:text-center justify-center">
      <div class="flex flex-col flex-1 items-center gap-14 max-lg:items-center lg:max-w-[1200px]">
        <div class="max-lg:text-4xl font-['Verdana'] text-6xl font-bold tracking-tight text-gem-primary text-center">
          {{
            readHealthCard.subjectName.value
              ? `Hallo ${readHealthCard.subjectName.value}`
              : 'Befolge die Anweisungen in der OpenHealth App'
          }}
        </div>
        <template v-if="readHealthCard.subjectName.value">
          <div class="text-xl text-gem-primary">Erfolgreich angemeldet!</div>
          <Button @click="router.replace('/')">Zur Startseite</Button>
        </template>
        <LoadingSpinner v-else class="size-[120px]" />
      </div>
    </main>
  </div>
</template>

<style scoped></style>
