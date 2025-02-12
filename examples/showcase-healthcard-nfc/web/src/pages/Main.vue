<script setup lang="ts">
import Header from '@/components/Header.vue'
import Button from '@/components/Button.vue'
import { useRouter } from 'vue-router'

const router = useRouter()
</script>

<template>
  <div class="bg-gem-primary flex h-screen w-screen flex-col">
    <Header class="z-100 bg-gem-primary/70 backdrop-blur-md" />
    <main class="font-['IBM Plex Sans'] bg-gem-primary flex flex-1 place-items-center p-18 max-lg:py-12 max-lg:px-4 text-white">
      <div class="z-1 flex flex-col">
        <div class="blurred-text font-['Verdana'] text-6xl max-lg:text-4xl font-bold">
          <p>Willkommen bei</p>
          <p><span class="font-light">Open</span>Health</p>
        </div>
        <div class="blurred-text mt-6 w-[60%] max-lg:w-full">
          Mit OpenHealth lassen sich Operationen auf der Telematikinfrastruktur einfach und effizient nutzen – auch für Showcases und Tests. Dafür wird zusätzlich die OpenHealth-App der gematik gebraucht.
        </div>
        <div class="mt-15 flex gap-4 flex-wrap">
          <Button class="flex gap-4" @click="router.push('/usecase/authentication')"
            ><img src="@/assets/person.svg" alt="Icon of a person" />Authentisierung
          </Button>
          <Button class="flex gap-4"><img src="@/assets/person.svg" alt="Icon of a person" />Wunsch PIN wählen </Button>
          <Button class="flex gap-4"><img src="@/assets/person.svg" alt="Icon of a person" />Karte entsperren </Button>
        </div>
      </div>
      <div class="absolute top-0 right-0 h-[80%] w-[80%] overflow-hidden max-lg:hidden">
        <img
          src="@/assets/bg-logo.svg"
          alt="logo"
          class="h-full w-full -translate-y-[20%] translate-x-[20%] transform"
        />
      </div>
    </main>
  </div>
</template>

<style scoped>
.blurred-text {
  text-shadow:
    0 0 10px rgba(0, 0, 0, 0.4),
    0 0 20px rgba(0, 0, 0, 0.2);
}
</style>
