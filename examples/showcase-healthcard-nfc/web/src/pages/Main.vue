<script setup lang="ts">
import HeaderContent from '@/components/HeaderContent.vue'
import Button from '@/components/Button.vue'
import { useRouter } from 'vue-router'

const router = useRouter()
</script>

<template>
  <div class="flex flex-col w-screen h-screen">
    <HeaderContent class="z-100" />
    <main
      class="font-['IBM Plex Sans'] flex flex-1 place-items-center p-18 text-white bg-gem-primary"
    >
      <div class="flex flex-col z-1">
        <div class="font-['Verdana'] text-7xl font-bold">
          <p>Willkommen bei</p>
          <p><span class="font-light">Open</span>Health</p>
        </div>
        <div class="mt-6 w-[60%]">
          Mit OpenHealth können Sie Operationen auf der Telematikinfrastruktur effizient gestalten
          und für Showcases und Testzwecke nutzen. Um teilzunehmen, benötigen Sie zusätzlich die
          OpenHealth-App der gematik.
        </div>
        <div class="mt-15 flex gap-4">
          <Button
            class="flex gap-4"
            @click="
              () => {
                router.push('/usecase/authentication')
              }
            "
            ><img src="@/assets/person.svg" alt="Icon of a person" />Authentisierung</Button
          >
          <Button class="flex gap-4"
            ><img src="@/assets/person.svg" alt="Icon of a person" />Wunsch PIN wählen</Button
          >
          <Button class="flex gap-4"
            ><img src="@/assets/person.svg" alt="Icon of a person" />Karte entsperren</Button
          >
        </div>
      </div>
      <div class="absolute top-0 right-0 w-[80%] h-[80%] overflow-hidden">
        <img
          src="@/assets/bg-logo.svg"
          alt="logo"
          class="w-full h-full transform -translate-y-[20%] translate-x-[20%]"
        />
      </div>
    </main>
  </div>
</template>

<style scoped></style>
