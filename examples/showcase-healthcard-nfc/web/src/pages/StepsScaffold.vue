<script setup lang="ts">

import Header from '@/components/Header.vue'

</script>

<template>
  <div class="flex h-screen w-screen flex-col">
    <Header class="bg-gem-primary" />
    <main class="font-['IBM Plex Sans'] flex flex-1 bg-white p-18 max-lg:p-6 max-lg:text-center justify-center">
      <div class="flex flex-1 flex-row flex-wrap max-lg:justify-center gap-12 lg:max-w-[1200px]">
        <div class="flex flex-col flex-1 items-start gap-14 max-lg:items-center">
          <div class="inline-flex flex-col items-start justify-start gap-2 max-lg:items-center">
            <div class="max-lg:text-4xl font-['Verdana'] text-6xl font-bold tracking-tight text-[#000e52]">
              <slot name="header"/>
            </div>
            <div class="self-stretch font-['Verdana'] text-xl leading-[25px] font-normal tracking-tight text-[#000e52]">
              <slot name="description"/>
            </div>
          </div>
          <slot name="body"/>
        </div>
        <div class="lg:flex-1">
          <slot name="image"/>
        </div>
      </div>
    </main>
  </div>
</template>

<style scoped>

</style>
