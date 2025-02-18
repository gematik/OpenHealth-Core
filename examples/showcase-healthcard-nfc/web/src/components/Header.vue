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
import { useRouter } from 'vue-router'

const router = useRouter()
</script>

<template>
  <header class="flex flex-row items-center place-content-between p-4 h-[72px] max-lg:h-[56px]">
    <div class="flex flex-row items-center h-full cursor-pointer" @click="router.push('/')">
      <img alt="OpenHealth Logo" src="@/assets/logo.svg" class="h-[90%] w-auto" />
      <h1 class="font-[roboto] ms-4 text-white text-xl max-lg:text-lg"><span class="font-light">Open</span>Health</h1>
    </div>
    <img alt="OpenHealth Logo" src="@/assets/logo_gematik.svg" class="h-[80%] w-auto" />
  </header>
</template>

<style scoped></style>
