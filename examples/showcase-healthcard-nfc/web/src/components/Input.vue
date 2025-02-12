<script setup lang="ts">
import { ref, useId } from 'vue'

const props = defineProps<{
  type?: string
  inputmode?: 'text' | 'email' | 'search' | 'tel' | 'url' | 'none' | 'numeric' | 'decimal'
  pattern?: string
  errorMessage?: string
  label: string
}>()

const id = useId()
const inputRef = ref<HTMLObjectElement | null>(null)
const text = defineModel<string>({ default: '' })
const error = ref('')

const validateInput = () => {
  if (props.pattern && props.errorMessage) {
    const regex = new RegExp(props.pattern)
    error.value = regex.test(text.value) ? '' : props.errorMessage
  }
}
</script>

<template>
  <div class="flex flex-col gap-1">
    <div class="relative">
      <input
        ref="inputRef"
        :id="id"
        :type="type || 'text'"
        placeholder=""
        class="peer w-full rounded-lg border px-3 py-2 text-gray-900 focus:border-gem-primary focus:ring-1 focus:ring-gem-primary
          focus:outline-none border-gray-300 invalid:border-red-500 invalid:ring-red-500 invalid:ring-1"
        v-model="text"
        :inputmode="inputmode"
        :pattern="pattern"
        @input="validateInput"
        @blur="validateInput"
      />
      <label
        :for="id"
        class="absolute left-3 top-4 text-sm text-gray-500 transition-all duration-200 ease-in-out peer-placeholder-shown:top-1/2
          peer-placeholder-shown:-translate-y-1/2 peer-placeholder-shown:text-base peer-placeholder-shown:text-gray-400
          peer-focus:top-0 peer-focus:bg-white peer-focus:px-1 peer-focus:text-xs peer-focus:text-gem-primary
          peer-not-placeholder-shown:top-0 peer-not-placeholder-shown:bg-white peer-not-placeholder-shown:px-1
          peer-not-placeholder-shown:text-xs peer-not-placeholder-shown:text-gem-primary
          peer-not-placeholder-shown:-translate-y-1/2 peer-invalid:text-red-500"
      >
        {{ props.label }}
      </label>
    </div>
    <p v-if="error" class="text-red-500 text-xs mt-1">{{ error }}</p>
  </div>
</template>

<style scoped></style>
