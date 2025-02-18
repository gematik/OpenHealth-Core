/*
 * Copyright 2025 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import type { Ref } from 'vue'
import { ref } from 'vue'
import type { UseExchangeReturn } from '@/Exchange.ts'
import {
  readHealthCardAsync
} from '../../../../build/js/packages/kmp-gematik-common-examples-showcase-healthcard-nfc'
import { hexToInt8Array, int8ArrayToHex } from '@/HexUtils.ts'

class ReVerifyError extends Error {}
class InvalidStateError extends Error {}

export type UseReadHealthCardReturn = {
  subjectName: Ref<string | null>
  process: (can: string, pin: string, onVerified: () => void) => Promise<void>
}

export function useReadHealthCard(exchange: UseExchangeReturn): UseReadHealthCardReturn {
  const { responseAsync, requestAsync, finish } = exchange
  const subjectName = ref<string | null>(null)

  async function process(can: string, pin: string, onVerified: () => void) {
    try {
      await ensureVerification()
      onVerified()

      while (true) {
        try {
          subjectName.value = await readHealthCardAsync(can, pin, handleApdu)
          break
        } catch (error) {
          if (!(error instanceof ReVerifyError)) {
            console.error(error)
            await ensureVerification()
          }
          // If ReVerifyError, simply retry
        }
      }

      await requestAsync({ type: 'finish' }, false)
    } finally {
      await finish()
    }
  }

  async function ensureVerification() {
    const verifyCommand = await responseAsync()
    if (verifyCommand.type !== 'verif') {
      throw new InvalidStateError(`Invalid command: ${JSON.stringify(verifyCommand)}`)
    }
  }

  async function handleApdu(apdu: Int8Array): Promise<Int8Array> {
    console.log('Request:', int8ArrayToHex(apdu))
    const response = await requestAsync({ type: 'cmd', apdu: int8ArrayToHex(apdu) }, true)

    if (response.type === 'cmd') {
      console.log('Response:', response.apdu)
      return hexToInt8Array(response.apdu)
    } else if (response.type === 'verif') {
      throw new ReVerifyError()
    } else {
      throw new InvalidStateError(`Invalid command: ${JSON.stringify(response)}`)
    }
  }

  return {
    subjectName,
    process,
  }
}
