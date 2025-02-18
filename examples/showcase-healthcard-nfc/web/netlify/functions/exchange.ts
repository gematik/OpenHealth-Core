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

import { Config } from '@netlify/functions'
import crypto from 'crypto'
import * as Ably from 'ably'

export default async () => {
  try {
    const apiKey = Netlify.env.get('ABLY_API_KEY')
    const ably = new Ably.Rest(apiKey)

    const c2wChannelName = crypto.randomUUID()
    const w2cChannelName = crypto.randomUUID()
    const webTokenRequest = await ably.auth.createTokenRequest({
      capability: {
        [c2wChannelName]: ['subscribe'],
        [w2cChannelName]: ['publish'],
      },
      ttl: 15 * 60000,
    })
    const clientTokenRequest = await ably.auth.createTokenRequest({
      capability: {
        [c2wChannelName]: ['publish'],
        [w2cChannelName]: ['subscribe'],
      },
      ttl: 15 * 60000,
    })

    const result = {
      webTokenRequest,
      clientTokenRequest,
      clientToWebChannel: c2wChannelName,
      webToClientChannel: w2cChannelName,
    }

    return new Response(JSON.stringify(result), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  } catch (error) {
    console.error('Ably Token Error:', error)
    return new Response(JSON.stringify({ error: 'Failed to generate Ably token' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    })
  }
}

export const config: Config = {
  path: '/api/exchange',
}
