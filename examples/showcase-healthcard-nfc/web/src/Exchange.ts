import * as Ably from 'ably'
import { type Message } from 'ably'
import { computed, type ComputedRef, onUnmounted, type Ref, ref } from 'vue'

export enum UseCase {
  AUTHENTICATION = 1,
  CHANGE_PASSWORD = 2,
  UNLOCK_HC = 3,
}

export type Command = CommandVerify | CommandApdu | CommandFinish

export type CommandVerify = {
  type: 'verif'
  code: string
}

export type CommandApdu = {
  type: 'cmd'
  apdu: string
}

export type CommandFinish = {
  type: 'finish'
}

export type ExchangeToken = {
  webTokenRequest: Ably.TokenRequest
  clientTokenRequest: Ably.TokenRequest
  clientToWebChannel: string
  webToClientChannel: string
}

export type UseExchangeReturn = {
  connect: () => Promise<void>
  finish: () => Promise<void>
  ttlUntil: ComputedRef<number>
  requestAsync: (request: Command, expectResponse: boolean) => Promise<Command>
  responseAsync: () => Promise<Command>
  token: ComputedRef<string | null>
}

export function useExchange(useCase: UseCase): UseExchangeReturn {
  const state: Ref<{
    token: ExchangeToken
    ably: Ably.Realtime
    clientToWebChannel: Ably.RealtimeChannel
    webToClientChannel: Ably.RealtimeChannel
  } | null> = ref(null)

  const token = computed(() => {
    const tok = state.value?.token
    if (tok) {
      return JSON.stringify({
        token: JSON.stringify(tok.clientTokenRequest),
        c2w: tok.clientToWebChannel,
        w2c: tok.webToClientChannel,
        uc: useCase,
      })
    } else {
      return null
    }
  })

  const responseAsync = async (): Promise<Command> => {
    return new Promise((resolve, reject) => {
      if (state.value) {
        state.value.clientToWebChannel.subscribe((message: Message) => {
          resolve(message.data as Command)
          state.value?.clientToWebChannel?.unsubscribe()
        })
      } else {
        reject('Not connected')
      }
    })
  }

  const requestAsync = async (request: Command, expectResponse: boolean = true): Promise<Command> => {
    return new Promise((resolve, reject) => {
      if (state.value) {
        state.value.webToClientChannel.publish('w2c', request)
        if (expectResponse) {
          state.value.clientToWebChannel.subscribe((message: Message) => {
            resolve(message.data as Command)
            state.value?.clientToWebChannel?.unsubscribe()
          })
        }
      } else {
        reject('Not connected')
      }
    })
  }

  const connect = async () => {
    await finish()
    const exchange = (await (await fetch('/api/exchange')).json()) as ExchangeToken
    const ably = new Ably.Realtime({
      authCallback: (params, callback) => {
        callback(null, exchange.webTokenRequest)
      },
    })
    const clientToWebChannel = ably.channels.get(exchange.clientToWebChannel)
    const webToClientChannel = ably.channels.get(exchange.webToClientChannel)
    state.value = {
      token: exchange,
      ably,
      clientToWebChannel,
      webToClientChannel,
    }
  }

  const finish = async () => {
    if (state.value) {
      state.value.ably.close()
      state.value = null
    }
  }

  onUnmounted(() => {
    finish().catch((err: Error) => {
      console.error(err)
    })
  })

  return {
    token,
    ttlUntil: computed(() => {
      console.log(state.value?.token.clientTokenRequest)
      const tm = state.value?.token.clientTokenRequest.timestamp ?? 0
      const ttl = state.value?.token.clientTokenRequest.ttl ?? 0
      return tm + ttl
    }),
    responseAsync,
    requestAsync,
    connect,
    finish,
  }
}
