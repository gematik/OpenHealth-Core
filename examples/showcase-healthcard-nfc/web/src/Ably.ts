import * as Ably from 'ably'
import { type Message } from 'ably'

const ably = new Ably.Realtime({
  key: '',
  clientId: `client-${Math.random().toString(36).substring(2, 10)}`,
})

export type Command = CommandVerify | CommandApdu | CommandFinish

export type CommandVerify = {
  type: "verif",
  code: string
}

export type CommandApdu = {
  type: "cmd",
  apdu: string
}

export type CommandFinish = {
  type: "finish",
}


export function useAbly({channelReceiveName, channelRequestName}: {channelReceiveName: string, channelRequestName: string }) {
  const channelReceive = ably.channels.get(channelReceiveName);
  const channelRequest = ably.channels.get(channelRequestName);

  const responseAsync = async (): Promise<Command> => {
    return new Promise((resolve) => {
      channelRequest.subscribe((message: Message) => {
        resolve(message.data as Command)
        channelRequest?.unsubscribe()
      })
    })
  }

  const requestAsync = async (request: Command, expectResponse: boolean = true): Promise<Command> => {
    return new Promise((resolve) => {
      channelReceive.publish('request', request)
      if (expectResponse) {
        channelRequest.subscribe((message: Message) => {
          resolve(message.data as Command)
          channelRequest?.unsubscribe()
        })
      }
    })
  }

  return {
    responseAsync,
    requestAsync,
  }
}
