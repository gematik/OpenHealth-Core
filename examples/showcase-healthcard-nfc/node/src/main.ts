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

import pcsclite from 'pcsclite'
import * as Ably from 'ably'

const ably = new Ably.Realtime({ key: 'Wdy9DA.-6gnKg:cAks85v4VaNMx45AL-2am_nd4rgNcOnve2oXfi1NsZw' })

const channelReceive = ably.channels.get('receive')
const channelRequest = ably.channels.get('request')

const pcsc = pcsclite()

pcsc.on('reader', (reader) => {
  console.log('New reader detected', reader.name)

  reader.on('error', (err) => {
    console.log('Error(', reader.name, '):', err.message)
  })

  reader.on('status', (status) => {
    console.log('Status(', reader.name, '):', status)

    const changes = reader.state ^ status.state

    if (changes) {
      if (changes & reader.SCARD_STATE_EMPTY && status.state & reader.SCARD_STATE_EMPTY) {
        console.log('Card removed')

        reader.disconnect(reader.SCARD_LEAVE_CARD, (err) => {
          if (err) {
            console.log(err)
          } else {
            console.log('Disconnected')
          }
        })
      } else if (
        changes & reader.SCARD_STATE_PRESENT &&
        status.state & reader.SCARD_STATE_PRESENT
      ) {
        console.log('Card inserted')

        reader.connect({ share_mode: reader.SCARD_SHARE_SHARED }, (err, protocol) => {
          if (err) {
            console.log(err)
          } else {
            console.log('Protocol(', reader.name, '):', protocol)

            channelReceive.subscribe((message: Ably.Message) => {
              const data = message.data as { apdu: string }
              const command = Buffer.from(data.apdu, 'hex')
              console.log('Command: ', data.apdu)
              reader.transmit(command, 65536, protocol, (err, data) => {
                if (err) {
                  console.log(err)
                } else {
                  console.log('Data received', data.toString('hex'))
                  channelRequest.publish('response', { apdu: data.toString('hex') })
                }
              })
            })
          }
        })
      }
    }
  })

  reader.on('end', () => {
    console.log('Reader', reader.name, 'removed')
  })
})

pcsc.on('error', (err) => {
  console.log('PCSC error', err.message)
})
