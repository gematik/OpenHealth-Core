export function int8ArrayToHex(int8Array: Int8Array) {
  return Array.from(int8Array)
    .map((byte) => (byte & 0xff).toString(16).padStart(2, '0'))
    .join('')
}

export function hexToInt8Array(hexString: string) {
  if (hexString.length % 2 !== 0) {
    throw new Error('Invalid hex string length')
  }

  const array = new Int8Array(hexString.length / 2)

  for (let i = 0; i < hexString.length; i += 2) {
    const byte = parseInt(hexString.substring(i, i + 2), 16)
    array[i / 2] = byte > 127 ? byte - 256 : byte // Handle signed values
  }

  return array
}
