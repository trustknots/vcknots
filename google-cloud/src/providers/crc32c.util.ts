const CRC32C_POLY = 0x82f63b78

let table: Uint32Array | null = null

const getTable = () => {
  if (table) return table

  table = new Uint32Array(256)
  for (let i = 0; i < 256; i += 1) {
    let crc = i
    for (let j = 0; j < 8; j += 1) {
      crc = (crc & 1) !== 0 ? (crc >>> 1) ^ CRC32C_POLY : crc >>> 1
    }
    table[i] = crc >>> 0
  }
  return table
}

export const crc32c = (input: string | Uint8Array): number => {
  const bytes = typeof input === 'string' ? Buffer.from(input) : input
  const lookup = getTable()

  let crc = 0xffffffff
  for (const byte of bytes) {
    crc = lookup[(crc ^ byte) & 0xff] ^ (crc >>> 8)
  }

  return (crc ^ 0xffffffff) >>> 0
}
