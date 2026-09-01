import { unserialize } from 'node-serialize'
export function hydrate(cookie: string) {
  return unserialize(cookie)       // CTS072: node-serialize RCE
}
