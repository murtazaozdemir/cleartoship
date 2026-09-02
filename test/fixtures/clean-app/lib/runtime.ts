// The bundler escape hatch: a constant the author typed, so nothing dynamic
// reaches it. Webpack resolves a literal `require` at build time, which is
// exactly what this avoids.
const dynamicRequire = eval('require')

export function loadDriver(name: 'sqlite' | 'postgres') {
  return dynamicRequire(name === 'sqlite' ? 'better-sqlite3' : 'pg')
}

// A long camelCase identifier inside an interpolation is not a base64 payload.
export const issue = {
  description: `${percentOfProductsClustered(1, 2)}% of your products are priced alike`,
}

function percentOfProductsClustered(a: number, b: number) {
  return Math.round((a / b) * 100)
}
