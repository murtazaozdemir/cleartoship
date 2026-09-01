export function verifyToken(raw: string): boolean {
  try {
    return checkSignature(raw)
  } catch {
    return true                                           // CTS071: fails OPEN
  }
}

export async function isAuthorized(userId: string): Promise<boolean> {
  try {
    return await lookupRole(userId)
  } catch (e) {
    // swallow
  }
  return false
}

export function safeVerify(raw: string): boolean {
  try {
    return checkSignature(raw)
  } catch {
    return false                                          // fail-closed: OK, not flagged
  }
}
