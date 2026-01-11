import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import net from 'node:net'
import { Logger } from './types';
import { INVALID } from './const';

export function getConsoleLogger(): Logger {
  return {
    info: console.info,
    warn: console.warn,
    error: console.error,
  }
}

export function assertPath(path?: string) {
  let newPath = path ?? '';
  newPath = newPath.trim();
  if (!newPath) return newPath;

  if (!newPath.startsWith('/')) {
    newPath = `/${newPath}`
  }
  if (newPath.endsWith('/')) {
    newPath = newPath.substring(0, newPath.length-1)
  }
  return newPath;
}

function isLocalHostname(hostname: string): boolean {
  // Normalize
  const host = hostname.toLowerCase()

  // Obvious local hostnames
  if (host === "localhost") return true
  if (host.endsWith(".localhost")) return true

  // Check if it's an IP address
  const ipType = net.isIP(host)
  if (!ipType) return false

  // IPv4
  if (ipType === 4) {
    return (
      host.startsWith("127.") ||        // loopback
      host.startsWith("10.") ||         // private
      host.startsWith("192.168.") ||    // private
      /^172\.(1[6-9]|2\d|3[0-1])\./.test(host) // private
    )
  }

  // IPv6
  if (ipType === 6) {
    return (
      host === "::1" ||                 // loopback
      host.startsWith("fc") ||          // unique local
      host.startsWith("fd")
    )
  }

  return false
}

export function assertPublicUrl(url?: string) {
  let publicUrl = url ?? '';
  publicUrl = publicUrl.trim();
  if (!publicUrl) return publicUrl;
  
  publicUrl = publicUrl.toLowerCase()
  if (publicUrl.endsWith('/')) {
    publicUrl = publicUrl.substring(0, publicUrl.length-1)
  }
  if (!publicUrl.startsWith('http://') && !publicUrl.startsWith('https://')) {
    return INVALID
  }

  try {
    const urlObj = new URL(publicUrl)
    if (isLocalHostname(urlObj.hostname)) {
      return ''
    } else {
      return publicUrl
    }
  } catch(err) {
    return INVALID
  }
}

function getAppPackageName(): string | null {
  let dir = process.cwd()

  while (true) {
    const pkgPath = path.join(dir, 'package.json')
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'))
        return pkg.name ?? null
      } catch {
        return null
      }
    }

    const parent = path.dirname(dir)
    if (parent === dir) break
    dir = parent
  }

  return null
}

export function getDatabasePath() {
  let dbFile = 'database.sqlite';
  const packageName = getAppPackageName()
  if (packageName) {
    dbFile = `${packageName}-${dbFile}`
  }
  dbFile = dbFile.replace(/\s+/g, '-');

  const dir = path.join(os.homedir(), '.onelyid', 'db')
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true })
  }

  const file = path.join(dir, dbFile)
  return file
}
