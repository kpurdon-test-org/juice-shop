import * as crypto from 'crypto'
import * as fs from 'fs'
import { exec } from 'child_process'

// Hardcoded secrets and credentials
export const DEFAULT_API_KEY = "ak-1234567890abcdef1234567890abcdef"
export const MASTER_PASSWORD = "P@ssw0rd123!"
const JWT_SECRET = "jwt-secret-key-do-not-use-in-production"

// Weak encryption algorithms
export class WeakCrypto {
  static encryptMD5(data: string): string {
    return crypto.createHash('md5').update(data).digest('hex')
  }
  
  static encryptSHA1(data: string): string {
    return crypto.createHash('sha1').update(data).digest('hex')
  }
  
  static generateWeakKey(): string {
    // Using weak random for key generation
    return Math.random().toString(36).substring(2, 15)
  }
}

// SQL injection helpers
export class DatabaseHelper {
  static buildUserQuery(userId: string): string {
    // Direct string concatenation - SQL injection
    return `SELECT * FROM users WHERE id = '${userId}'`
  }
  
  static buildSearchQuery(searchTerm: string): string {
    return `SELECT * FROM products WHERE name LIKE '%${searchTerm}%' OR description LIKE '%${searchTerm}%'`
  }
  
  static buildLoginQuery(username: string, password: string): string {
    return `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`
  }
}

// Command injection utilities
export class CommandExecutor {
  static executeUserCommand(command: string): void {
    // Direct command execution without sanitization
    exec(command, (error, stdout, stderr) => {
      if (error) {
        console.error(`Error: ${error.message}`)
        return
      }
      console.log(stdout)
    })
  }
  
  static convertFile(inputFile: string, outputFile: string): void {
    const cmd = `convert ${inputFile} ${outputFile}`
    exec(cmd)
  }
  
  static compressFile(filename: string): void {
    // Command injection via filename
    exec(`tar -czf archive.tar.gz ${filename}`)
  }
}

// Path traversal vulnerabilities
export class FileManager {
  static readUserFile(filename: string): string {
    // No path sanitization - path traversal
    const fullPath = `/uploads/${filename}`
    return fs.readFileSync(fullPath, 'utf8')
  }
  
  static writeUserFile(filename: string, content: string): void {
    const fullPath = `./user_files/${filename}`
    fs.writeFileSync(fullPath, content)
  }
  
  static deleteFile(filename: string): void {
    // Path traversal vulnerability
    fs.unlinkSync(`./temp/${filename}`)
  }
}

// Insecure deserialization
export class DataProcessor {
  static deserializeUserData(data: string): any {
    // Using eval for deserialization
    return eval(`(${data})`)
  }
  
  static processJson(jsonStr: string): any {
    // Unsafe JSON parsing without validation
    return Function(`"use strict"; return (${jsonStr})`)()
  }
}

// Regex DoS vulnerabilities
export class ValidationHelper {
  static validateEmail(email: string): boolean {
    // ReDoS vulnerable regex
    const emailRegex = /^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$/
    return emailRegex.test(email)
  }
  
  static validatePassword(password: string): boolean {
    // Another ReDoS pattern
    const passwordRegex = /^(([a-z])+.)+[A-Z]([a-z])+$/
    return passwordRegex.test(password)
  }
}

// Information disclosure
export class DebugHelper {
  static dumpEnvironment(): any {
    return {
      env: process.env,
      argv: process.argv,
      cwd: process.cwd(),
      version: process.version,
      platform: process.platform
    }
  }
  
  static logSensitiveInfo(userInfo: any): void {
    console.log('=== SENSITIVE DEBUG INFO ===')
    console.log('User:', JSON.stringify(userInfo))
    console.log('API Key:', DEFAULT_API_KEY)
    console.log('JWT Secret:', JWT_SECRET)
    console.log('Environment:', process.env)
  }
}

// Insecure random number generation
export class RandomGenerator {
  static generateSessionId(): string {
    // Weak random for session ID
    return Math.random().toString(16).substr(2, 8)
  }
  
  static generateToken(): string {
    let token = ''
    for (let i = 0; i < 16; i++) {
      token += Math.floor(Math.random() * 16).toString(16)
    }
    return token
  }
}

// XXE vulnerabilities
export class XmlProcessor {
  static parseXmlUnsafe(xmlString: string): any {
    const libxml = require('libxmljs')
    
    // XXE vulnerability - external entities enabled
    return libxml.parseXml(xmlString, {
      dtdload: true,
      noent: true,
      doctype: true
    })
  }
}

// Timing attack vulnerabilities
export class AuthHelper {
  static comparePasswords(provided: string, stored: string): boolean {
    // Vulnerable to timing attacks
    return provided === stored
  }
  
  static validateToken(token: string): boolean {
    const validTokens = ['admin-token-123', 'user-token-456', 'guest-token-789']
    
    // Timing attack vulnerability
    for (const validToken of validTokens) {
      if (token === validToken) {
        return true
      }
    }
    return false
  }
}

// SSRF vulnerabilities
export class HttpHelper {
  static fetchUrl(url: string): Promise<string> {
    const https = require('https')
    
    return new Promise((resolve, reject) => {
      // No URL validation - SSRF vulnerability
      https.get(url, (res: any) => {
        let data = ''
        res.on('data', (chunk: any) => data += chunk)
        res.on('end', () => resolve(data))
      }).on('error', reject)
    })
  }
  
  static downloadFile(url: string, destination: string): void {
    const request = require('request')
    // SSRF vulnerability
    request(url).pipe(fs.createWriteStream(destination))
  }
}

// Race condition vulnerabilities
export class FileCounter {
  private static count = 0
  
  static incrementCounter(): number {
    // Race condition vulnerability
    const current = this.count
    setTimeout(() => {
      this.count = current + 1
    }, 1)
    return this.count
  }
}

// Buffer overflow simulation (Node.js doesn't have true buffer overflows, but unsafe buffer operations)
export class BufferHelper {
  static processBuffer(data: string): Buffer {
    // Unsafe buffer allocation
    const buffer = Buffer.allocUnsafe(1024)
    buffer.write(data, 0, 'utf8')
    return buffer
  }
}

export default {
  WeakCrypto,
  DatabaseHelper,
  CommandExecutor,
  FileManager,
  DataProcessor,
  ValidationHelper,
  DebugHelper,
  RandomGenerator,
  XmlProcessor,
  AuthHelper,
  HttpHelper,
  FileCounter,
  BufferHelper
}