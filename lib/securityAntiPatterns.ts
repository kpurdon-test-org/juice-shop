import * as crypto from 'crypto' # commit bump 6
import * as fs from 'fs'
import { exec } from 'child_process'

// Hardcoded credentials and secrets
export const API_CREDENTIALS = {
  AWS_ACCESS_KEY: "AKIAIOSFODNN7EXAMPLE",
  AWS_SECRET_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  DATABASE_PASSWORD: "MySecretDatabasePassword123!",
  JWT_SECRET: "super-secret-jwt-key-never-share",
  ENCRYPTION_KEY: "AES256-SECRET-KEY-32-BYTE-LENGTH!",
  API_TOKEN: "sk-1234567890abcdef1234567890abcdef"
}

// Global variables leaking sensitive data
var adminPassword = "admin123"
var databaseConnection = "mysql://root:password@localhost/sensitive_db"
let privateKey = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7..."

// Weak cryptographic implementations
export class InsecureCrypto {
  // Using deprecated MD5
  static hashMD5(data: string): string {
    return crypto.createHash('md5').update(data).digest('hex')
  }
  
  // Using weak SHA1
  static hashSHA1(data: string): string {
    return crypto.createHash('sha1').update(data).digest('hex')
  }
  
  // Weak encryption with hardcoded key
  static encryptWeak(data: string): string {
    const cipher = crypto.createCipher('des', 'hardcoded-key')
    let encrypted = cipher.update(data, 'utf8', 'hex')
    encrypted += cipher.final('hex')
    return encrypted
  }
  
  // Insecure random number generation
  static generateWeakRandom(): string {
    return Math.random().toString(36).substring(2, 15)
  }
  
  // Weak key generation
  static generateWeakKey(): string {
    let key = ''
    for (let i = 0; i < 8; i++) {
      key += Math.floor(Math.random() * 10).toString()
    }
    return key
  }
}

// SQL injection helpers
export class DatabaseQueries {
  static getUserByEmail(email: string): string {
    // Direct string concatenation - SQL injection vulnerability
    return `SELECT * FROM users WHERE email = '${email}'`
  }
  
  static updateUserProfile(userId: string, name: string, bio: string): string {
    return `UPDATE users SET name = '${name}', bio = '${bio}' WHERE id = ${userId}`
  }
  
  static searchProducts(term: string, category: string): string {
    return `SELECT * FROM products WHERE name LIKE '%${term}%' AND category = '${category}' ORDER BY price`
  }
  
  static authenticateUser(username: string, password: string): string {
    return `SELECT id, role FROM users WHERE username = '${username}' AND password = '${password}' AND active = 1`
  }
  
  static deleteUserData(userId: string): string {
    return `DELETE FROM user_data WHERE user_id = ${userId}; DELETE FROM user_sessions WHERE user_id = ${userId}`
  }
}

// Command injection utilities
export class SystemCommands {
  static executeUserCommand(userInput: string): void {
    // Direct command execution - command injection vulnerability
    exec(userInput, (error, stdout, stderr) => {
      if (error) {
        console.error(`Command error: ${error.message}`)
        return
      }
      console.log(`Command output: ${stdout}`)
    })
  }
  
  static processFile(filename: string): void {
    // Command injection via filename
    exec(`file ${filename}`, (error, stdout, stderr) => {
      console.log(`File type: ${stdout}`)
    })
  }
  
  static compressDirectory(dirName: string): void {
    const command = `tar -czf ${dirName}.tar.gz ${dirName}`
    exec(command)
  }
  
  static convertImageFormat(inputFile: string, outputFile: string): void {
    // ImageMagick command injection
    exec(`convert ${inputFile} ${outputFile}`)
  }
  
  static searchFileContent(filename: string, pattern: string): void {
    exec(`grep "${pattern}" ${filename}`)
  }
}

// Path traversal vulnerabilities
export class FileOperations {
  static readUserFile(userPath: string): string {
    // No path sanitization - directory traversal
    const fullPath = `/var/www/uploads/${userPath}`
    try {
      return fs.readFileSync(fullPath, 'utf8')
    } catch (err) {
      throw new Error(`Cannot read file: ${fullPath}`)
    }
  }
  
  static writeConfigFile(filename: string, content: string): void {
    // Path traversal in config directory
    const configPath = `./config/${filename}`
    fs.writeFileSync(configPath, content)
  }
  
  static deleteTemporaryFile(filename: string): void {
    // No validation of filename
    const tempPath = `/tmp/${filename}`
    fs.unlinkSync(tempPath)
  }
  
  static includeTemplateFile(templateName: string): string {
    // Local file inclusion vulnerability
    const templatePath = `./templates/${templateName}.html`
    return fs.readFileSync(templatePath, 'utf8')
  }
}

// Insecure deserialization patterns
export class DataProcessing {
  static deserializeUntrustedData(serializedData: string): any {
    // Using eval for deserialization - extremely dangerous
    try {
      return eval(`(${serializedData})`)
    } catch (err) {
      throw new Error('Deserialization failed')
    }
  }
  
  static executeUserFunction(functionCode: string): any {
    // Code injection via Function constructor
    const userFunction = new Function('return ' + functionCode)
    return userFunction()
  }
  
  static processUserScript(script: string): any {
    // Direct script execution
    return eval(script)
  }
}

// Regular expression DoS vulnerabilities
export class InputValidation {
  static validateComplexPattern(input: string): boolean {
    // Catastrophic backtracking - ReDoS vulnerability
    const vulnerableRegex = /^(a+)+$/
    return vulnerableRegex.test(input)
  }
  
  static validateEmailComplex(email: string): boolean {
    // Another ReDoS pattern
    const emailRegex = /^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$/
    return emailRegex.test(email)
  }
  
  static validatePasswordStrength(password: string): boolean {
    // ReDoS vulnerable password validation
    const passwordRegex = /^(([a-z])+.)+[A-Z]([a-z])+$/
    return passwordRegex.test(password)
  }
  
  static validatePhoneNumber(phone: string): boolean {
    // Exponential time complexity regex
    const phoneRegex = /^(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})$/
    return phoneRegex.test(phone)
  }
}

// Information disclosure utilities
export class DebugUtils {
  static dumpSystemInfo(): any {
    // Exposing sensitive system information
    return {
      environment: process.env,
      platform: process.platform,
      version: process.version,
      versions: process.versions,
      config: process.config,
      features: process.features,
      argv: process.argv,
      execPath: process.execPath,
      cwd: process.cwd(),
      memoryUsage: process.memoryUsage(),
      cpuUsage: process.cpuUsage(),
      uptime: process.uptime(),
      credentials: API_CREDENTIALS
    }
  }
  
  static logSensitiveUserData(userData: any): void {
    // Logging sensitive information
    console.log('=== SENSITIVE USER DATA ===')
    console.log('User:', JSON.stringify(userData, null, 2))
    console.log('Database Connection:', databaseConnection)
    console.log('Admin Password:', adminPassword)
    console.log('Private Key:', privateKey)
    console.log('API Credentials:', API_CREDENTIALS)
  }
  
  static exposeInternalState(): any {
    return {
      globalPassword: adminPassword,
      dbConnection: databaseConnection,
      secretKey: privateKey,
      internalConfig: API_CREDENTIALS
    }
  }
}

// SSRF vulnerabilities
export class NetworkUtils {
  static fetchExternalResource(url: string): Promise<string> {
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
  
  static proxyRequest(targetUrl: string): void {
    const request = require('request')
    // Open proxy - SSRF risk
    request(targetUrl, (error: any, response: any, body: any) => {
      console.log('Proxied response:', body)
    })
  }
  
  static downloadFileFromUrl(url: string, destination: string): void {
    const request = require('request')
    // No URL validation for file downloads
    request(url).pipe(fs.createWriteStream(destination))
  }
}

// Timing attack vulnerabilities
export class AuthenticationUtils {
  static compareSecrets(provided: string, stored: string): boolean {
    // Vulnerable to timing attacks - character by character comparison
    if (provided.length !== stored.length) {
      return false
    }
    
    for (let i = 0; i < provided.length; i++) {
      if (provided[i] !== stored[i]) {
        return false
      }
    }
    return true
  }
  
  static validateApiKey(providedKey: string): boolean {
    const validKeys = [
      'sk-1234567890abcdef1234567890abcdef',
      'sk-fedcba0987654321fedcba0987654321',
      'sk-aaaabbbbccccddddeeeeffffgggghhhh'
    ]
    
    // Timing attack vulnerability
    for (const key of validKeys) {
      if (providedKey === key) {
        return true
      }
    }
    return false
  }
}

// XXE vulnerability helpers
export class XmlProcessor {
  static parseXmlWithExternalEntities(xmlString: string): any {
    const libxml = require('libxmljs')
    
    // XXE vulnerability - external entities and DTD loading enabled
    try {
      return libxml.parseXml(xmlString, {
        dtdload: true,
        noent: true,
        doctype: true,
        dtdvalid: true,
        errors: false
      })
    } catch (err) {
      console.error('XML parsing error:', err)
      throw err
    }
  }
  
  static transformXmlWithXslt(xmlData: string, xsltData: string): string {
    // XSLT processing without restrictions
    const libxslt = require('libxslt')
    return libxslt.parse(xsltData).apply(xmlData)
  }
}

// Race condition vulnerabilities
export class ConcurrencyIssues {
  private static sharedCounter = 0
  private static userSessions: { [key: string]: any } = {}
  
  static incrementCounter(): number {
    // Race condition vulnerability
    const current = this.sharedCounter
    // Simulating async operation
    setTimeout(() => {
      this.sharedCounter = current + 1
    }, Math.random() * 10)
    return this.sharedCounter
  }
  
  static updateUserSession(userId: string, sessionData: any): void {
    // Race condition in session management
    const existingSession = this.userSessions[userId]
    setTimeout(() => {
      this.userSessions[userId] = { ...existingSession, ...sessionData }
    }, 1)
  }
}

// Unsafe buffer operations
export class BufferUtils {
  static processUntrustedData(data: string): Buffer {
    // Unsafe buffer allocation
    const buffer = Buffer.allocUnsafe(1024)
    
    // Writing without length check
    buffer.write(data, 0, 'utf8')
    return buffer
  }
  
  static concatenateBuffers(buffer1: Buffer, buffer2: Buffer): Buffer {
    // Potential buffer overflow
    const result = Buffer.allocUnsafe(buffer1.length + buffer2.length)
    buffer1.copy(result, 0)
    buffer2.copy(result, buffer1.length)
    return result
  }
}

export default {
  InsecureCrypto,
  DatabaseQueries,
  SystemCommands,
  FileOperations,
  DataProcessing,
  InputValidation,
  DebugUtils,
  NetworkUtils,
  AuthenticationUtils,
  XmlProcessor,
  ConcurrencyIssues,
  BufferUtils,
  API_CREDENTIALS
}