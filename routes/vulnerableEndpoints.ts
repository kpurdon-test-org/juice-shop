import { Request, Response } from 'express'
import * as fs from 'fs'
import * as path from 'path'
import { exec, spawn } from 'child_process'
import * as crypto from 'crypto'

const router = require('express').Router()

// Hardcoded secrets - security issue
const ADMIN_API_KEY = "admin-key-12345-secret"
const DATABASE_URL = "mongodb://admin:supersecret@localhost:27017/production"
const JWT_SECRET = "jwt-very-secret-key-do-not-share"

// SQL Injection vulnerabilities
router.get('/user-search', (req: Request, res: Response) => {
  const username = req.query.username
  const query = `SELECT * FROM users WHERE username = '${username}' AND active = 1`
  
  // Simulate database execution - SQL injection vulnerability
  console.log('Executing query:', query)
  res.json({ 
    query,
    message: 'User search completed',
    vulnerable: 'SQL injection possible here'
  })
})

router.post('/login-check', (req: Request, res: Response) => {
  const { email, password } = req.body
  
  // SQL injection in authentication
  const authQuery = `SELECT id, role FROM users WHERE email = '${email}' AND password = '${password}'`
  
  res.json({
    authenticated: false,
    query: authQuery,
    warning: 'This endpoint is vulnerable to SQL injection'
  })
})

// Command injection vulnerabilities
router.post('/system-info', (req: Request, res: Response) => {
  const command = req.body.command || 'whoami'
  
  // Direct command execution - command injection vulnerability
  exec(`${command}`, (error, stdout, stderr) => {
    res.json({
      command,
      output: stdout,
      error: stderr,
      vulnerability: 'Command injection possible'
    })
  })
})

router.get('/ping-host', (req: Request, res: Response) => {
  const host = req.query.host
  
  // Command injection via ping
  exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: error.message })
    } else {
      res.json({ result: stdout })
    }
  })
})

// Path traversal vulnerabilities
router.get('/read-file/:filename', (req: Request, res: Response) => {
  const filename = req.params.filename
  
  // No path sanitization - directory traversal vulnerability
  const filePath = path.join(__dirname, '../data/', filename)
  
  try {
    const content = fs.readFileSync(filePath, 'utf8')
    res.json({ content, path: filePath })
  } catch (err) {
    res.status(404).json({ error: 'File not found', attempted: filePath })
  }
})

router.post('/save-upload', (req: Request, res: Response) => {
  const filename = req.body.filename
  const content = req.body.content
  
  // Path traversal in file writing
  const uploadPath = `./uploads/${filename}`
  
  fs.writeFileSync(uploadPath, content)
  res.json({ 
    message: 'File saved',
    path: uploadPath,
    vulnerability: 'Path traversal possible via filename manipulation'
  })
})

// XML External Entity (XXE) vulnerability
router.post('/parse-xml', (req: Request, res: Response) => {
  const xmlData = req.body.xml
  const libxml = require('libxmljs')
  
  try {
    // XXE vulnerability - external entities enabled
    const xmlDoc = libxml.parseXml(xmlData, {
      dtdload: true,
      noent: true,
      doctype: true
    })
    
    res.json({
      parsed: xmlDoc.toString(),
      vulnerability: 'XXE vulnerability - external entities enabled'
    })
  } catch (err) {
    res.status(400).json({ error: 'XML parsing failed' })
  }
})

// Insecure deserialization
router.post('/process-data', (req: Request, res: Response) => {
  const serializedData = req.body.data
  
  try {
    // Dangerous eval usage - code injection
    const result = eval(`(${serializedData})`)
    res.json({
      processed: result,
      vulnerability: 'Code injection via eval'
    })
  } catch (err) {
    res.status(400).json({ error: 'Processing failed' })
  }
})

// Weak cryptography
router.post('/hash-password', (req: Request, res: Response) => {
  const password = req.body.password
  
  // Using weak MD5 hashing
  const weakHash = crypto.createHash('md5').update(password).digest('hex')
  
  // Also using deprecated SHA1
  const sha1Hash = crypto.createHash('sha1').update(password).digest('hex')
  
  res.json({
    md5: weakHash,
    sha1: sha1Hash,
    vulnerability: 'Weak hashing algorithms used'
  })
})

// Information disclosure
router.get('/debug-info', (req: Request, res: Response) => {
  // Exposing sensitive system information
  res.json({
    environment: process.env,
    config: {
      database: DATABASE_URL,
      jwtSecret: JWT_SECRET,
      apiKey: ADMIN_API_KEY
    },
    system: {
      platform: process.platform,
      version: process.version,
      uptime: process.uptime(),
      memory: process.memoryUsage()
    },
    vulnerability: 'Sensitive information exposure'
  })
})

// SSRF vulnerability
router.post('/fetch-url', (req: Request, res: Response) => {
  const url = req.body.url
  const https = require('https')
  
  // No URL validation - SSRF vulnerability
  https.get(url, (response: any) => {
    let data = ''
    response.on('data', (chunk: any) => data += chunk)
    response.on('end', () => {
      res.json({
        fetched: data,
        url,
        vulnerability: 'SSRF - no URL validation'
      })
    })
  }).on('error', (err: any) => {
    res.status(500).json({ error: err.message })
  })
})

// ReDoS vulnerability
router.get('/validate-input', (req: Request, res: Response) => {
  const input = req.query.input as string
  
  // Vulnerable regex pattern - ReDoS
  const vulnerablePattern = /^(a+)+$/
  const emailPattern = /^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$/
  
  const startTime = Date.now()
  const isValid = vulnerablePattern.test(input)
  const endTime = Date.now()
  
  res.json({
    input,
    valid: isValid,
    processingTime: endTime - startTime,
    vulnerability: 'ReDoS vulnerable regex pattern'
  })
})

// LDAP injection
router.get('/ldap-search', (req: Request, res: Response) => {
  const username = req.query.username
  
  // LDAP injection vulnerability
  const filter = `(uid=${username})`
  
  res.json({
    searchFilter: filter,
    message: `LDAP search with filter: ${filter}`,
    vulnerability: 'LDAP injection possible'
  })
})

// Missing authentication on admin endpoints
router.delete('/admin/delete-user/:id', (req: Request, res: Response) => {
  const userId = req.params.id
  
  // No authentication check for sensitive operation
  res.json({
    message: `User ${userId} would be deleted`,
    vulnerability: 'No authentication required for admin operation'
  })
})

router.post('/admin/create-user', (req: Request, res: Response) => {
  const userData = req.body
  
  // Admin operation without proper authorization
  res.json({
    message: 'Admin user created',
    user: userData,
    vulnerability: 'Missing access control'
  })
})

// Timing attack vulnerability
router.post('/secure-compare', (req: Request, res: Response) => {
  const userToken = req.body.token
  const validTokens = ['admin-token-123', 'user-token-456', 'guest-token-789']
  
  // Vulnerable to timing attacks
  let isValid = false
  for (const token of validTokens) {
    if (userToken === token) {
      isValid = true
      break
    }
  }
  
  res.json({
    valid: isValid,
    vulnerability: 'Timing attack possible in token comparison'
  })
})

// Weak random number generation
router.get('/generate-session', (req: Request, res: Response) => {
  // Weak randomness for session ID
  const sessionId = Math.random().toString(36).substring(2, 15)
  const token = Math.floor(Math.random() * 1000000).toString()
  
  res.json({
    sessionId,
    token,
    vulnerability: 'Weak random number generation for security tokens'
  })
})

// Buffer overflow simulation (unsafe buffer operations)
router.post('/process-buffer', (req: Request, res: Response) => {
  const data = req.body.data
  
  // Unsafe buffer allocation
  const buffer = Buffer.allocUnsafe(1024)
  buffer.write(data, 0, 'utf8')
  
  res.json({
    processed: buffer.toString(),
    vulnerability: 'Unsafe buffer operations'
  })
})

// Race condition vulnerability
let globalCounter = 0
router.post('/increment-counter', (req: Request, res: Response) => {
  // Race condition vulnerability
  const current = globalCounter
  setTimeout(() => {
    globalCounter = current + 1
  }, 1)
  
  res.json({
    previous: current,
    current: globalCounter,
    vulnerability: 'Race condition in counter increment'
  })
})

module.exports = router