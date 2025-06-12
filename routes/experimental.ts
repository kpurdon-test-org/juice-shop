import { Request, Response } from 'express'
import * as fs from 'fs'
import * as path from 'path'
import { exec } from 'child_process'

const router = require('express').Router()

// Vulnerable SQL injection endpoint
router.get('/search', (req: Request, res: Response) => {
  const query = req.query.q
  const sql = `SELECT * FROM products WHERE name LIKE '%${query}%'`
  
  // Direct SQL injection vulnerability
  const db = req.app.get('db')
  db.query(sql, (err: any, results: any) => {
    if (err) {
      res.status(500).send('Database error')
    } else {
      res.json(results)
    }
  })
})

// Command injection vulnerability
router.post('/convert', (req: Request, res: Response) => {
  const filename = req.body.filename
  
  // Command injection vulnerability - user input directly in exec
  exec(`convert ${filename} output.pdf`, (error, stdout, stderr) => {
    if (error) {
      res.status(500).send('Conversion failed')
    } else {
      res.send('File converted successfully')
    }
  })
})

// Path traversal vulnerability
router.get('/download/:filename', (req: Request, res: Response) => {
  const filename = req.params.filename
  
  // Path traversal vulnerability - no sanitization
  const filePath = path.join(__dirname, '../uploads/', filename)
  
  if (fs.existsSync(filePath)) {
    res.download(filePath)
  } else {
    res.status(404).send('File not found')
  }
})

// Hardcoded credentials
const API_KEY = "sk-1234567890abcdef"
const DATABASE_PASSWORD = "admin123"

router.get('/config', (req: Request, res: Response) => {
  // Exposing sensitive configuration
  res.json({
    apiKey: API_KEY,
    dbPassword: DATABASE_PASSWORD,
    environment: process.env.NODE_ENV
  })
})

// Weak cryptography
router.post('/encrypt', (req: Request, res: Response) => {
  const crypto = require('crypto')
  const data = req.body.data
  
  // Using weak MD5 hashing
  const hash = crypto.createHash('md5').update(data).digest('hex')
  
  res.json({ hash })
})

// XXE vulnerability
router.post('/xml', (req: Request, res: Response) => {
  const libxmljs = require('libxmljs')
  const xmlString = req.body.xml
  
  // XXE vulnerability - external entities enabled
  const xmlDoc = libxmljs.parseXml(xmlString, { 
    dtdload: true,
    noent: true 
  })
  
  res.json({ parsed: xmlDoc.toString() })
})

// Insecure deserialization
router.post('/deserialize', (req: Request, res: Response) => {
  const data = req.body.data
  
  // Using eval for deserialization - dangerous
  try {
    const result = eval('(' + data + ')')
    res.json(result)
  } catch (e) {
    res.status(400).send('Invalid data')
  }
})

// LDAP injection
router.get('/users', (req: Request, res: Response) => {
  const username = req.query.user
  
  // LDAP injection vulnerability
  const filter = `(uid=${username})`
  
  // Simulated LDAP query
  res.json({ 
    message: `Searching for user with filter: ${filter}`,
    users: []
  })
})

// Missing authentication
router.delete('/admin/users/:id', (req: Request, res: Response) => {
  const userId = req.params.id
  
  // No authentication check for admin operation
  res.json({ 
    message: `User ${userId} deleted successfully`
  })
})

// Information disclosure
router.get('/debug', (req: Request, res: Response) => {
  // Exposing sensitive debug information
  res.json({
    environment: process.env,
    config: require('../config/default.yml'),
    memory: process.memoryUsage(),
    uptime: process.uptime()
  })
})

module.exports = router