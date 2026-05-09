const express = require('express')
const crypto = require('crypto')
const fs = require('fs')
const path = require('path')

const app = express()
const port = 3000

// Simple CORS implementation
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// Middleware to receive raw encrypted data as text/plain
app.use(express.text({ type: 'text/plain', limit: '10mb' }))

app.get('/', (req, res) => {
  res.send('BFF is running')
})

app.post('/charge', (req, res) => {
  try {
    const encryptedDataB64 = req.body
    if (!encryptedDataB64 || typeof encryptedDataB64 !== 'string') {
      console.error('Invalid or missing body')
      return res.status(400).send('Invalid data')
    }

    // 1. Decode payload
    const fullBuffer = Buffer.from(encryptedDataB64, 'base64')

    // 2. Extract components
    // Ephemeral Public Key (Raw P-256 is 65 bytes)
    const EPHEMERAL_PUB_KEY_SIZE = 65
    const IV_SIZE = 12

    if (fullBuffer.length < EPHEMERAL_PUB_KEY_SIZE + IV_SIZE + 16) {
      throw new Error('Payload too short (minimum size: PubKey + IV + AuthTag)')
    }

    const ephemeralPubKeyRaw = fullBuffer.slice(0, EPHEMERAL_PUB_KEY_SIZE)
    const iv = fullBuffer.slice(EPHEMERAL_PUB_KEY_SIZE, EPHEMERAL_PUB_KEY_SIZE + IV_SIZE)
    const ciphertextWithTag = fullBuffer.slice(EPHEMERAL_PUB_KEY_SIZE + IV_SIZE)

    // 3. Get Private Key from environment variable
    const privateKeyPem = process.env.PRIVATE_KEY_PEM ? process.env.PRIVATE_KEY_PEM.replace(/\\n/g, '\n') : null;
    if (!privateKeyPem) {
      throw new Error('PRIVATE_KEY_PEM environment variable is missing');
    }
    const privateKey = crypto.createPrivateKey(privateKeyPem)

    // 4. Compute Shared Secret (ECDH)
    // We convert the raw ephemeral public key into SPKI format by adding the DER header
    const spkiHeader = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex')
    const ephemeralPublicKey = crypto.createPublicKey({
      key: Buffer.concat([spkiHeader, ephemeralPubKeyRaw]),
      format: 'der',
      type: 'spki'
    })

    const sharedSecret = crypto.diffieHellman({
      privateKey: privateKey,
      publicKey: ephemeralPublicKey
    })

    // 5. Derive AES-GCM key (using SHA-256 as KDF, matching frontend)
    const aesKey = crypto.createHash('sha256').update(sharedSecret).digest()

    // 6. Decrypt with AES-GCM
    // In Web Crypto, the 16-byte authentication tag is appended to the ciphertext
    const tag = ciphertextWithTag.slice(-16)
    const ciphertext = ciphertextWithTag.slice(0, -16)

    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv)
    decipher.setAuthTag(tag)

    let decrypted = decipher.update(ciphertext, 'binary', 'utf8')
    decrypted += decipher.final('utf8')

    // 7. Parse and Log
    const result = JSON.parse(decrypted)
    console.log('--- Decrypted Charge Data ---')
    console.log(result)
    console.log('-----------------------------')

    res.status(200).json({ status: 'success' })
  } catch (err) {
    console.error('Decryption failed:', err.message)
    res.status(500).send('Decryption failed')
  }
})

app.listen(port, () => {
  console.log(`BFF listening on port ${port}`)
})
