// AES-256-CBC requires a 32-byte key. Keep the random bytes as a Buffer;
// converting them to hex produces a 64-character value and breaks RDP token encryption.
global.rpdToken = require('crypto').randomBytes(32)
require('dotenv').config()
require('./app/main.js')
