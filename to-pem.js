import dotenv from 'dotenv'
import NodeJose from 'node-jose'

dotenv.config()

const jwk = JSON.parse(process.env.JWKS_KEY)

// Create the JWK key
const key = await NodeJose.JWK.asKey(jwk);

// Export to PEM
const pem = key.toPEM(); // true includes private key, false for public key
console.log('PEM:', pem);