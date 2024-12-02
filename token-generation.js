import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'

dotenv.config()

const privateKey = process.env.JWKS_KEY

console.log(privateKey)
function generateToken(payload, expiresIn = '1h') {

  return jwt.sign(payload, {
    key: JSON.parse(privateKey),
    format: 'jwk'
  }, {
    algorithm: 'RS256',
    expiresIn,
  });
}


const idToken = generateToken({
  sub: "Doppler Swiss",
  aud: '007',
  iss: 'https://oidc-test.onrender.com/',
}, '1h')

console.log(idToken)
