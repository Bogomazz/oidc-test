import NodeJose  from 'node-jose'
import dotenv from 'dotenv'

dotenv.config()

const {JWK} = NodeJose
const JWKS_KEY = process.env.JWKS_KEY

async function generateJWKS() {
  const keystore = JWK.createKeyStore()
  
  // const key = await keystore.generate('RSA', 2048, { alg: 'RS256', use: 'sig' })
  const key = await keystore.add(
    JSON.parse(JWKS_KEY)
  )
  console.log(key)
  console.log('PRIVATE KEY')
  console.log(
    JSON.stringify(
      key.toJSON(true)
    )
  )
  console.log('PUBLIC KEY')
  console.log(
    JSON.stringify(
      key.toJSON()
    )
  )
}

generateJWKS()