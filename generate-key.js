import NodeJose  from 'node-jose'
const {JWK} = NodeJose

async function generateJWKS() {
  const keystore = JWK.createKeyStore()
  
  const key = await keystore.generate('RSA', 2048, { alg: 'RS256', use: 'sig' })
  
  console.log(
    JSON.stringify(
      key.toJSON(true)
    )
  )
}

generateJWKS()