import NodeJose  from 'node-jose'
const {JWK} = NodeJose

async function generateJWKS() {
  const keystore = JWK.createKeyStore()
  
  const key = await keystore.generate('RSA', 2048, { alg: 'RS256', use: 'sig' })
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