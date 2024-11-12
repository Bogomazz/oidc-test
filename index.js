import Provider from 'oidc-provider'
import NodeJose  from 'node-jose'
import dotenv from 'dotenv'
import express from 'express'

const app = express()

const {JWK} = NodeJose
dotenv.config()
const { 
  SDO_PUBLIC_HOST: public_host, 
  OIDC_CLIENT_ID: client_id, 
  OIDC_REDIRECT_URIS: redirect_uris_str,
  PORT,
} = process.env
const redirect_uris = [] // redirect_uris_str?.split(',')

const port = PORT || 8080;

async function generateJWKS() {
  const keystore = JWK.createKeyStore()
  
  const key = await keystore.generate('RSA', 2048, { alg: 'RS256', use: 'sig' })
  
  return {
    keys: [key.toJSON(true)]
  }
}

async function init() {

  const jwks = await generateJWKS()

  const configuration = {
    clients: [
      {
        client_id,
        client_secret: 'bar',
        redirect_uris,
        response_types: ['id_token'],
        grant_types: ['implicit'],
        token_endpoint_auth_method: 'none',
        scope: 'openid',
      },
    ],
    claims: {

      openid: [
        'sub'
      ],
    },
    scopes: ['openid'],
    responseTypes: ['id_token'],
    discovery: {
        "SigningKeys": [],
    },
    issuer: `https://${public_host}:${port}/`,
    jwks,
  }

  
  
  const oidc = new Provider(`https://${public_host}:${port}`, configuration)
  
  app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
    console.log(req.body);
    next()
  }) 

  app.use(oidc.callback())
  app.listen(port, () => {
    console.log(
      `oidc-provider listening on port ${port}, check https://${public_host}:${port}/.well-known/openid-configuration`,
    )
  })
}

init()