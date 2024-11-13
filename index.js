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
  NODE_ENV
} = process.env
const redirect_uris = []

const port = PORT || 8080;
const DEV = NODE_ENV === 'development'
const PORT_POSTFIX = DEV ? `:${port}` : ''
const PROTOCOL = DEV ? 'http' : 'https'

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
    issuer: `${PROTOCOL}://${public_host}${PORT_POSTFIX}/`,
    jwks,
  }

  
  
  const oidc = new Provider(`${PROTOCOL}://${public_host}${PORT_POSTFIX}/`, configuration)
  oidc.use(async (ctx, next) => {

    console.log(new Date().toISOString(), ctx.method, ctx.path)
    await next()
    /** post-processing
     * since internal route matching was already executed you may target a specific action here
     * checking `ctx.oidc.route`, the unique route names used are
     *
     * `authorization`
     * `backchannel_authentication`
     * `client_delete`
     * `client_update`
     * `client`
     * `code_verification`
     * `cors.device_authorization`
     * `cors.discovery`
     * `cors.introspection`
     * `cors.jwks`
     * `cors.pushed_authorization_request`
     * `cors.revocation`
     * `cors.token`
     * `cors.userinfo`
     * `device_authorization`
     * `device_resume`
     * `discovery`
     * `end_session_confirm`
     * `end_session_success`
     * `end_session`
     * `introspection`
     * `jwks`
     * `pushed_authorization_request`
     * `registration`
     * `resume`
     * `revocation`
     * `token`
     * `userinfo`
     */
    if (ctx.oidc?.route === 'discovery') {
      ctx.response.body = {...ctx.response.body, authorization_endpoint: ctx.response.body.authorization_endpoint.replace('http://', 'https://')}
    }
    console.log(ctx.response.body)
  })
  

  app.use(oidc.callback())

  app.listen(port, () => {
    console.log(
      `oidc-provider listening on port ${port}, check ${PROTOCOL}://${public_host}${PORT_POSTFIX}/.well-known/openid-configuration`,
    )
  })
}

init()