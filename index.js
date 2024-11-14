import Provider from 'oidc-provider'
import dotenv from 'dotenv'
import express from 'express'

const app = express()

dotenv.config()
const { 
  SDO_PUBLIC_HOST: public_host, 
  OIDC_CLIENT_ID: client_id, 
  OIDC_REDIRECT_URIS: redirect_uris_str,
  PORT,
  NODE_ENV,
  JWKS_KEY
} = process.env

const redirect_uris = ['https://login.microsoftonline.com/common/federation/externalauthprovider']
const port = PORT || 8080;
const DEV = NODE_ENV === 'development'
const PORT_POSTFIX = DEV ? `:${port}` : ''
const PROTOCOL = DEV ? 'http' : 'https'

async function init() {

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
    jwks: {
      keys: [JSON.parse(JWKS_KEY)]
    },
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
    if (ctx.oidc?.route === 'discovery' && !DEV) {
      ctx.response.body = {
        ...ctx.response.body, 
        authorization_endpoint: ctx.response.body.authorization_endpoint.replace('http://', 'https://'),
        jwks_uri: ctx.response.body.jwks_uri.replace('http://', 'https://'),
        token_endpoint: ctx.response.body.token_endpoint.replace('http://', 'https://'),
        userinfo_endpoint: ctx.response.body.userinfo_endpoint.replace('http://', 'https://'),
        pushed_authorization_request_endpoint: ctx.response.body.pushed_authorization_request_endpoint.replace('http://', 'https://'),
        end_session_endpoint: ctx.response.body.end_session_endpoint.replace('http://', 'https://'),
      }
    }
    console.log(ctx.response.body)
  })
  

  app.use(oidc.callback())
  app.get('/', (req, res) => {res.send("OK")})

  app.listen(port, () => {
    console.log(
      `oidc-provider listening on port ${port}, check ${PROTOCOL}://${public_host}${PORT_POSTFIX}/.well-known/openid-configuration`,
    )
  })
}

init()