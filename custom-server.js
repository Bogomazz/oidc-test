import express from 'express';
import jwt from 'jsonwebtoken';
import bodyParser from 'body-parser';
import dotenv from 'dotenv'

dotenv.config()

const msKeysUrl = 'https://login.microsoftonline.com/common/discovery/v2.0/keys';

const {
  OIDC_CLIENT_ID,
  PORT: port = 4000,
  SDO_PUBLIC_HOST: host,
  JWKS_KEY,
} = process.env;
const WHITELISTED_KEYS = ['kty', 'kid', 'use', 'alg', 'e', 'n', 'x5c']
const JWK = JWKS_KEY ? JSON.parse(JWKS_KEY) : null;

console.log('jwks: -------------------');
console.log(JWK);

function generateToken(payload, keyObj, expiresIn) {
  return jwt.sign(payload, keyObj, {
    algorithm: 'RS256',
    expiresIn: expiresIn,
    header: {
      kid: keyObj.key.kid
    }
  });
}

async function initApp() {
  const app = express();

  const privateKey = {
    key: JWK,
    format: 'jwk'
  }

  app.use(bodyParser.urlencoded({ extended: true }));
  app.use(bodyParser.json());

  app.use((req, res, next) => {
    console.log(`Requsting: ${req.url} - ${req.method} --------------------------------`);
    console.log('req.headers:');
    console.log(req.headers);
    console.dir(req.query ? req.query : {});
    console.dir(req.params ? req.params : {});
    console.dir(req.body ? req.body : {});

    next();
  });

  app.post('/authorize', async (req, res) => {
    const {
      scope,
      response_mode,
      response_type,
      client_id,
      redirect_uri,
      claims,
      nonce,
      id_token_hint,
      'client-request-id': clientRequestId,
      state
    } = req.body;

    console.log('client-request-id', clientRequestId);

    const { keys } = await fetch(msKeysUrl).then(res => res.json());

    console.log('Id token hint', id_token_hint)
    const decodedIdTokenHint = jwt.decode(id_token_hint, { complete: true });
    const { kid: idTokenHintKID } = decodedIdTokenHint.header;
    console.log('decoded id token hint', decodedIdTokenHint)
    const key = keys.find(key => key.kid === idTokenHintKID);
    const pKey = {
      key,
      format: 'jwk'
    }

    let decoded;
    try {
      decoded = jwt.verify(id_token_hint, pKey, { complete: true });
    } catch (error) {
      console.error(error);
      return res.status(400).json({ error: 'Invalid id_token_hint' });
    }

    console.log(decoded);

    if (
      !scope ||
      response_mode !== 'form_post' ||
      response_type !== 'id_token' ||
      !client_id ||
      !redirect_uri
    ) {
      return res.status(400).json({ error: 'Invalid request' });
    }
    
    const {
      preferred_username: username,
      iss,
      aud,
      sub,
      name,
      oid,
      tid,
      uti,
      ver,
    } = decoded.payload;

    const idToken = generateToken({
      sub: sub,
      aud: client_id,
      nonce: nonce,
      amr: ['face'],
      acr: 'possessionorinherence',
      // preferred_username: username,
      iss: `https://${process.env.SDO_PUBLIC_HOST}`,
    }, privateKey, '1h');

    console.log('id token: ', idToken)
    
    res.send(`
      <form method="POST" action="${redirect_uri}">
        <input type="hidden" name="state" value="${state}" />
        <input type="hidden" name="id_token" value="${idToken}" />
        <button type="submit" style="border-radius: 15px; background-color: cyan;">Login</button>
      </form>
    `);
  });


  // JWKs endpoint
  app.get('/jwks', (req, res) => {
    const publicKey = Object
      .entries(JWK)
      .filter(([key]) => WHITELISTED_KEYS.includes(key))
      .reduce((publicObj, [key, value]) => ({
        ...publicObj,
        [key]: value 
      }), {})
    
    res.json({
      keys: [publicKey]
    });
  });

  // Userinfo endpoint
  app.get('/userinfo', (req, res) => {
    const { serviceId } = req.params;

    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).send('Missing authorization header');
    }

    const token = authHeader.split(' ')[1];
    jwt.verify(token, CLIENT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(401).send('Invalid token');
      }

      res.json(decoded);
    });
  });

  // OpenID Connect discovery endpoint
  app.get('/.well-known/openid-configuration', (req, res) => {
    const baseUrl = `https://${host}`;
    res.json({
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/authorize`,
      token_endpoint: `${baseUrl}/token`,
      userinfo_endpoint: `${baseUrl}/userinfo`, // Optional if implementing userinfo
      jwks_uri: `${baseUrl}/jwks`, // For public key distribution if using asymmetric signing
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
    });
  });

  app.listen(port, () => {
    console.log(`OIDC server running at http://localhost:${port}`);
  });
}

initApp().catch(console.error);
