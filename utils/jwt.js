import AuthError from '../auth/authError';
import { KEYUTIL, KJUR } from 'jsrsasign';
const jwtDecoder = require('jwt-decode');

export const verifyToken = (credentials, clientInfo) => {
  if (!tokenValidationRequired(credentials, clientInfo)) {
    return Promise.resolve(credentials);
  }

  if (!credentials.idToken) {
    return Promise.reject(
      idTokenError({
        desc: 'ID token missing'
      })
    );
  }

  return verifySignature(credentials, clientInfo)
    .then(decoded => validateClaims(decoded, clientInfo))
    .then(() => Promise.resolve(credentials));
};

const verifySignature = (credentials, clientInfo) => {
  let header, payload;

  try {
    header = jwtDecoder(credentials.idToken, { header: true });
    payload = jwtDecoder(credentials.idToken);
  } catch (err) {
    return Promise.reject(
      idTokenError({
        error: 'token_decoding_error',
        desc: 'Error decoding token'
      })
    );
  }

  const supportedAlgs = ['RS256', 'HS256'];
  const alg = header.alg;

  if (!supportedAlgs.includes(alg)) {
    return Promise.reject(
      idTokenError({
        error: 'invalid_algorithm',
        desc: 'Token signing algorithm must be either RS256 or HS256'
      })
    );
  }

  // HS256 tokens require private key, which cannot be stored securely in public clients.
  // Since the ID token exchange is done via CODE with PKCE flow, skip signature verification in this case.
  if (alg === 'HS256') {
    return Promise.resolve(payload);
  }

  return getJwk(clientInfo.domain, header.kid)
    .then(jwk => {
      const pubKey = KEYUTIL.getKey(jwk);
      const signatureValid = KJUR.jws.JWS.verify(credentials.idToken, pubKey, [
        'RS256'
      ]);

      if (signatureValid) {
        return Promise.resolve(payload);
      } else {
        return Promise.reject(
          idTokenError({
            error: 'invalid_signature',
            desc: 'Token signature is not valid'
          })
        );
      }
    })
    .catch(err => {
      if (err.json && err.status === 0) {
        return Promise.reject(err);
      } else {
        return Promise.reject(
          idTokenError({
            error: 'key_retrieval_error',
            desc: 'Unable to retrieve public keyset needed to verify token'
          })
        );
      }
    });
};

const tokenValidationRequired = (credentials, clientInfo) => {
  // If client did not specify scope of "openid", we do not expect an ID token thus no validation is needed
  if (clientInfo.scope && typeof clientInfo.scope === 'string') {
    const scopes = clientInfo.scope.split(/(\s+)/);
    if (scopes.includes('openid')) {
      return true;
    }
  }
  return false;
};

const getJwk = (domain, kid) => {
  return getJwksUri(domain)
    .then(uri => getJwkFromUri(uri))
    .then(jwk => {
      const keys = jwk.keys;
      const key = keys
        .filter(
          k => k.use === 'sig' && k.kty === 'RSA' && k.kid && (k.n && k.e)
        )
        .find(k => k.kid == kid);
      return Promise.resolve(key);
    });
};

const getJwksUri = domain => {
  return fetch(`https://${domain}/.well-known/openid-configuration`)
    .then(resp => resp.json())
    .then(openIdConfig => openIdConfig.jwks_uri);
};

const getJwkFromUri = uri => {
  return fetch(uri).then(resp => resp.json());
};

const validateClaims = (decoded, opts) => {
  // "iss" claim must be present and matches the domain
  if (!decoded.iss || decoded.iss !== 'https://' + opts.domain + '/') {
    return Promise.reject(
      idTokenError({
        error: 'invalid_issuer_claim',
        desc: '"iss" claim is not valid'
      })
    );
  }

  // "sub" claim must be present
  if (!decoded.sub) {
    return Promise.reject(
      idTokenError({
        error: 'invlid_sub_claim',
        desc: '"sub" claim is not present'
      })
    );
  }

  const now = new Date();

  // "exp" claim must be present and represent a time in the future
  if (typeof decoded.exp !== 'number') {
    return Promise.reject(
      idTokenError({
        error: 'invalid_exp_claim',
        desc: '"exp" claim must be present and be a number'
      })
    );
  }

  const expDate = new Date(0);
  const leeway = typeof opts.leeway === 'number' ? opts.leeway : 60;

  expDate.setUTCSeconds(decoded.exp + leeway);

  if (now > expDate) {
    return Promise.reject(
      idTokenError({
        error: 'invalid_exp_claim',
        desc: `JWT expired on ${new Date(decoded.exp * 1000)}`
      })
    );
  }

  // "iat" claim must be present and represent a time in the past
  if (typeof decoded.iat !== 'number') {
    return Promise.reject(
      idTokenError({
        error: 'invalid_iat_claim',
        desc: '"iat" claim must be present and be a number'
      })
    );
  }

  const iatDate = new Date(0);
  iatDate.setUTCSeconds(decoded.iat - leeway);

  if (now < iatDate) {
    return Promise.reject(
      idTokenError({
        error: 'invalid_iat_claim',
        desc: 'Token was issued in the past'
      })
    );
  }

  // if "max_age" param sent on auth request, "auth_time" claim must be present,
  // and its value plus the "max_age" param must be a date in the future.
  if (typeof opts.maxAge === 'number') {
    if (typeof decoded.auth_time !== 'number') {
      return Promise.reject(
        idTokenError({
          error: 'invalid_auth_time_claim',
          desc:
            '"auth_time" claim must be present and be a number when "max_age" included on auth request'
        })
      );
    }

    const authTimeDate = new Date(0);
    authTimeDate.setUTCSeconds(decoded.auth_time + opts.maxAge + leeway);

    if (now > authTimeDate) {
      return Promise.reject(
        idTokenError({
          error: 'invalid_max_age_claim',
          desc: '"auth_time" claim does not match the expected value'
        })
      );
    }
  }

  // If nonce was present on the auth request, it must match the value sent on the auth request
  if (opts.nonce && opts.nonce !== decoded.nonce) {
    return Promise.reject(
      idTokenError({
        error: 'invalid_nonce_claim',
        desc: '"nonce" claim does not match nonce sent'
      })
    );
  }

  // "aud" claim must be present and value must equal or contain the client ID.
  // If the "aud" claim is an array with more than one item, the "azp" claim must be present and equal the client ID.
  if (Array.isArray(decoded.aud)) {
    if (!decoded.aud.includes(opts.clientId)) {
      return Promise.reject(
        idTokenError({
          error: 'invalid_aud_claim',
          desc: '"aud" claim is not valid'
        })
      );
    }
    if (decoded.aud.length > 1 && decoded.azp !== opts.clientId) {
      return Promise.reject(
        idTokenError({
          error: 'invalid_azp_claim',
          desc: '"azp" claim is not valid'
        })
      );
    }
  } else if (decoded.aud !== opts.clientId) {
    return Promise.reject(
      idTokenError({
        error: 'invalid_aud_claim',
        desc: '"aud" claim is not valid'
      })
    );
  }

  return Promise.resolve();
};

const idTokenError = ({
  error = 'verification_error',
  desc = 'Error verifying ID token'
} = {}) => {
  return new AuthError({
    json: {
      error: `a0.idtoken.${error}`,
      error_description: desc
    },
    status: 0
  });
};
